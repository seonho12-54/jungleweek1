from bson import ObjectId  # pymongo가 설치될 때 함께 설치됨. (install X)
from pymongo import MongoClient

from flask import Flask, render_template, jsonify, request, abort
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity,
    create_refresh_token,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
)

from flask.json.provider import JSONProvider

from flask_bcrypt import Bcrypt

from dotenv import load_dotenv

from datetime import datetime, timezone, timedelta

import json
import os
import sys
from datetime import datetime

import hashlib

load_dotenv()

app = Flask(__name__)
jwt = JWTManager(app)
database_url = os.environ.get("DATABASE_URL")
client = MongoClient(database_url, 27017)
db = client.dbjungle

# flask-jwt-extended 관련 변수
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["BCRYPT_LEVEL"] = os.environ.get("BCRYPT_LEVEL")

# flask-jwt-extended cookie 관련 세팅
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_ACCESS_CSRF_HEADER_NAME"] = "X-CSRF-TOKEN"
app.config["JWT_REFRESH_CSRF_HEADER_NAME"] = "X-CSRF-TOKEN"

bcrypt = Bcrypt(app)


#####################################################################################
# 이 부분은 코드를 건드리지 말고 그냥 두세요. 코드를 이해하지 못해도 상관없는 부분입니다.
#
# ObjectId 타입으로 되어있는 _id 필드는 Flask 의 jsonify 호출시 문제가 된다.
# 이를 처리하기 위해서 기본 JsonEncoder 가 아닌 custom encoder 를 사용한다.
# Custom encoder 는 다른 부분은 모두 기본 encoder 에 동작을 위임하고 ObjectId 타입만 직접 처리한다.
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


class CustomJSONProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        return json.dumps(obj, **kwargs, cls=CustomJSONEncoder)

    def loads(self, s, **kwargs):
        return json.loads(s, **kwargs)


# 위에 정의되 custom encoder 를 사용하게끔 설정한다.
app.json = CustomJSONProvider(app)

# 여기까지 이해 못해도 그냥 넘어갈 코드입니다.
# #####################################################################################


@app.route("/")
@jwt_required(optional=True)
def home():
    current_user = get_jwt_identity()

    if current_user:
        user_info = db.users.find_one({"id": current_user})
        return render_template("index.html", user_info=user_info)
    else:
        return render_template("index.html")


@app.route("/user", methods=["POST"])
def create_user():
    data = request.get_json()
    pwd = data["pwd"]
    # 해당 아이디로 이미 존재하는지 확인
    if db.users.find_one({"id": data["id"]}):
        abort(409, description="이미 존재하는 id입니다.")

    encryptPwd = bcrypt.generate_password_hash(pwd)
    user = {
        "id": data["id"],
        "pwd": encryptPwd,
        "gender": data["gender"],
        "name": data["name"],
        "role": "USER",
    }

    db.users.insert_one(user)
    return jsonify({"result": "success"})


# id 중복확인
@app.route("/user/check-id", methods=["POST"])
def check_id():
    data = request.get_json()
    user_id = data["id"]

    if db.users.find_one({"id": user_id}):
        abort(409, description="이미 존재하는 id입니다.")
    else:
        return jsonify({"result": "success", "message": "사용 가능한 id입니다."})


@app.route("/login", methods=["POST"])
def login():
    try:
        user_data = request.get_json()
    except Exception:
        abort(400, description="JSON 형식이 잘못되었습니다.")

    user_id = user_data.get("id")
    user_password = user_data.get("pwd")

    # server side validation
    if not user_id:
        abort(400, description="id가 비어 있습니다.")
    if not user_password:
        abort(400, description="비밀번호가 비어 있습니다.")

    user = db.users.find_one({"id": user_id})

    if user:
        if bcrypt.check_password_hash(user.get("pwd"), user_password):
            access_token = create_access_token(identity=user_id)
            refresh_token = create_refresh_token(identity=user_id)
            refresh_token_hash(user_id, refresh_token, "new")

            # 쿠키 설정
            response = jsonify({"result": "success", "role": user.get("role")})
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)

            return response
        else:
            abort(401, description="비밀번호가 틀렸습니다.")


@app.route("/logout", methods=["POST"])
@jwt_required(optional=True)
def logout():
    current_user = get_jwt_identity()
    response = jsonify({"result": "success"})

    # refresh token을 db에서 삭제
    if current_user:
        db.refresh_tokens.delete_one({"user_id": current_user})

    # access token과 refresh token을 브라우저에서 삭제
    unset_jwt_cookies(response)

    return response


# client가 이미 refresh token을 가지고 있을때 받는 request
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    # request를 보낸 유저 정보 가져오기
    current_user = get_jwt_identity()

    # 브라우저 쿠키 가져오기
    raw_refresh_token = request.cookies.get("refresh_token_cookie")

    # 현재 유저의 refresh token을 가져오기
    stored_token_data = db.refresh_tokens.find_one({"user_id": current_user})

    if not stored_token_data:
        abort(401, description="다시 로그인 하세요.")

    salt = stored_token_data.get("salt")

    # 클라이언트가 보낸 Raw 토큰과 합쳐서 해시 생성
    sha256_hash = hashlib.sha256()
    combined_string = raw_refresh_token + salt
    sha256_hash.update(combined_string.encode("utf-8"))
    current_hash_result = sha256_hash.hexdigest()

    # 유저가 가지고 있는 refresh token과 비교
    if stored_token_data["refresh_token"] == current_hash_result:
        access_token = create_access_token(identity=current_user)
        new_refresh_token = refresh_token_key_rotation(current_user)

        # 새로운 refresh token 쿠키에 업데이트
        response = jsonify({"result": "success"})

        set_access_cookies(response, access_token)
        set_refresh_cookies(response, new_refresh_token)

        return response
    else:
        abort(401, description="접근 권한이 없습니다.")


# refresh 토큰 암호화 (SHA-256 + salt)
def refresh_token_hash(user_id, refresh_token, type):
    salt = os.urandom(16).hex()

    sha256_hash = hashlib.sha256()
    combined_string = refresh_token + salt
    sha256_hash.update(combined_string.encode("utf-8"))
    hash_result = sha256_hash.hexdigest()

    time_now = datetime.now(timezone.utc)

    refresh_token_hashed = {
        "user_id": user_id,
        "refresh_token": hash_result,
        "salt": salt,
        "issued_at": time_now,
        "expires_at": time_now + timedelta(days=7),
    }

    # 처음 로그인 할때 + key rotation 할때
    db.refresh_tokens.update_one(
        {"user_id": user_id}, {"$set": refresh_token_hashed}, upsert=True
    )


# refresh token rotation으로 한번 사용한 token 폐기
def refresh_token_key_rotation(user_id):
    refresh_token = create_refresh_token(identity=user_id)
    refresh_token_hash(user_id, refresh_token, "update")
    return refresh_token


def db_setup_ttl_indexes():
    db.refresh_tokens.create_index("expires_at", expireAfterSeconds=0)


# 예약 생성
@app.route("/reserve", methods=["POST"])
@jwt_required()
def create_reserve():
    uid = get_jwt_identity()
    data_list = request.get_json()
    validation_reserve(uid, data_list)
    for data in data_list:
        data["id"] = uid
        data["id"] = uid
    db.reserve.insert_many(data_list)
    return jsonify({"result": "success"})


def validation_reserve(uid, data_list):
    errors = []
    for req in data_list:
        # Validation 1: 시간대 + item 겹침 체크
        conflict = db.reserve.find_one(
            {
                "item": req["item"],
                "start": {"$lt": req["end"]},
                "end": {"$gt": req["start"]},
            }
        )

        if conflict:
            abort(
                409,
                description=f"{req['start']} ~ {req['end']} 시간대에 이미 예약이 존재합니다.",
            )

    # Validation 2: 날짜별 2시간 초과 체크
    request_minutes_by_date = {}
    for req in data_list:
        date_key = req["start"][:10]
        start_dt = datetime.strptime(req["start"], "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(req["end"], "%Y-%m-%d %H:%M:%S")
        duration = (end_dt - start_dt).seconds // 60
        request_minutes_by_date[date_key] = (
            request_minutes_by_date.get(date_key, 0) + duration
        )

    for date_key, req_minutes in request_minutes_by_date.items():
        existing = list(
            db.reserve.find({"id": uid, "start": {"$regex": f"^{date_key}"}})
        )

        existing_minutes = sum(
            (
                datetime.strptime(doc["end"], "%Y-%m-%d %H:%M:%S")
                - datetime.strptime(doc["start"], "%Y-%m-%d %H:%M:%S")
            ).seconds
            // 60
            for doc in existing
        )

        total = existing_minutes + req_minutes
        if total > 120:
            abort(
                400,
                description=f"{date_key} 날짜의 예약 가능 시간(2시간)을 초과합니다.",
            )


# 예약 조회
@app.route("/reserve", methods=["GET"])
@jwt_required(optional=True)
def find_reserve():
    uid = get_jwt_identity()
    reserves = list(db.reserve.find({}, {"_id": 0}))

    for reserve in reserves:
        if uid and reserve["id"] == uid:
            reserve["own"] = True
        else:
            reserve["own"] = False
    return jsonify(result=reserves)


# 세탁기/건조기 조회
@app.route("/machine/<machine_type>", methods=["GET"])
def find_machine(machine_type):
    prefix = "L" if machine_type == "laundry" else "D"

    # item이 prefix로 시작하는 machine 목록 조회
    machines = list(
        db.machine.find({"item": {"$regex": f"^{prefix}"}}, {"_id": 0})  # _id 제외
    )

    return jsonify(machines)


# 나의 예약 정보 조회
@app.route("/own/<machine_type>", methods=["GET"])
@jwt_required()
def find_own_reserve(machine_type):
    uid = get_jwt_identity()
    prefix = "L" if machine_type == "laundry" else "D"

    reserve = db.reserve.find_one(
        {"id": uid, "item": {"$regex": f"^{prefix}"}}, {"_id": 0}
    )
    return jsonify(result=reserve)


# 신고 목록 조회
@app.route("/report", methods=["GET"])
@jwt_required()
def find_report():
    uid = get_jwt_identity()
    user = db.users.find_one({"id": uid})
    role = user.get("role")
    if role and role != "ADMIN":
        abort(403, description="관리자 권한이 아닙니다.")

    report = list(db.report.find({}, {"_id": 0}))
    return jsonify(result=report)


# 고장 신고
@app.route("/report", methods=["POST"])
@jwt_required()
def create_report():
    data = request.get_json()
    uid = get_jwt_identity()

    report = {
        "item": data.get("item"),
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uid": uid,
    }
    db.report.insert_one(report)
    return jsonify(result="success")


# 기계 사용금지
@app.route("/ban/machine", methods=["POST"])
@jwt_required()
def ban_machine():
    uid = get_jwt_identity()
    check_admin_role(uid)
    item = request.get_json().get("item")

    db.machine.update_one({"item": item}, {"$set": {"ban": True}})
    return jsonify(result="success")


def check_admin_role(uid):
    user = db.users.find_one({"id": uid})
    role = user.get("role")
    if role and role != "ADMIN":
        abort(403, description="관리자 권한이 아닙니다.")


# 에러핸들러
@app.errorhandler(409)
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
def handle_validation_error(e):
    return jsonify({"result": "fail", "message": e.description}), e.code


if __name__ == "__main__":
    db_setup_ttl_indexes()
    app.run("0.0.0.0", port=5001, debug=True)
