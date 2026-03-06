from bson import ObjectId
from pymongo import MongoClient

from flask import Flask, render_template, jsonify, request, abort, redirect, url_for
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
from datetime import datetime, timezone, timedelta

import json
import os
import hashlib
import threading

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

load_dotenv()

slack_client = WebClient(token=os.environ.get("SLACK_BOT_TOKEN"))
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID")

app = Flask(__name__)
jwt = JWTManager(app)
client = MongoClient("mongodb://localhost:27017")
db = client.dbjungle

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["BCRYPT_LEVEL"] = os.environ.get("BCRYPT_LEVEL")
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_ACCESS_CSRF_HEADER_NAME"] = "X-CSRF-TOKEN"
app.config["JWT_REFRESH_CSRF_HEADER_NAME"] = "X-CSRF-TOKEN"
app.config["JWT_COOKIE_SECURE"] = True

bcrypt = Bcrypt(app)


#####################################################################################
# 이 부분은 코드를 건드리지 말고 그냥 두세요.
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


class CustomJSONProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        return json.dumps(obj, **kwargs, cls=CustomJSONEncoder, ensure_ascii=False)

    def loads(self, s, **kwargs):
        return json.loads(s, **kwargs)


app.json = CustomJSONProvider(app)
#####################################################################################



@app.route("/")
@jwt_required(optional=True)
def home():
    current_user = get_jwt_identity()
    if current_user:
        user_info = db.users.find_one({"id": current_user})
        if user_info.get("role") == "ADMIN":
            return render_template("admin-page.html", user_info=user_info)
        else:
            return render_template("index.html", user_info=user_info)
    else:
        return render_template("index.html")


@app.route("/register", methods=["GET"])
def register():
    return render_template("signup.html")


@app.route("/user", methods=["POST"])
def create_user():
    data = request.get_json()
    pwd = data["pwd"]
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


@app.route("/user/check-id", methods=["POST"])
def check_id():
    data = request.get_json()
    user_id = data.get("id")
    if db.users.find_one({"id": user_id}):
        abort(409, description="이미 존재하는 id입니다.")
    return jsonify({"result": "success", "message": "사용 가능한 id입니다."})


@app.route("/login", methods=["POST"])
def login():
    try:
        user_data = request.get_json()
    except Exception:
        abort(400, description="JSON 형식이 잘못되었습니다.")

    user_id = user_data.get("id")
    user_password = user_data.get("pwd")

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
    if current_user:
        db.refresh_tokens.delete_one({"user_id": current_user})
    unset_jwt_cookies(response)
    return response


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    raw_refresh_token = request.cookies.get("refresh_token_cookie")
    stored_token_data = db.refresh_tokens.find_one({"user_id": current_user})

    if not stored_token_data:
        abort(401, description="다시 로그인 하세요.")

    salt = stored_token_data.get("salt")
    sha256_hash = hashlib.sha256()
    combined_string = raw_refresh_token + salt
    sha256_hash.update(combined_string.encode("utf-8"))
    current_hash_result = sha256_hash.hexdigest()

    if stored_token_data["refresh_token"] == current_hash_result:
        access_token = create_access_token(identity=current_user)
        new_refresh_token = refresh_token_key_rotation(current_user)

        response = jsonify({"result": "success"})
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, new_refresh_token)
        return response
    else:
        abort(401, description="접근 권한이 없습니다.")


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
    db.refresh_tokens.update_one(
        {"user_id": user_id}, {"$set": refresh_token_hashed}, upsert=True
    )


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

    name = db.users.find_one({"id": uid}).get("name")
    for data in data_list:
        data["id"] = uid
        data["name"] = name

    try:
        db.reserve.insert_many(data_list, ordered=False)
    except Exception:
        abort(409, description="이미 예약된 시간대입니다.")

    return jsonify({"result": "success"})


def validation_reserve(uid, data_list):
    for req in data_list:
        conflict = db.reserve.find_one(
            {
                "item": req["item"],
                "start": {"$lt": req["end"]},
                "end": {"$gt": req["start"]},
            }
        )
        if conflict:
            abort(409, description=f"{req['start']} ~ {req['end']} 시간대에 이미 예약이 존재합니다.")

    request_minutes_by_date = {}
    for req in data_list:
        date_key = req["start"][:10]
        start_dt = datetime.strptime(req["start"], "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(req["end"], "%Y-%m-%d %H:%M:%S")
        duration = (end_dt - start_dt).seconds // 60
        request_minutes_by_date[date_key] = request_minutes_by_date.get(date_key, 0) + duration

    for date_key, req_minutes in request_minutes_by_date.items():
        existing = list(db.reserve.find({"id": uid, "start": {"$regex": f"^{date_key}"}}))
        existing_minutes = sum(
            (
                datetime.strptime(doc["end"], "%Y-%m-%d %H:%M:%S")
                - datetime.strptime(doc["start"], "%Y-%m-%d %H:%M:%S")
            ).seconds // 60
            for doc in existing
        )
        total = existing_minutes + req_minutes
        if total > 120:
            abort(400, description={"code": 4999, "description": f"{date_key} 날짜의 예약 가능 시간(2시간)을 초과합니다."})


# 예약 조회
@app.route("/reserve", methods=["GET"])
@jwt_required(optional=True)
def find_reserve():
    item = request.args.get("item")
    uid = get_jwt_identity()
    reserves = list(db.reserve.find({"item": item}))

    for reserve in reserves:
        reserve["own"] = uid is not None and reserve["id"] == uid

    return render_template("time.html", reserves=reserves, current_user=uid, machine_type=item)


@app.route("/machine/<machine_type>", methods=["GET"])
@jwt_required(optional=True)
def find_machine(machine_type):
    prefix = "L" if machine_type == "laundry" else "D"

    current_user_id = get_jwt_identity()
    user_info = db.users.find_one({"id": current_user_id}) if current_user_id else None
    user_gender = user_info.get("gender") if user_info else None

    if user_gender:
        query = {"item": {"$regex": f"^{prefix}"}, "gender": {"$in": [user_gender, "both"]}}
    else:
        query = {"item": {"$regex": f"^{prefix}"}}

    machines = list(db.machine.find(query).sort("item", 1))

    # 현재 진행 중인 예약 정보를 각 기계에 붙여줌
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for machine in machines:
        active = db.reserve.find_one({
            "item": machine["item"],
            "start": {"$lte": now},
            "end": {"$gte": now},
        })
        if active:
            machine["using"] = True
            machine["use_start"] = active["start"][11:16]  # "HH:MM"
            machine["use_end"] = active["end"][11:16]
        else:
            machine["using"] = False
            machine["use_start"] = None
            machine["use_end"] = None

    if prefix == "L":
        return render_template("laundry-select.html", machines=machines, current_user=user_info)
    elif prefix == "D":
        return render_template("dryer-select.html", machines=machines, current_user=user_info)
    else:
        abort(400, "유효한 기계 타입이 아닙니다.")


# 나의 예약 정보 조회
@app.route("/own/<machine_type>", methods=["GET"])
@jwt_required()
def find_own_reserve(machine_type):
    uid = get_jwt_identity()
    prefix = "L" if machine_type == "laundry" else "D"
    user = db.users.find_one({"id": uid})
    name = user.get("name")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reserve = db.reserve.find_one(
        {
            "id": uid,
            "item": {"$regex": f"^{prefix}"},
            "end": {"$gte": now},
        },
        {"id": 0},
        sort=[("start", 1)],
    )

    if reserve is None:
        return jsonify(result=None)

    reserve["name"] = name
    return jsonify(result=reserve)


# 신고 목록 조회
@app.route("/report", methods=["GET"])
@jwt_required()
def find_report():
    uid = get_jwt_identity()
    check_admin_role(uid)
    report = list(db.report.find())
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


# 신고 삭제
@app.route("/report/<report_id>", methods=["DELETE"])
@jwt_required()
def delete_report(report_id):
    uid = get_jwt_identity()
    check_admin_role(uid)
    db.report.delete_one({"_id": ObjectId(report_id)})
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
    if user.get("role") != "ADMIN":
        abort(403, description="관리자 권한이 아닙니다.")


# 반납하기
@app.route("/reserve/<pk>", methods=["DELETE"])
@jwt_required()
def return_machine(pk):
    uid = get_jwt_identity()
    reserve = db.reserve.find_one({"_id": ObjectId(pk)})

    if not reserve:
        abort(404, description="예약을 찾을 수 없습니다.")
    if uid != reserve.get("id"):
        abort(403, description="본인의 예약만 반납할 수 있습니다.")

    item = reserve.get("item")
    db.reserve.delete_one({"_id": ObjectId(pk)})

    if item.startswith("L"):
        machine_name = "세탁기" + reserve["item"][1:]
    elif item.startswith("D"):
        machine_name = "건조기" + reserve["item"][1:]
    else:
        machine_name = reserve["item"]

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    next_reserve = db.reserve.find_one({"item": item, "start": {"$gte": now}}, sort=[("start", 1)])

    if next_reserve:
        next_name = next_reserve.get("name", next_reserve["id"])
        start_time = next_reserve["start"]
        message = f"{machine_name} 사용이 끝났습니다!\n다음 예약자 {next_name}님 ({start_time}) 이용 가능합니다."
    else:
        message = f"{machine_name} 사용이 끝났습니다!"

    send_slack_async(message)
    return jsonify(result="success")


def send_slack_message(message):
    try:
        slack_client.chat_postMessage(channel=SLACK_CHANNEL_ID, text=message)
    except SlackApiError as e:
        print(f"Slack 에러: {e.response['error']}")


def send_slack_async(message):
    thread = threading.Thread(target=send_slack_message, args=(message,))
    thread.daemon = True
    thread.start()


# 에러핸들러
@app.errorhandler(409)
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
def handle_validation_error(e):
 
    error_data = e.description
    if isinstance(error_data, dict) and "code" in error_data:
        return jsonify({"result": "fail", "info": error_data}), e.code
    return jsonify({"result": "fail", "message": str(error_data)}), e.code


if __name__ == "__main__":
    db_setup_ttl_indexes()
    app.run("0.0.0.0", port=5001, debug=True)
