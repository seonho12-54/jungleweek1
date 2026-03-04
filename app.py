from bson import ObjectId # pymongo가 설치될 때 함께 설치됨. (install X)
from pymongo import MongoClient

from flask import Flask, render_template, jsonify, request, abort
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity,
    unset_jwt_cookies, create_refresh_token
)
from flask.json.provider import JSONProvider
from flask_bcrypt import Bcrypt
import json
import os
import sys
from datetime import datetime


load_dotenv()
app = Flask(__name__)
jwt = JWTManager(app)
client = MongoClient('mongodb://test:test@localhost',27017)
db = client.dbjungle

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['BCRYPT_LEVEL'] = os.environ.get('BCRYPT_LEVEL')
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


@app.route('/')
def home():
    return render_template('index.html')

# 회원가입
@app.route('/user', methods=['POST'])
def create_user():
   data = request.get_json()
   pwd = data['pwd']
   encryptPwd = bcrypt.generate_password_hash(pwd)
   user = {
       'id' : data['id'],
       'pwd' : encryptPwd,
       'gender' : data['gender'],
       'name' : data['name']
   }

   db.users.insert_one(user)
   return jsonify({'result': 'success'})
    

# 예약 신청
@app.route('/reserve', methods=['POST'])
@jwt_required()
def create_reserve():
    uid = get_jwt_identity()
    data_list = request.get_json()
    validation_reserve(uid, data_list)
    for data in data_list:
        data['id'] = uid
    db.reserve.insert_many(data_list)
    return jsonify({'result': 'success'})




def validation_reserve(uid, data_list):
    errors = []
    for req in data_list:
        # Validation 1: 시간대 + item 겹침 체크
        conflict = db.reserve.find_one({
            "item": req["item"],
            "start": {"$lt": req["end"]},
            "end":   {"$gt": req["start"]},
        })

        if conflict:
            abort(409, description=f"{req['start']} ~ {req['end']} 시간대에 이미 예약이 존재합니다.")

    # Validation 2: 날짜별 2시간 초과 체크
    request_minutes_by_date = {}
    for req in data_list:
        date_key = req["start"][:10]
        start_dt = datetime.strptime(req["start"], "%Y-%m-%d %H:%M:%S")
        end_dt   = datetime.strptime(req["end"],   "%Y-%m-%d %H:%M:%S")
        duration = (end_dt - start_dt).seconds // 60
        request_minutes_by_date[date_key] = request_minutes_by_date.get(date_key, 0) + duration

    for date_key, req_minutes in request_minutes_by_date.items():
        existing = list(db.reserve.find({
            "id": uid,
            "start": {"$regex": f"^{date_key}"}
        }))

    
        existing_minutes = sum(
            (datetime.strptime(doc["end"], "%Y-%m-%d %H:%M:%S") -
             datetime.strptime(doc["start"], "%Y-%m-%d %H:%M:%S")).seconds // 60
            for doc in existing
        )

        total = existing_minutes + req_minutes
        if total > 120:
            abort(400, description=f"{date_key} 날짜의 예약 가능 시간(2시간)을 초과합니다.")

# 예약 조회
@app.route('/reserve', methods=['GET'])
@jwt_required(optional=True)
def find_reserve():
    uid = get_jwt_identity()
    reserves = list(db.reserve.find({},{'_id':0}))
    
    for reserve in reserves:
        if uid and reserve['id'] == uid:
            reserve['own'] = True
        else:
            reserve['own'] = False
    return jsonify(result = reserves)
# 세탁기/건조기 조회
@app.route('/machine/<machine_type>', methods=['GET'])
def find_machine(machine_type):
    prefix = "L" if machine_type == "laundry" else "D"

    # item이 prefix로 시작하는 machine 목록 조회
    machines = list(db.machine.find(
        {"item": {"$regex": f"^{prefix}"}},
        {"_id": 0}  # _id 제외
    ))

    return jsonify(machines)

# 나의 예약 정보 조회
@app.route('/own/<machine_type>', methods=['GET'])
@jwt_required()
def find_own_reserve(machine_type):
    uid = get_jwt_identity();
    prefix = "L" if machine_type == "laundry" else "D"

    reserve = db.reserve.find_one(
        {"id":uid,
         "item": {"$regex": f"^{prefix}"}},
         {"_id":0}
    )
    return jsonify(result = reserve)
    
# 에러핸들러
@app.errorhandler(409)
@app.errorhandler(400)
def handle_validation_error(e):
    return jsonify({'result': 'fail', 'message': e.description}), e.code

if __name__ == '__main__':
    app.run('0.0.0.0', port=5001, debug=True)