from bson import ObjectId # pymongo가 설치될 때 함께 설치됨. (install X)
from pymongo import MongoClient

from flask import Flask, render_template, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, unset_jwt_cookies, create_refresh_token, jwt_refresh_token_required,
)
from flask.json.provider import JSONProvider
from flask_bcrypt import Bcrypt
import json
import os
import sys

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
    

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)