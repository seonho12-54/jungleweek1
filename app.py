from bson import ObjectId # pymongo가 설치될 때 함께 설치됨. (install X)
from pymongo import MongoClient

from flask import Flask, render_template, jsonify, request, abort
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token, set_access_cookies, set_refresh_cookies, unset_jwt_cookies)

from flask.json.provider import JSONProvider

from flask_bcrypt import Bcrypt

from dotenv import load_dotenv 

from datetime import datetime, timezone, timedelta 

import json
import os
import hashlib 

load_dotenv()

app = Flask(__name__)
jwt = JWTManager(app)
client = MongoClient('mongodb://localhost', 27017)
db = client.dbjungle

# flask-jwt-extended 관련 변수 
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['BCRYPT_LEVEL'] = os.environ.get('BCRYPT_LEVEL')

# flask-jwt-extended cookie 관련 세팅 
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)
app.config['JWT_COOKIE_CSRF_PROTECT'] = True  
app.config['JWT_ACCESS_CSRF_HEADER_NAME'] = "X-CSRF-TOKEN"
app.config['JWT_REFRESH_CSRF_HEADER_NAME'] = "X-CSRF-TOKEN"

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
@jwt_required(optional=True)
def home():
    current_user = get_jwt_identity()
        
    if current_user: 
        user_info = db.users.find_one({'id': current_user}) 
        return render_template('index.html', user_info=user_info)
    else:
        return render_template('index.html')
    

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
    

@app.route('/login', methods=['POST'])
def login(): 
    try:
        user_data = request.get_json()
    except Exception: 
        abort(400, description="JSON 형식이 잘못되었습니다.")
    
    user_id = user_data.get('id')
    user_password = user_data.get("pwd")

    # server side validation 
    if not user_id: 
        abort(400, description="id가 비어 있습니다.")
    if not user_password:
        abort(400, description="비밀번호가 비어 있습니다.")
        
    user = db.users.find_one({'id': user_id})

    if user:        
        if bcrypt.check_password_hash(user.get('pwd'), user_password):
            access_token = create_access_token(identity=user_id)
            refresh_token = create_refresh_token(identity=user_id)
            refresh_token_hash(user_id, refresh_token, "new")

            # 쿠키 설정
            response = jsonify({'result': 'success', 'role': user.get('role')})
            set_access_cookies(response, access_token) 
            set_refresh_cookies(response, refresh_token)
            
            return response 
        else:
            abort(401, description="비밀번호가 틀렸습니다.")

@app.route('/logout', methods=['POST'])
@jwt_required(optional=True)
def logout():
    current_user = get_jwt_identity()
    response = jsonify({'result': 'success'})

    # refresh token을 db에서 삭제 
    if current_user:
        db.refresh_tokens.delete_one({'user_id': current_user})

    # access token과 refresh token을 브라우저에서 삭제 
    unset_jwt_cookies(response)

    return response 

    

# client가 이미 refresh token을 가지고 있을때 받는 request 
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    # request를 보낸 유저 정보 가져오기 
    current_user = get_jwt_identity()
    
    # 브라우저 쿠키 가져오기 
    raw_refresh_token = request.cookies.get('refresh_token_cookie')

    # 현재 유저의 refresh token을 가져오기 
    stored_token_data = db.refresh_tokens.find_one({'user_id': current_user})  

    if not stored_token_data: 
        abort(401, description="다시 로그인 하세요.")
        
    salt = stored_token_data.get('salt')

    # 클라이언트가 보낸 Raw 토큰과 합쳐서 해시 생성             
    sha256_hash = hashlib.sha256()
    combined_string = raw_refresh_token + salt 
    sha256_hash.update(combined_string.encode('utf-8'))            
    current_hash_result = sha256_hash.hexdigest()

    # 유저가 가지고 있는 refresh token과 비교 
    if stored_token_data['refresh_token'] == current_hash_result: 
        access_token = create_access_token(identity=current_user)
        new_refresh_token = refresh_token_key_rotation(current_user)

        # 새로운 refresh token 쿠키에 업데이트 
        response = jsonify({'result': 'success'})

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
    sha256_hash.update(combined_string.encode('utf-8'))            
    hash_result = sha256_hash.hexdigest()

    time_now = datetime.now(timezone.utc) 
    
    refresh_token_hashed = {
        'user_id': user_id, 
        'refresh_token': hash_result, 
        'salt': salt, 
        'issued_at': time_now,  
        'expires_at': time_now + timedelta(days=7)
    }               

    # 처음 로그인 할때 + key rotation 할때
    db.refresh_tokens.update_one(
        {'user_id': user_id}, 
        {'$set': refresh_token_hashed},
        upsert=True 
    )

# refresh token rotation으로 한번 사용한 token 폐기 
def refresh_token_key_rotation(user_id): 
    refresh_token = create_refresh_token(identity=user_id)
    refresh_token_hash(user_id, refresh_token, "update")
    return refresh_token 
 
def db_setup_ttl_indexes(): 
    db.refresh_tokens.create_index("expires_at", expireAfterSeconds=0)


if __name__ == '__main__':
    db_setup_ttl_indexes()
    app.run('0.0.0.0', port=5001, debug=True)
    