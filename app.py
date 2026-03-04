from bson import ObjectId # pymongo가 설치될 때 함께 설치됨. (install X)
from pymongo import MongoClient

from flask import Flask, render_template, jsonify, request
from flask.json.provider import JSONProvider

import json
import sys


app = Flask(__name__)

client = MongoClient('mongodb://test:test@localhost',27017)
db = client.dbjungle


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

# 메모 생성
@app.route('/memo', methods=['POST'])
def create_memo():
    title_receive = request.form['title_give']
    content_receive = request.form['content_give']
    
    memo = {
        'title': title_receive,
        'content': content_receive,
        'likes': 0
    }
    
    db.memos.insert_one(memo)
    
    return jsonify({'result': 'success'})

# 메모 조회
@app.route('/memo', methods=['GET'])
def read_memos():
    memos = list(db.memos.find({}))
    memos.sort(key=lambda memo: memo['likes'], reverse= True)
    return jsonify({'result': 'success', 'memos': memos})

# 메모 수정
@app.route('/memo', methods=['PUT'])
def update_memo():
    id_receive = request.form['id_give']
    title_receive = request.form['title_give']
    content_receive = request.form['content_give']
    
    db.memos.update_one(
        {'_id': ObjectId(id_receive)},
        {'$set': {'title': title_receive, 'content': content_receive}}
    )
    
    return jsonify({'result': 'success'})

# 메모 삭제
@app.route('/memo', methods=['DELETE'])
def delete_memo():
    id_receive = request.form['id_give']
    
    db.memos.delete_one({'_id': ObjectId(id_receive)})
    
    return jsonify({'result': 'success'})

# 좋아요
@app.route('/memo/like', methods=['POST'])
def like_memo():
    id_receive = request.form['id_give']
    
    db.memos.update_one(
        {'_id': ObjectId(id_receive)},
        {'$inc': {'likes': 1}}  
    )
    
    return jsonify({'result': 'success'})

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)