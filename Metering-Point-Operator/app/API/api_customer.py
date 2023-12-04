from app import app, db

from flask import request, make_response

import hashlib

from dotenv import load_dotenv
import os

h = hashlib.sha256()
load_dotenv()


@app.route('/getcounter/<counter_id>', methods=['GET'])
def get_counter(counter_id):
    try:
        if authorize(request.headers.get('Authorization')):
            return make_response({'counter': db.counters.find_one({'_id': counter_id})}, 200)
        else:
            return make_response({'counter': ''}, 401)
    except:
        return make_response(500)

@app.route('/getcounterstatus/<counter_id>', methods=['GET'])
def get_counter_status(counter_id):
    try:
        if authorize(request.headers.get('Authorization')):
            return make_response({'counter': db.counters.find_one({'_id': counter_id})}, 200)
        else:
            return make_response({'counter': ''}, 401)
    except:
        return make_response(500)
@app.route('/setcounterstatus/<counter_id>', methods=['SET'])
def set_counter_status(counter_id):
    try:
        if authorize(request.headers.get('Authorization')):
            db.counters.update_one({'_id': counter_id}, {'$set': {'status': request.args.get('status')}})
            return make_response(200)
        else:
            return make_response(401)

    except:
        return make_response(500)
def authorize(token) -> bool:
    h.update(os.getenv('SHARED_SECRET_CP').encode('utf-8'))
    if h.hexdigest() == token.encode('utf-8'):
        return True
    else:
        return False
