from app import app, db

from flask import request, make_response

import hashlib

from dotenv import load_dotenv
import os

h = hashlib.sha256()
load_dotenv()

@app.route('/setcounter/<counter_id>', methods=['SET'])
def get_counter(counter_id):
    try:
        if authorize(request.headers.get('Authorization')):
            db.counters.update_one({'_id': counter_id}, {'$set': {'counter': request.args.get('counter')}})
            return make_response(200)
        else:
            return make_response({'counter': ''}, 401)
    except:
        return make_response(500)


@app.route('/seterrorstatus/<counter_id>', methods=['SET'])

def authorize(token) -> bool:
    h.update(os.getenv('SHARED_SECRET_C').encode('utf-8'))
    if h.hexdigest() == token.encode('utf-8'):
        return True
    else:
        return False
