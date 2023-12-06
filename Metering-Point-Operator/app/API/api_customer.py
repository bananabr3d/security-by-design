from app import app, db, logger

from flask import request, make_response
#from models.electricity_meter import load_electricity_meter

import hashlib

from dotenv import load_dotenv
import os

from bson.objectid import ObjectId
load_dotenv()


@app.route('/api/getcounter/<counter_id>', methods=['GET'])
def get_counter(counter_id):
    try:
        if authorize(request.headers.get('Authorization')) and db.electricity_meter.find_one({'_id': ObjectId(counter_id)}) != None:
            logger.info(f"Received getcounter request for electricity meter with ID {counter_id}. Sending 200...")
            return make_response({'em_value': db.electricity_meter.find_one({'_id': ObjectId(counter_id)})['em_value'],
                                        'em_last_update': db.electricity_meter.find_one({'_id': ObjectId(counter_id)})['em_last_update']}, 200)
        else:
            logger.info(f"Received getcounter request for electricity meter with ID {counter_id}. Sending 401...")
            return make_response(401)
    except:
        return make_response(500)

@app.route('/api/getcounterstatus/<counter_id>', methods=['GET'])
def get_counter_status(counter_id):
    try:
        logger.info(f"Received getcounterstatus request for electricity meter with ID {counter_id}.")
        # Try to authenticate the request
        if authorize(request.headers.get('Authorization')):
             # Check if the counter exists and status is free "True"
             logger.info(db.electricity_meter.find_one({'_id': ObjectId(counter_id)}))
             logger.info(db.electricity_meter.find_one({'_id': ObjectId(counter_id)})['em_status'])
             if db.electricity_meter.find_one({'_id': ObjectId(counter_id)}) != None and db.electricity_meter.find_one({'_id': ObjectId(counter_id)})['em_status']:
                logger.info(f"Received getcounterstatus request for electricity meter with ID {counter_id}. Sending 200...")

                db.electricity_meter.update_one({'_id': ObjectId(counter_id)}, {'$set': {'em_status': False}})
                return make_response('', 200)
             
             else: # If the counter is not free, return 301
                logger.info(f"Received getcounterstatus request for electricity meter with ID {counter_id}. Sending 301...")
                return make_response('', 301)
        else: # If the request is not authenticated, return 401
            logger.info(f"Received getcounterstatus request for electricity meter with ID {counter_id}. Sending 401...")
            return make_response('', 401)
    except: # If an error occurs, return 500
        return make_response('', 500)

@app.route('/api/freecounter/<counter_id>', methods=['POST'])
def free_counter(counter_id):

    try:
        if ((authorize(request.headers.get('Authorization')) and
            db.electricity_meter.find_one({'_id': ObjectId(counter_id)}) != None) and not
            db.electricity_meter.find_one({'_id': ObjectId(counter_id)})['em_status']):
            db.electricity_meter.update_one({'_id': ObjectId(counter_id)}, {'$set': {'em_status': True}})
            logger.info(f"Received free request for electricity meter with ID {counter_id}. Sending 200...")
            return make_response(200)
        else:
            logger.info(f"Received free request for electricity meter with ID {counter_id}. Sending 401...")
            return make_response(401)
    except:
        return make_response(500)


def authorize(token) -> bool:
    h = hashlib.sha256()
    h.update(os.getenv('SECRET_CP_MPO').encode('utf-8'))
    if h.hexdigest() == token:
        return True
    else:
        return False
