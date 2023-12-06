from app import app, db, logger

from flask import request, make_response

import hashlib

from dotenv import load_dotenv
import os

from bson.objectid import ObjectId

from datetime import datetime

load_dotenv()

# Delete all current electricity meters
logger.info("Deleting all current electricity meters...")
db.electricity_meter.delete_many({})

@app.route('/api/heartbeat/<counter_id>', methods=['POST'])
def post_counter_hearbeat(counter_id):
    try:
        if authorize(request.headers.get('Authorization')):
            # Check if the em with _id exists
            data = db.electricity_meter.find_one({"_id": ObjectId(counter_id)})
            
            if data:
                logger.info(f"Electricity meter with ID {counter_id} exists.")
            else:
                logger.info(f"Electricity meter with ID {counter_id} does not exist yet.")
                # If not, create it
                db.electricity_meter.insert_one({"_id": ObjectId(counter_id)})
                # Set the status to free (True)
                db.electricity_meter.update_one({"_id": ObjectId(counter_id)}, {"$set": {"em_status": True}})
                # Set em ip
                db.electricity_meter.update_one({"_id": ObjectId(counter_id)}, {"$set": {"em_ip": request.remote_addr}})
    

            logger.info(f"Received heartbeat from electricity meter with ID {counter_id}. Update value...")
            # Update the em_value
            db.electricity_meter.update_one({"_id": ObjectId(counter_id)}, {"$set": {"em_value": request.json.get('em_value')}})
            # Update em timestamp
            db.electricity_meter.update_one({"_id": ObjectId(counter_id)}, {"$set": {"em_last_update": datetime.now()}})
            # Send 200 status code
            return make_response('', 200)
        else:
            return make_response('', 401)
    except:
        return make_response('', 500)




def authorize(token) -> bool:
    h = hashlib.sha256()
    h.update(os.getenv('SECRET_MPO_EM').encode('utf-8'))
    if h.hexdigest() == token:
        return True
    else:
        return False
