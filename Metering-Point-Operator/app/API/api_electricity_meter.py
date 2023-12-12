from app import app, db, logger, csrf

from flask import request, make_response

import hashlib

from dotenv import load_dotenv
import os

from bson.objectid import ObjectId

from datetime import datetime

from ..models.electricity_meter import ElectricityMeter, load_electricity_meter

load_dotenv()

# Delete all current electricity meters
logger.info("Deleting all current electricity meters...")
db.electricity_meter.delete_many({})

@app.route('/api/heartbeat/<counter_id>', methods=['POST'])
@csrf.exempt
def post_counter_hearbeat(counter_id):
    try:
        if authorize(request.headers.get('Authorization')):
            # Check if the em with _id exists
            data = db.electricity_meter.find_one({"_id": ObjectId(counter_id)})
            if data == None:

                em = ElectricityMeter(
                    db=db,
                    em_id=ObjectId(counter_id),
                    em_value=request.json.get('em_value'),
                    em_status=True,
                    em_error= None,
                    em_last_update=datetime.fromtimestamp(datetime.now().timestamp()),
                    em_manufacturer=request.json.get('manufacturer'),
                    em_model=request.json.get('model'),
                    em_serial_number=request.json.get('serial_number'),
                    em_firmware_version=request.json.get('firmware_version'),
                    em_maintain=False,
                    em_ip = request.remote_addr

                )
                em.save(db=db)
                logger.info(f"Electricity meter with ID {db.electricity_meter.find_one({"_id" : ObjectId(counter_id)})} does not exist yet. Saving new one")

            else:
                logger.info(f"Received heartbeat from electricity meter with ID {counter_id}. Update value...")

                # Update the em_value
                db.electricity_meter.update_one({"_id": ObjectId(counter_id)}, {"$set": {"em_value": request.json.get('em_value')}})
                db.electricity_meter.update_one({"_id": ObjectId(counter_id)}, {"$set": {"em_last_update": datetime.fromtimestamp(datetime.now().timestamp())}})
                em = load_electricity_meter(db=db, em_id=counter_id)
                if em.get_em_maintain():
                    logger.info(f"Electricity meter with ID {counter_id} is not in maintenance mode anymore. Not updating value.")
                    em.toggle_maintain()
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
