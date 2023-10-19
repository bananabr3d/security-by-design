from flask import request
from flask_jwt_extended import jwt_required
from app import app, logger

@app.route('/add-contract', methods=['POST'])
@jwt_required()
def add_contract():
    logger.info(str(request.method) + "-Request on " + request.path)

    # Add here information from form to contract object and then save it in the db
 
# # Change to "Netzstellenbetreiber" routes in other app
# @app.route('/api/register', methods=['GET'])
# def api_register():
#     logger.info("Get-Request: Electricity-Meter /register")
#     # register a new electricity-meter:
#     # 1. Generate a random number (ID) # Maybe id + password auth?
#     # 2. Check if the number is already in the "electricity-meter" collection
#     # 3.1 If so, generate new one, until its new
#     # 3.2 If not, save hash in db and give number to the electricity-meter's get-response body
#     return 1

# @app.route('/api/heartbeat', methods=['POST'])
# def api_heartbeat():
#     electricity_meter = 1 # Change to its ID from the POST
#     logger.info("POST-Request: Electricity-Meter heartbeat: ", electricity_meter)
#     # Set status of electricity-meter to "online" and update "last_heartbeat" 
#     # (anywhere in the code the electricity-meters will get checked every 5 mins and if the last heartbeat was more than 3min ago, the em will be displayed offline)
#     # Also update the values provided by the em