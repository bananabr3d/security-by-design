# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the contract routes of the web application.
# Last update: 23.10.2023

from flask import request, flash, redirect, url_for, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import app, logger, db
from app.models.contract import Contract
from app.models.user import load_user

@app.route('/add-contract', methods=['POST'])
@jwt_required()
def add_contract():
    logger.info(str(request.method) + "-Request on " + request.path)
    
    try: # last resort error handling

        # Add here information from form to contract object and then save it in the db
        electricity_meter_id = request.form['electricity_meter_id']
        # Check electricity_meter_id for correct format
        #TODO

        # Check if contract with electricity_meter_id already exists
        if Contract.find_contract_by_electricity_meter_id(db=db, electricity_meter_id=electricity_meter_id) != None:
            logger.warning("Contract with electricity_meter_id %s already exists.", electricity_meter_id)
            flash("A contract with the provided Electricity Meter ID already exists")
            return redirect(url_for('dashboard'))
        
        else:
            contract = Contract(db=db, electricity_meter_id=electricity_meter_id)
            contract.save(db=db)
            logger.debug("Contract with Electricity Meter ID '%s' successfully created.", electricity_meter_id)

            # Add contract to user
            user = load_user(db=db, user_id=get_jwt_identity())
            user.add_contract(db=db, contract_id=contract.get_id())
            logger.debug("Contract successfully added to user")
            flash("Contract successfully added", "success")

            return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500
    
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