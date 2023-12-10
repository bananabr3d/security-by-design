# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the contract routes of the web application.

from flask import request, flash, redirect, url_for, g, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import app, logger, db, Invalid2FA
from app.models.contract import Contract, get_all_contracts
from app.models.user import User
from app.routes.auth_routes import validate_text
from app.routes.routes import address_plz_regex, address_street_city_country_regex, address_street_house_number_regex
from requests import get, post
from datetime import datetime, timedelta
from re import fullmatch
from dotenv import load_dotenv
load_dotenv()
import os
from hashlib import sha256
# For checking expired contracts
from threading import Timer


# Remove all existing contracts
db.contracts.delete_many({})
logger.info("All contracts deleted")
# Remove all contracts in user db
db.users.update_many({}, {"$set": {"contract_list": []}})
logger.info("All contracts deleted in user db")


@app.route('/add-contract', methods=['POST'])
@jwt_required(fresh=True)
def add_contract():
    '''
    This function handles the add-contract page of the web application. The JWT Token is required and the 2fa is checked. 

    If the Electricity-Meter ID is correct, adds a new contract to the user and redirects to the dashboard page.
    '''

    if not g.twofa_authenticated:
        raise Invalid2FA
    
    # Check if user has his user_info provided
    for attribute in ["name", "surname", "phone_number", "email", "date_of_birth"]:
        if g.user[attribute] == None or g.user[attribute] == "None":
            logger.warning(f"Contract Denied. User with ID: '{g.user.get_id()}' has no '{attribute}' provided.")
            flash("Please provide your personal information first", "warning")
            return redirect(url_for('update_user_info'))
        
    # Check if user has his address provided
    address_dict = g.user['address']

    for attribute in ["plz", "street", "street_house_number", "city", "country"]:
        if address_dict[attribute] == None:
            logger.warning(f"Contract Denied. User with ID: '{g.user.get_id()}' has no '{attribute}' provided.")
            flash("Please provide your address first", "warning")
            return redirect(url_for('update_user_info'))


    # Add here information from form to contract object and then save it in the db
    electricity_meter_id = request.form['electricity_meter_id']

    # Check with regex if all attributes are in the correct format
    if not fullmatch( address_plz_regex , request.form['address_plz']):
        logger.warning(f"Contract Denied PLZ in wrong format")
        flash("Your PLZ is in an wrong format", "failed")
        return redirect(url_for('dashboard'))
    
    elif not fullmatch( address_street_city_country_regex, request.form['address_street']):
        logger.warning(f"Contract Denied street in wrong format")
        flash("Your Street is in an wrong format", "failed")
        return redirect(url_for('dashboard'))
    
    elif not fullmatch( address_street_city_country_regex, request.form['address_city']):
        logger.warning(f"Contract Denied City in wrong format")
        flash("Your City is in an wrong format", "failed")
        return redirect(url_for('dashboard'))
    
    elif not fullmatch( address_street_city_country_regex, request.form['address_country'],):
        logger.warning(f"Contract Denied Country in wrong format")
        flash("Your Country is in an wrong format", "failed")
        return redirect(url_for('dashboard'))
    
    elif not fullmatch( address_street_house_number_regex, request.form['address_street_number']):
        logger.warning(f"Contract Denied Street Number in wrong format")
        flash("Your Street Number is in an wrong format", "failed")
        return redirect(url_for('dashboard'))
    
    elif not validate_text(request.form['notes']):
        logger.warning(f"Contract Denied Notes in wrong format")
        flash("Your Notes are in an wrong format", "failed")
        return redirect(url_for('dashboard'))
    
        # Match ObjectID String with RegEx (A-Z, a-z, 0-9)
    elif not fullmatch(r'[a-zA-Z0-9]{24}', electricity_meter_id):
        logger.warning(f"Contract Denied Electricity Meter ID in wrong format")
        flash("Your Electricity Meter ID is in an wrong format", "failed")
        return redirect(url_for('dashboard'))
    
    # Check electricity_meter_id with metering point operator if it exists and is free
    h = sha256()
    h.update(os.getenv("SECRET_CP_MPO").encode("utf-8"))
    url = "http://metering-point-operator:5000/api/getcounterstatus/" + electricity_meter_id

    response = get(url,  headers={"Authorization":h.hexdigest()})
    blocked = True

    if response.status_code == 401:
        logger.error(f"Contract with electricity_meter_id: '{electricity_meter_id}'. Authentication failed.")
        flash("Contract could not be created. Please contact an Administrator", "error")
        return redirect(url_for('dashboard'))
    
    elif response.status_code == 301:
        logger.warning(f"Contract with electricity_meter_id: '{electricity_meter_id}' is checked out already.")
        flash(f"The electricity meter with ID '{electricity_meter_id}' is blocked", "failed")
        return redirect(url_for('dashboard'))
    
    elif response.status_code == 200:
        logger.debug("Electricitymeter is not taken")
        
        blocked = False

    elif response.status_code == 500:
        logger.warning(f"Contract with electricity_meter_id: '{electricity_meter_id}' could not be created. Server Error from Metering Point Operator.")
        flash("Contract could not be created. Please contact an Administrator", "error")
        return redirect(url_for('dashboard'))

    # Check if contract with electricity_meter_id already exists
    if Contract.find_by_electricity_meter_id(db=db, electricity_meter_id=electricity_meter_id) != None:
        logger.warning(f"Contract with electricity_meter_id: '{electricity_meter_id}' already exists.")
        flash("A contract with the provided Electricity Meter ID already exists", "failed")
        return redirect(url_for('dashboard'))
    
    elif blocked == False:
        date = datetime.now()
        date2 = date + timedelta(days=90)

        startdate = date.strftime("%Y-%m-%d")
        enddate = date2.strftime("%Y-%m-%d")

        contract = Contract(db=db, electricity_meter_id=electricity_meter_id, startdate=startdate, enddate=enddate, notes=request.form['notes'], address_plz=request.form['address_plz'], address_street=request.form['address_street'], address_street_number=request.form['address_street_number'], address_city=request.form['address_city'], address_country=request.form['address_country'])
        contract.save()
        logger.debug(f"Contract with Electricity Meter ID '{electricity_meter_id}' successfully created.")

        # Add contract to user
        user = User.find_by_id(db=db, user_id=get_jwt_identity())
        user.add_contract(contract_id=contract.get_id())
        logger.debug("Contract successfully added to user")
        flash("Contract successfully added", "success")

        return redirect(url_for('dashboard'))
    
    else:
        logger.warning(f"Contract with electricity_meter_id: '{electricity_meter_id}' could not be created.")
        flash("Contract could not be created. Please contact an Administrator", "error")
        return redirect(url_for('dashboard'))

@app.route('/dashboard/<contract_id>', methods=['GET'])
@jwt_required()
def contract(contract_id: str):
    '''
    This function handles the contract page of the web application. The JWT Token is required. 

    If the contract_id is correct, the contract page is rendered.
    '''

    # Check if user has the contract, get contract_list from user
    contract_list = g.user['contract_list']

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist", "failed")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

    # Build contract_show dict
    contract_show = contract.get_contract_data()
    contract_show["active"] = "Yes" # As the contract is still active, see if statement before

    # Check if contract is still active
    if contract["enddate"] < datetime.now().strftime("%Y-%m-%d"):
        logger.warning(f"Contract with ID: '{contract_id}' is not active anymore.")
        contract_show["active"] = "No"
        if contract["enddate"] < (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d"):
            flash("The requested contract is already expired.", "warning")
            return redirect(url_for('dashboard'))
        else:
            flash(f"Contract is not active anymore. You can renew your current contract or it will expire in {90 - (datetime.now() - datetime.strptime(contract['enddate'], '%Y-%m-%d')).days} days.", "warning")

    try:
        # Get contract_information_json from contract
        contract_information_json = request.args.get('contract_information_json')
    except:
        contract_information_json = None

    # Get em value from metering point operator
    em_id = contract["electricity_meter_id"]

    # Get secret for request
    h = sha256()
    h.update(os.getenv("SECRET_CP_MPO").encode("utf-8"))

    # Send request to mpo
    response = get(f"http://metering-point-operator:5000/api/getcounter/{em_id}", headers={"Authorization":h.hexdigest()})

    electricity_meter_value = None

    # Check status code of mpo response
    if response.status_code == 200:
        logger.debug(f"Electricity meter with ID '{em_id}' successfully requested.")
        electricity_meter_value = response.json()["em_value"]
        electricity_meter_last_update = response.json()["em_last_update"]

    elif response.status_code == 401:
        logger.error(f"Electricity meter with ID '{em_id}' could not be requested. Authentication failed.")
        flash("Electricity meter could not be requested. Please contact an Administrator", "error")
        return redirect(url_for('dashboard'))
    
    elif response.status_code == 500:
        logger.error(f"Electricity meter with ID '{em_id}' could not be requested. Server Error from Metering Point Operator.")
        flash("Electricity meter could not be requested. Please contact an Administrator", "error")
        return redirect(url_for('dashboard'))

    return render_template('contract.html', 
                           contract=contract_show, 
                           jwt_authenticated=g.jwt_authenticated, 
                           twofa_activated=g.twofa_activated, 
                           twofa_authenticated=g.twofa_authenticated, 
                           admin=g.admin,
                           contract_information_json=contract_information_json,
                           electricity_meter_value=electricity_meter_value,
                           electricity_meter_last_update=electricity_meter_last_update,
                           jwt_time=g.jwt_time,
                           jwt_freshness=g.jwt_freshness,
                           twofa_time=g.twofa_time)

@app.route('/update-contract/<contract_id>', methods=['POST'])
@jwt_required(fresh=True)
def update_contract(contract_id: str):
    '''
    This function handles the update-contract page of the web application. The JWT Token is required and the 2fa is checked.

    It is only possible to change the notes and the auto_renew attribute of the contract.

    Raise Invalid2FA if the user is not 2fa authenticated.
    '''

    if not g.twofa_authenticated:
        raise Invalid2FA

    # Check if user has the contract, get contract_list from user
    contract_list = g.user['contract_list']

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist", "failed")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

    #Check if contract is still active
    if contract["enddate"] < datetime.now().strftime("%Y-%m-%d"):
        logger.warning(f"Contract with ID: '{contract_id}' is not active.")
        flash("Contract is not active", "failed")
        return redirect(url_for('dashboard'))
        
    # Check if "notes" or "auto_renew" in request.form
    if "notes" not in request.form and "auto_renew" not in request.form:
        logger.warning(f"Attribute is not allowed to be updated.")
        flash("Attribute is not allowed to be updated", "failed")
        return redirect(url_for('contract', contract_id=contract_id))
    
    # Check regex for "notes" and format of "auto_renew"
    if "auto_renew" in request.form and request.form["auto_renew"] not in ["true", "false"]:
        logger.warning(f"Auto renew in wrong format.")
        flash("Auto renew in wrong format", "failed")
        return redirect(url_for('contract', contract_id=contract_id))

    if "notes" in request.form and not validate_text(request.form['notes']):
        logger.warning(f"Notes in wrong format.")
        flash("Notes in wrong format", "failed")
        return redirect(url_for('contract', contract_id=contract_id))
        
    if "notes" in request.form:
        # Update contract
        contract["notes"] = request.form['notes']

    if "auto_renew" in request.form:
        # Update contract
        if request.form["auto_renew"] == "true":
            contract["auto_renew"] = True
        elif request.form["auto_renew"] == "false":
            contract["auto_renew"] = False


    logger.debug(f"Contract with ID '{contract_id}' successfully updated.")
    flash("Contract successfully updated", "success")
    return redirect(url_for('contract', contract_id=contract_id))


@app.route('/request-termination-contract/<contract_id>', methods=['POST'])
@jwt_required(fresh=True)
def request_termination_contract(contract_id: str):
    '''
    This function handles the remove-contract page of the web application. The JWT Token is required and the 2fa is checked. 
    '''
    
    if not g.twofa_authenticated:
        raise Invalid2FA

    # Check if user has the contract, get contract_list from user
    contract_list = g.user['contract_list']

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist", "failed")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

    #Check if contract is still active
    if contract["enddate"] < datetime.now().strftime("%Y-%m-%d"):
        logger.warning(f"Contract with ID: '{contract_id}' is not active.")
        flash("Contract is not active", "failed")
        return redirect(url_for('dashboard'))

    
    # Check if termination is already requested
    if contract["termination_requested"] == "True" or contract["termination_requested"] == True or contract["termination_requested"] == "true":
        logger.warning(f"Contract with ID: '{contract_id}' already requested termination.")
        flash("Contract already requested termination", "failed")
        return redirect(url_for('dashboard'))
    
    # Update contract
    contract["termination_requested"] = True

    logger.debug(f"Contract with ID '{contract_id}' successfully requested termination.")
    flash("Successfully requested contract termination", "success")

    return redirect(url_for('contract', contract_id=contract_id))

@app.route('/export-contract/<contract_id>', methods=['GET'])
@jwt_required(fresh=True)
def export_contract(contract_id: str):
    '''
    This function handles the export_contract route and can only be accessed with a fresh JWT Token.

    Raise Invalid2FA if the user is not 2fa authenticated.

    Returns the export_user.html template.    '''

    if not g.twofa_authenticated:
        raise Invalid2FA

    # Check if user has the contract, get contract_list from user
    contract_list = g.user['contract_list']

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist", "failed")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

    #Check if contract is still active
    if contract["enddate"] < datetime.now().strftime("%Y-%m-%d"):
        logger.warning(f"Contract with ID: '{contract_id}' is not active.")
        flash("Contract is not active", "failed")
        return redirect(url_for('dashboard'))

    # Get contract data
    contract_information_json = contract.get_contract_data()

    contract_information_json.pop("_id")
    
    return redirect(url_for('contract',
                            contract_id=contract_id,
                            contract_information_json=contract_information_json))

def check_expired_contracts():
    '''
    This function checks every 24 hours if a contract is expired and sets the attribute "expired" to True.
    '''

    # Get all contracts
    contracts = get_all_contracts(db=db)

    # Check if contract is more then 90 days over enddate
    for contract in contracts:
        if contract["enddate"] < (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d"):
            logger.debug(f"Contract with ID '{contract.get_id()}' is expired. Deleting it and removing from user.")
            # Free the em
            h = sha256()
            h.update(os.getenv("SECRET_CP_MPO").encode("utf-8"))
            url = "http://metering-point-operator:5000/api/freecounter/" + contract["electricity_meter_id"]

            response = post(url, headers={"Authorization":h.hexdigest()})
            if response.status_code == 200:
                logger.debug(f"Electricity meter with ID '{contract['electricity_meter_id']}' successfully freed.")
            elif response.status_code == 401:
                logger.error(f"Electricity meter with ID '{contract['electricity_meter_id']}' could not be freed. Authentication failed.")
            elif response.status_code == 500:
                logger.error(f"Electricity meter with ID '{contract['electricity_meter_id']}' could not be freed. Server Error from Metering Point Operator.")

            # Delete contract
            contract.delete()

            # Remove contract from user
            user = User.find_by_contract_id(db=db, contract_id=contract.get_id())

            if user != None:
                user.remove_contract(contract_id=contract.get_id())
                logger.debug(f"Contract with ID '{contract.get_id()}' successfully removed from user with ID '{user.get_id()}'.")

    # Check again in 24 hours
    Timer(86400, check_expired_contracts).start()

if not os.getenv("TESTING"):
    # Start the scheduler once
    check_expired_contracts()