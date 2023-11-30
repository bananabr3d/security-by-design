# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the contract routes of the web application.

from flask import request, flash, redirect, url_for, g, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import app, logger, db, Invalid2FA
from app.models.contract import Contract, load_contract
from app.models.user import load_user
from app.routes.auth_routes import validate_text
from requests import get, post
from datetime import datetime, timedelta

@app.route('/add-contract', methods=['POST'])
@jwt_required(fresh=True)
def add_contract():
    '''
    This function handles the add-contract page of the web application. The JWT Token is required and the 2fa is checked. 

    If the Electricity-Meter ID is correct, adds a new contract to the user and redirects to the dashboard page.
    '''

    if not g.twofa_authenticated:
        raise Invalid2FA

    # Add here information from form to contract object and then save it in the db
    electricity_meter_id = request.form['electricity_meter_id']

    # Regex for address_plz, address_street_house_number (5 digits)
    address_plz_regex = compile(r'^\d{5}$')

    # Regex for address_street, address_city, address_country (only letters, äöüÄÖÜß and spaces)
    address_street_city_country_regex = compile(r'^[a-zA-ZäöüÄÖÜß ]+$')

    # Regex for address_street_house_number (only digits, up to 5)
    address_street_house_number_regex = compile(r'^\d{1,5}$')

    address_plz = request.form['address_plz']
    address_street = request.form['address_street']
    address_street_number = request.form['address_street_number']
    address_city = request.form['address_city']
    address_country = request.form['address_country']

    if address_plz != address_plz_regex:
        logger.warning(f"Contract Denied PLZ in wrong format")
        flash("Your PLZ is in an wrong format")
        return redirect(url_for('dashboard'))
    elif address_street != address_street_city_country_regex:
        logger.warning(f"Contract Denied street in wrong format")
        flash("Your Street is in an wrong format")
        return redirect(url_for('dashboard'))
    elif address_city != address_street_city_country_regex:
        logger.warning(f"Contract Denied City in wrong format")
        flash("Your City is in an wrong format")
        return redirect(url_for('dashboard'))
    elif address_country != address_street_city_country_regex:
        logger.warning(f"Contract Denied Country in wrong format")
        flash("Your Country is in an wrong format")
        return redirect(url_for('dashboard'))
    elif address_street_number != address_street_house_number_regex:
        logger.warning(f"Contract Denied Street Number in wrong format")
        flash("Your Street Number is in an wrong format")
        return redirect(url_for('dashboard'))
    # Check electricity_meter_id for correct format and check with metering point operator if it exists and is free
    #TODO
    shared_secret =  None
    url = "127.0.0.1:8443/getcounterstatus/" + electricity_meter_id


    response = get(url,  headers={"Authorization":shared_secret})
    blocked = True

    if response.status_code == 401:
        logger.warning(f"Contract with electricity_meter_id: '{electricity_meter_id}' shared secret wrong.")
        flash("Contract could not be created Please contact an Administrator")
        return redirect(url_for('dashboard'))
    elif response.status_code == 301:
        logger.warning(f"Contract with electricity_meter_id: '{electricity_meter_id}' is checked out already.")
        flash(f"The electricity meter with ID '{electricity_meter_id}' is blocked")
        return redirect(url_for('dashboard'))
    elif response.status_code == 200:
        logger.debug("Electricitymeter is not taken")
        
        blocked = False
        # hier drin sind die eem daten
        # diese dann in dem contract speichern

    # Check if contract with electricity_meter_id already exists
    if Contract.find_contract_by_electricity_meter_id(db=db, electricity_meter_id=electricity_meter_id) != None:
        logger.warning(f"Contract with electricity_meter_id: '{electricity_meter_id}' already exists.")
        flash("A contract with the provided Electricity Meter ID already exists")
        return redirect(url_for('dashboard'))
    
    elif blocked == False:
        auto_renew = False
        renew_period = 1
        notes = ""

        date = datetime.now
        date2 = date + timedelta(days=90)

        startdate = date.strftime("%Y-%m-%d")
        enddate = date2.strftime("%Y-%m-%d")


        contract = Contract(db=db, electricity_meter_id=electricity_meter_id, startdate=startdate, enddate=enddate, renew_period=renew_period, auto_renew=auto_renew, notes=notes, address_plz=address_plz, address_street=address_street, address_street_number=address_street_number, address_city=address_city, address_country=address_country)
        contract.save(db=db)
        logger.debug(f"Contract with Electricity Meter ID '{electricity_meter_id}' successfully created.")

        # Add contract to user
        user = load_user(db=db, user_id=get_jwt_identity())
        user.add_contract(db=db, contract_id=contract.get_id())
        logger.debug("Contract successfully added to user")
        flash("Contract successfully added", "success")

        return redirect(url_for('dashboard'))

@app.route('/dashboard/<contract_id>', methods=['GET'])
@jwt_required()
def contract(contract_id: str):
    '''
    This function handles the contract page of the web application. The JWT Token is required. 

    If the contract_id is correct, the contract page is rendered.
    '''

    # Check if user has the contract, get contract_list from user
    contract_list = g.user.get_contract_list()

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = load_contract(db=db, contract_id=contract_id)

    # Check if contract is still active
    # if contract.get_attribute("active") == False:#TODO
    #     logger.warning(f"Contract with ID: '{contract_id}' is not active.")
    #     flash("Contract is not active")

    # Build contract_show dict
    contract_show = {"_id": contract.get_id(), "electricity_meter_id": contract.get_attribute("electricity_meter_id")}#TODO

    # Build attributes dict for update-contract -> remove _id and electricity_meter_id from
    contract_show["attributes"] = list(contract.contract_data.keys())
    contract_show["attributes"].remove("_id")
    contract_show["attributes"].remove("electricity_meter_id")

    # Add text in first item of attributes to be shown in the frontend
    contract_show["attributes"] = ["Select attribute"] + contract_show["attributes"]

    return render_template('contract.html', contract=contract_show, jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated, admin=g.admin)

@app.route('/update-contract/<contract_id>', methods=['POST'])
@jwt_required(fresh=True)
def update_contract(contract_id: str):
    '''
    This function handles the update-contract page of the web application. The JWT Token is required and the 2fa is checked. 
    '''

    if not g.twofa_authenticated:
        raise Invalid2FA

    # Check if user has the contract, get contract_list from user
    contract_list = g.user.get_contract_list()

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = load_contract(db=db, contract_id=contract_id)

    # Check if contract is still active
    # if contract.get_attribute("active") == False:#TODO
    #     logger.warning(f"Contract with ID: '{contract_id}' is not active.")
    #     flash("Contract is not active")
    
    # Check attribute for correct format
    if not validate_text(request.form['attribute']) or request.form['attribute'] not in contract.contract_data.keys():
        flash("Invalid attribute")
        return redirect(url_for('contract', contract_id=contract_id))
    
    # Check value for correct format #TODO also check if value is sutiable for attribute
    if not validate_text(request.form['value']) or request.form['value'] == "electricity_meter_id" or request.form['value'] == "_id":
        flash("Invalid value")
        return redirect(url_for('contract', contract_id=contract_id))

    # Update contract
    contract.update_attribute(db=db, attribute=request.form['attribute'], value=request.form['value'])

    logger.debug(f"Contract with ID '{contract_id}' successfully updated attribute '{request.form['attribute']}'.")
    flash("Contract successfully updated", "success")
    return redirect(url_for('contract', contract_id=contract_id))


@app.route('/remove-contract/<contract_id>', methods=['POST'])
@jwt_required(fresh=True)
def remove_contract(contract_id: str):
    '''
    This function handles the remove-contract page of the web application. The JWT Token is required and the 2fa is checked. 
    '''

    if not g.twofa_authenticated:
        raise Invalid2FA

    # Check if user has the contract, get contract_list from user
    contract_list = g.user.get_contract_list()

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = load_contract(db=db, contract_id=contract_id)

    # Check if contract is still active
    # if contract.get_attribute("active") == False:#TODO
    #     logger.warning(f"Contract with ID: '{contract_id}' is not active.")
    #     flash("Contract is not active")

    #TODO Send API request to metering point operator to say the em is free again
    
    # Delete contract
    contract.delete(db=db)

    # Remove contract from user
    g.user.remove_contract(db=db, contract_id=contract_id)

    logger.debug(f"Contract with ID '{contract_id}' successfully deleted.")
    flash("Contract successfully deleted", "success")
    return redirect(url_for('dashboard'))

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