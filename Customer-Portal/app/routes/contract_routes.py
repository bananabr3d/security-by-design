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
from re import compile, fullmatch
from dotenv import load_dotenv
load_dotenv()
import os

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
    notes = request.form['notes']
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

    if not fullmatch( address_plz_regex , address_plz):
        logger.warning(f"Contract Denied PLZ in wrong format")
        flash("Your PLZ is in an wrong format")
        return redirect(url_for('dashboard'))
    elif not fullmatch( address_street_city_country_regex, address_street):
        logger.warning(f"Contract Denied street in wrong format")
        flash("Your Street is in an wrong format")
        return redirect(url_for('dashboard'))
    elif not fullmatch( address_street_city_country_regex, address_city):
        logger.warning(f"Contract Denied City in wrong format")
        flash("Your City is in an wrong format")
        return redirect(url_for('dashboard'))
    elif not fullmatch( address_street_city_country_regex, address_country,):
        logger.warning(f"Contract Denied Country in wrong format")
        flash("Your Country is in an wrong format")
        return redirect(url_for('dashboard'))
    elif not fullmatch( address_street_house_number_regex, address_street_number):
        logger.warning(f"Contract Denied Street Number in wrong format")
        flash("Your Street Number is in an wrong format")
        return redirect(url_for('dashboard'))
    # Check electricity_meter_id for correct format and check with metering point operator if it exists and is free
    # Add notes regex check (import text regex from routes.py) and em regex before checking with metering point operator
    # TODO
    shared_secret =  os.getenv("authorization_header")#TODO change name to shared secret
    url = "metering-point-operator:5000/getcounterstatus/" + electricity_meter_id


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

        date = datetime.now()
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

    #Check if contract is still active
    if contract.get_attribute("enddate") < datetime.now().strftime("%Y-%m-%d"):
        logger.warning(f"Contract with ID: '{contract_id}' is not active.")
        flash("Contract is not active")
        return redirect(url_for('dashboard'))

    # Build contract_show dict
    contract_show = contract.get_contract_data()
    contract_show["active"] = True # As the contract is still active, see if statement before

    try:
        # Get contract_information_json from contract
        contract_information_json = request.args.get('contract_information_json')
    except:
        contract_information_json = None

    return render_template('contract.html', 
                           contract=contract_show, 
                           jwt_authenticated=g.jwt_authenticated, 
                           twofa_activated=g.twofa_activated, 
                           twofa_authenticated=g.twofa_authenticated, 
                           admin=g.admin,
                           contract_information_json=contract_information_json
                           )

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

    # Get contract data
    contract_information_json = contract.get_contract_data()

    contract_information_json.pop("_id")
    
    return redirect(url_for('contract',
                            contract_id=contract_id,
                            contract_information_json=contract_information_json))