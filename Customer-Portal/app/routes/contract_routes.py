# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the contract routes of the web application.

from flask import request, flash, redirect, url_for, g, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import app, logger, db, Invalid2FA
from app.models.contract import Contract
from app.models.user import User
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
    
    # Check if user has his user_info provided
    for attribute in ["name", "surname", "phone_number", "email", "date_of_birth"]:
        if g.user.get_attribute(attribute) == None or g.user.get_attribute(attribute) == "None":
            logger.warning(f"Contract Denied. User with ID: '{g.user.get_id()}' has no '{attribute}' provided.")
            flash("Please provide your personal information first")
            return redirect(url_for('update_user_info'))
        
    # Check if user has his address provided
    address_dict = g.user.get_address()

    for attribute in ["plz", "street", "street_house_number", "city", "country"]:
        if address_dict[attribute] == None:
            logger.warning(f"Contract Denied. User with ID: '{g.user.get_id()}' has no '{attribute}' provided.")
            flash("Please provide your address first")
            return redirect(url_for('update_user_info'))


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
    if Contract.find_by_electricity_meter_id(db=db, electricity_meter_id=electricity_meter_id) != None:
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
        user = User.find_by_id(db=db, user_id=get_jwt_identity())
        user.add_contract(contract_id=contract.get_id())
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
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

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

    It is only possible to change the notes and the auto_renew attribute of the contract.

    Raise Invalid2FA if the user is not 2fa authenticated.
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
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

    #Check if contract is still active
    if contract.get_attribute("enddate") < datetime.now().strftime("%Y-%m-%d"):
        logger.warning(f"Contract with ID: '{contract_id}' is not active.")
        flash("Contract is not active")
        return redirect(url_for('dashboard'))
        
    # Check if "notes" or "auto_renew" in request.form
    if "notes" not in request.form and "auto_renew" not in request.form:
        logger.warning(f"Attribute is not allowed to be updated.")
        flash("Attribute is not allowed to be updated")
        return redirect(url_for('contract', contract_id=contract_id))
    
    # Check regex for "notes" and format of "auto_renew"
    if "auto_renew" in request.form and request.form["auto_renew"] not in ["true", "false"]:
        logger.warning(f"Auto renew in wrong format.")
        flash("Auto renew in wrong format")
        return redirect(url_for('contract', contract_id=contract_id))

    if "notes" in request.form and not validate_text(request.form['notes']):
        logger.warning(f"Notes in wrong format.")
        flash("Notes in wrong format")
        return redirect(url_for('contract', contract_id=contract_id))
        
    if "notes" in request.form:
        # Update contract
        contract.update_attribute(attribute="notes", value=request.form['notes'])

    if "auto_renew" in request.form:
        # Update contract
        if request.form["auto_renew"] == "true":
            contract.update_attribute(attribute="auto_renew", value=True)
        elif request.form["auto_renew"] == "false":
            contract.update_attribute(attribute="auto_renew", value=False)


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
    contract_list = g.user.get_contract_list()

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

    #Check if contract is still active
    if contract.get_attribute("enddate") < datetime.now().strftime("%Y-%m-%d"):
        logger.warning(f"Contract with ID: '{contract_id}' is not active.")
        flash("Contract is not active")
        return redirect(url_for('dashboard'))

    
    # Check if termination is already requested
    if contract.get_attribute("termination_requested") == "True" or contract.get_attribute("termination_requested") == True or contract.get_attribute("termination_requested") == "true":
        logger.warning(f"Contract with ID: '{contract_id}' already requested termination.")
        flash("Contract already requested termination")
        return redirect(url_for('dashboard'))
    
    # Update contract
    contract.update_attribute(attribute="termination_requested", value=True)

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
    contract_list = g.user.get_contract_list()

    if contract_id not in contract_list:
        logger.warning(f"Contract with ID: '{contract_id}' does not exist for user with ID: '{g.user.get_id()}'.")
        flash("Contract does not exist")
        return redirect(url_for('dashboard'))
    
    # Load contract
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

    #Check if contract is still active
    if contract.get_attribute("enddate") < datetime.now().strftime("%Y-%m-%d"):
        logger.warning(f"Contract with ID: '{contract_id}' is not active.")
        flash("Contract is not active")
        return redirect(url_for('dashboard'))

    # Get contract data
    contract_information_json = contract.get_contract_data()

    contract_information_json.pop("_id")
    
    return redirect(url_for('contract',
                            contract_id=contract_id,
                            contract_information_json=contract_information_json))