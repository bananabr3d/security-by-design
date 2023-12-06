# Contributions by: Vitali Bier
# Description: This file contains the admin routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import request, render_template, redirect, url_for, flash, make_response, g
from flask_jwt_extended import jwt_required

# Import app, logger, db, jwt object, exceptions and models from app package
from app import app, logger, db, Invalid2FA

# Import from models
from app.models.user import get_user_count, get_usernames, User
from app.models.contract import get_contracts_termination_requested, Contract

# Import for mpo communication
from requests import post
from hashlib import sha256
import os

# ===== Routes =====
# === Admin Panel ===
@app.route('/admin', methods=['GET'])
@jwt_required()
def admin_dashboard():
    '''
    This function handles the GET dashboard/admin route.

    Raise Invalid2FA if the user is not 2fa authenticated.

    Returns the admin dashboard template.
    '''
    # Check if the user is 2fa authenticated
    if not g.twofa_authenticated:
        raise Invalid2FA
    
    # Check if the user is an admin
    if not g.admin:
        # If not, redirect to dashboard
        return redirect(url_for('dashboard'))
    
    # Get user count
    user_count = get_user_count(db=db)

    # Get usernames
    usernames = get_usernames(db=db)

    # Get contracts with termination requested == True
    contracts_termination_requested = get_contracts_termination_requested(db=db)

    # Turn contracts into dicts
    contracts_termination_requested_data_list = list()

    for contract in contracts_termination_requested:
        # Turn contracts into dicts
        temp_contract = contract.get_contract_data()

        logger.debug(temp_contract)
        
        # for every contract search for the user and add its username as "customer" key
        user = User.find_by_contract_id(db=db, contract_id=temp_contract["_id"])
        temp_contract["customer"] = user["username"]
        logger.debug(temp_contract)

        contracts_termination_requested_data_list.append(temp_contract)

    logger.info(f"Admin {g.user['username']} accessed the admin dashboard.")

    # Render the admin dashboard
    return render_template('admin_dashboard.html', user_count=user_count, 
                           jwt_authenticated=g.jwt_authenticated, 
                           twofa_activated=g.twofa_activated, 
                           twofa_authenticated=g.twofa_authenticated, 
                           username=g.user['username'], 
                           admin=g.admin, usernames=usernames,
                           contracts_termination_requested=contracts_termination_requested_data_list)

# === Confirm Contract Termination ===
@app.route('/admin/confirm-contract-termination/<contract_id>', methods=['POST'])
@jwt_required(fresh=True)
def confirm_contract_termination(contract_id):
    '''
    This function handles the POST admin/confirm-contract-termination/<contract_id> route.

    Raise Invalid2FA if the user is not 2fa authenticated.

    Returns the confirm contract termination template.
    '''
    # Check if the user is 2fa authenticated
    if not g.twofa_authenticated:
        raise Invalid2FA
    
    # Check if the user is an admin
    if not g.admin:
        # If not, redirect to dashboard
        return redirect(url_for('dashboard'))

    # Get the contract
    contract = Contract.find_by_id(db=db, contract_id=contract_id)

    # Get the electricity meter id
    electricity_meter_id = contract["electricity_meter_id"]

    # Set up secret header
    h = sha256()
    h.update(os.getenv("SECRET_CP_MPO").encode("utf-8"))

    # Send post request to mpo in order to free the electricity meter
    request = post(f"http://metering-point-operator:5000/api/freecounter/{electricity_meter_id}", headers={"Authorization":h.hexdigest()})

    # Check status code of mpo response
    if request.status_code == 200:
        logger.info(f"Electricity meter with ID {electricity_meter_id} successfully freed.")

        # Delete contract
        contract.delete()

        # Remove contract from user
        g.user.remove_contract(contract_id=contract_id)

        logger.info(f"Admin {g.user['username']} confirmed the termination of contract {contract_id}.")

        logger.debug(f"Contract with ID '{contract_id}' successfully deleted.")
        flash("Contract successfully deleted", "success")
        return redirect(url_for('admin_dashboard'))
    
    elif request.status_code == 301:
        logger.error(f"Contract with electricity_meter_id: '{electricity_meter_id}'. Electricity meter is not free.")
        flash("Contract termination could not be denied. Electricity meter is already free", "error")
        return redirect(url_for('admin_dashboard'))

    elif request.status_code == 401:
        logger.error(f"Contract with electricity_meter_id: '{electricity_meter_id}'. Authentication failed.")
        flash("Contract termination could not be denied. Authorization failed", "error")
        return redirect(url_for('admin_dashboard'))
    
    elif request.status_code == 500:
        logger.error(f"Contract with electricity_meter_id: '{electricity_meter_id}'. MPO internal server error.")
        flash("Contract termination could not be denied. MPO internal server error", "error")
        return redirect(url_for('admin_dashboard'))

# === Decline Contract Termination ===
@app.route('/admin/decline-contract-termination/<contract_id>', methods=['POST'])
@jwt_required(fresh=True)
def decline_contract_termination(contract_id):
    '''
    This function handles the POST admin/decline-contract-termination/<contract_id> route.

    Raise Invalid2FA if the user is not 2fa authenticated.

    Returns the decline contract termination template.
    '''
    # Check if the user is 2fa authenticated
    if not g.twofa_authenticated:
        raise Invalid2FA
    
    # Check if the user is an admin
    if not g.admin:
        # If not, redirect to dashboard
        return redirect(url_for('dashboard'))

    # Get the contract
    contract = Contract.find_by_id(db=db, contract_id=contract_id)


    # Set termination_requested to False
    contract["termination_requested"] = False

    logger.info(f"Admin {g.user['username']} declined the termination of contract {contract_id}.")

    logger.debug(f"Contract with ID '{contract_id}' successfully declined.")
    flash("Contract termination successfully declined", "success")
    return redirect(url_for('admin_dashboard'))
    


# === Admin Before Request ===
@app.before_request
@jwt_required(optional=True)
def before_request_admin():
    '''
    This function is executed before each request.

    It checks if the user is a admin
    '''
    try: # last resort error handling

        g.admin = False

        if g.user:
            if g.user["admin"] == True or g.user["admin"] == "True" or g.user["admin"] == "true":
                logger.debug("User is admin.")

                g.admin = True

    except Exception as e:
        logger.error(f"Error while executing before_request_admin: {e}")