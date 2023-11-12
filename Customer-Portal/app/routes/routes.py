# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the regular routes of the web application.
# Last update: 25.10.2023

# ===== Packages =====
# Packages for Flask
from flask import request, render_template, url_for, redirect, flash

# Packages for JWT
from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt, unset_jwt_cookies

# Import app, logger and db object from app package
from app import app, logger, db

# Import check_2fa function 
from app.routes.auth_routes import check_2fa

# Import models
from app.models.user import load_user
from app.models.contract import load_contract_data

# ===== Routes =====

# === Home / Index ===
@app.route('/')
@jwt_required(optional=True) # optional=True allows to access the route without a valid JWT, but checks it if it is present
def home():
    '''
    This function handles the home page of the web application.

    The JWT Token is checked and the home page is displayed accordingly.
    '''
    logger.info(str(request.method) + "-Request on " + request.path)

    try: # last resort error handling

        # Check if user has a valid JWT and display the starting page accordingly
        if get_jwt_identity() and check_2fa(twofa_activated=load_user(db=db, user_id=get_jwt_identity()).get_attribute('twofa_activated'), jwt_token=get_jwt()) == None:
            logger.debug("Starting Page displayed for logged in user")
            return render_template('index.html', loggedin=True)
        else:
            logger.debug("Starting Page displayed for not logged in user")
            return render_template('index.html')
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500

# === Dashboard ===
@app.route('/dashboard', methods=['GET'])
@jwt_required() # jwt_required() requires a valid JWT to access the route
def dashboard():
    '''
    This function handles the dashboard page of the web application.

    The JWT Token is required and the 2fa is checked. Then the dashboard page is displayed accordingly.
    '''
    logger.info(str(request.method) + "-Request on " + request.path)

    try: # last resort error handling

        # Check if user has a valid JWT, then load user object
        if get_jwt_identity():
            user = load_user(db=db, user_id=get_jwt_identity())
            
        # Check if user is 2FA authenticated
        result_check_2fa = check_2fa(twofa_activated=user.get_attribute('twofa_activated'), jwt_token=get_jwt())
        if result_check_2fa != None:
            return result_check_2fa 
        
        # 1. load all contract objects of user
        contract_list = load_contract_data(user, db)

        transformed_contract_list = list()

        # Transform contract objects in list to dicts
        for contract in contract_list:
            temp_contract = {"_id": contract.get_id(), "electricity_meter_id": contract.get_attribute("electricity_meter_id")}
            transformed_contract_list.append(temp_contract)

        # 2. make request on Messstellenbetreiber for data of each contract => How to implement? Do we load a contract.html in the dashboard.html or can we add it here in the return?
        
        #render_template with contract objects for each contract
        return render_template('dashboard.html', loggedin=True, username=user.get_attribute('username'), contract_list=transformed_contract_list)
    
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500

# === Error handling ===
@app.errorhandler(404)
@jwt_required(optional=True)
def page_not_found(errorhandler_error):
    '''
    This function handles the error page of the web application.

    The JWT Token is checked and the error page is displayed accordingly.
    '''
    logger.info(str(request.method) + "-Request on " + request.path)
    logger.debug("Error from errorhandler: " + str(errorhandler_error))

    try: # last resort error handling

        # Check if user has a valid JWT and display the error page accordingly
        if get_jwt_identity() and check_2fa(twofa_activated=load_user(db=db, user_id=get_jwt_identity()).get_attribute('twofa_activated'), jwt_token=get_jwt()) == None:
            logger.debug("Error Page displayed for logged in user")
            return render_template('PageNotFound.html', loggedin=True), 404
        else:
            logger.debug("Error Page displayed for not logged in user")
            return render_template('PageNotFound.html'), 404
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500
    

# New route for user information
@app.route('/user_info', methods=['GET'])
@jwt_required()  # Requires a valid JWT to access the route
def user_info():
    try:
        # Check if the user has a valid JWT
        if get_jwt_identity():
            user = load_user(db=db, user_id=get_jwt_identity())

            # Render the user_info.html template with user data
            return render_template('user_info.html', loggedin=True, username=user.get_attribute('username'), email=user.get_attribute('email'), twofa_activated=user.get_attribute('twofa_activated'), contract_list=user.get_attribute('contract_list'))

        # If the JWT is not valid, you can redirect or handle it accordingly
        else:
            flash("Invalid JWT", "error")
            return redirect(url_for('home'))

    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500