# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the regular routes of the web application.
# Last update: 23.10.2023

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
from app.models.contract import load_contract

# ===== Routes =====

# === Home / Index ===
@app.route('/')
@jwt_required(optional=True) # optional=True allows to access the route without a valid JWT, but checks it if it is present
def home():
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
    logger.info(str(request.method) + "-Request on " + request.path)

    try: # last resort error handling

        # Check if user has a valid JWT, then load user object
        if get_jwt_identity():
            user = load_user(db=db, user_id=get_jwt_identity())

        # Check if user is 2FA authenticated
        result_check_2fa = check_2fa(twofa_activated=user.get_attribute('twofa_activated'), jwt_token=get_jwt())
        if result_check_2fa != None:
            return result_check_2fa 

        # Add here loading of all contracts of user and then displaying the status, ...
        # contract_list = user.get_attribute("contracts")
        
        # # 1. load data from contract of user
        # for contract_id in contract_list:
        #     contract = load_contract(contract_id)

            # 2. make request on Messstellenbetreiber for data of each contract => How to implement? Do we load a contract.html in the dashboard.html or can we add it here in the return?

        
        #render_template with contract objects for each contract
        return render_template('dashboard.html', loggedin=True, username=user.get_attribute('username'))
    
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500

# === Error handling ===
@app.errorhandler(404)
@jwt_required(optional=True)
def page_not_found(errorhandler_error):
    logger.info(str(request.method) + "-Request on " + request.path)
    logger.debug("Error from errorhandler: " + str(errorhandler_error))

    try: # last resort error handling

        # # Check if user has a valid JWT and display the error page accordingly
        # if get_jwt_identity() and check_2fa(twofa_activated=load_user(db=db, user_id=get_jwt_identity()).get_attribute('twofa_activated'), jwt_token=get_jwt()) == None:
        #     logger.debug("Error Page displayed for logged in user")
        #     return render_template('PageNotFound.html', loggedin=True), 404
        # else:
            logger.debug("Error Page displayed for not logged in user")
            return render_template('PageNotFound.html'), 404
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500