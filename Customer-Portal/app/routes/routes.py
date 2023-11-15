# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import request, render_template, url_for, redirect, flash, g

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
    '''
    return render_template('index.html', jwt_authenticated=g.jwt_authenticated, twofa_authenticated=g.twofa_authenticated)
    
# === Dashboard ===
@app.route('/dashboard', methods=['GET'])
@jwt_required() # jwt_required() requires a valid JWT to access the route
def dashboard():
    '''
    This function handles the dashboard page of the web application.

    The JWT Token is required and the 2fa is checked. Then the dashboard page is displayed accordingly.
    '''
        
    # Check if user is 2FA authenticated #TODO
    result_check_2fa = check_2fa(twofa_activated=g.user.get_attribute('twofa_activated'), jwt_token=get_jwt())
    if result_check_2fa != None:
        return result_check_2fa 
    
    # 1. load all contract objects of user
    contract_list = load_contract_data(g.user, db)

    transformed_contract_list = list()

    # Transform contract objects in list to dicts
    for contract in contract_list:
        temp_contract = {"_id": contract.get_id(), "electricity_meter_id": contract.get_attribute("electricity_meter_id")}
        transformed_contract_list.append(temp_contract)

    # 2. make request on Messstellenbetreiber for data of each contract => How to implement? Do we load a contract.html in the dashboard.html or can we add it here in the return?
    
    #render_template with contract objects for each contract
    return render_template('dashboard.html', jwt_authenticated=g.jwt_authenticated, twofa_authenticated=g.twofa_authenticated, username=g.user.get_attribute('username'), contract_list=transformed_contract_list)
    
# === User Info Page ===
@app.route('/user_info', methods=['GET'])
@jwt_required()
def user_info():
    '''
    This function handles the user info page of the web application.

    The JWT Token is required and the 2fa is checked. Then the user info page is displayed accordingly.
    '''

    # Render the user_info.html template with user data
    return render_template('user_info.html', 
                            jwt_authenticated=g.jwt_authenticated, 
                            username=g.user.get_attribute("username"), 
                            email=g.user.get_attribute('email'),
                            twofa_activated=g.user.get_attribute('twofa_activated'), 
                            twofa_authenticated=g.twofa_authenticated,
                            contract_list=g.user.get_contract_list())

# === Before Request ===
@app.before_request
@jwt_required(optional=True)
def before_request_main():
    '''
    This function is executed before each request.

    It logs the request method and the request path. It also checks wether the user has a valid JWT and 2fa authentication and stores the result in the g object.
    '''

    try: # last resort error handling

        g.jwt_authenticated = False
        g.twofa_authenticated = False
        g.user = None

        # Check if user has a valid JWT
        if get_jwt_identity():
            logger.debug("User has a valid JWT")
            g.jwt_authenticated = True
            g.user = load_user(db=db, user_id=get_jwt_identity())

            twofa_activated = g.user.get_attribute('twofa_activated')
            
            # Check if user has a valid JWT and 2fa authentication
            if check_2fa(twofa_activated=twofa_activated, jwt_token=get_jwt()) == None:
                logger.debug("User is not 2fa authenticated")
                g.twofa_authenticated = True
            
    except Exception as e:
        logger.error(f"Error in before_request: {e}")


# === Error handling ===
@app.errorhandler(404)
@jwt_required(optional=True)
def page_not_found(errorhandler_error):
    '''
    This function handles the error page of the web application.

    The JWT Token is checked and the error page is displayed accordingly.
    '''
    logger.debug(f"Error on Code 404: {errorhandler_error}")

    try: # last resort error handling
        return render_template('PageNotFound.html', jwt_authenticated=g.jwt_authenticated, twofa_authenticated=g.twofa_authenticated), 404
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500
    

@app.errorhandler(500)
def internal_server_error(errorhandler_error):
    '''
    This function handles the internal server error page of the web application. It will be called if an error occurs in the application, but not if errors occur in other error handling or before/after request functions.
    
    The error is logged and the user is redirected to the home page.
    '''
    logger.error(f"Error: {errorhandler_error}")
    flash("Internal Server Error, redirect to home", "error")
    return redirect(url_for('home')), 500