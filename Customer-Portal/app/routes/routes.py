# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import render_template, g

# Packages for JWT
from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt

# Import app, logger and db object from app package
from app import app, logger, db, Invalid2FA, security_questions

# Import models
from app.models.user import load_user
from app.models.contract import load_contract_data

# Import datetime, os for cookie expiration handling
from datetime import datetime, timedelta
import os


# ===== Routes =====

# === Home / Index ===
@app.route('/')
@jwt_required(optional=True) # optional=True allows to access the route without a valid JWT, but checks it if it is present
def home():
    '''
    This function handles the home page of the web application.
    '''
    return render_template('index.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated)

# === Dashboard ===
@app.route('/dashboard', methods=['GET'])
@jwt_required() # jwt_required() requires a valid JWT to access the route
def dashboard():
    '''
    This function handles the dashboard page of the web application.

    The JWT Token is required and the 2fa is checked. Then the dashboard page is displayed accordingly.
    '''
        
    if not g.twofa_authenticated:
        raise Invalid2FA
    
    # 1. load all contract objects of user
    contract_list = load_contract_data(g.user, db)

    transformed_contract_list = list()

    # Transform contract objects in list to dicts
    for contract in contract_list:
        temp_contract = {"_id": contract.get_id(), "electricity_meter_id": contract.get_attribute("electricity_meter_id")}
        transformed_contract_list.append(temp_contract)

    # 2. make request on Messstellenbetreiber for data of each contract => How to implement? Do we load a contract.html in the dashboard.html or can we add it here in the return?
    
    #render_template with contract objects for each contract
    return render_template('dashboard.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated, username=g.user.get_attribute('username'), contract_list=transformed_contract_list)
    
# === User Info Page ===
@app.route('/user_info', methods=['GET'])
@jwt_required()
def user_info():
    '''
    This function handles the user info page of the web application.

    The JWT Token is required and the 2fa is checked. Then the user info page is displayed accordingly.
    '''

    # Show user only security questions, that are not answered yet
    security_questions_show = list()
    security_questions_show.append("Please select a security question...")

    security_questions_user = g.user.get_security_questions().keys()
    for question in security_questions:
        if question not in security_questions_user:
            security_questions_show.append(question)

    # Render the user_info.html template with user data
    return render_template('user_info.html', 
                            jwt_authenticated=g.jwt_authenticated, 
                            username=g.user.get_attribute("username"), 
                            email=g.user.get_attribute('email'),
                            twofa_activated=g.twofa_activated, 
                            twofa_authenticated=g.twofa_authenticated,
                            contract_list=g.user.get_contract_list(),
                            security_questions=security_questions_show,
                            security_questions_user=security_questions_user)


# ===== Before Request =====
@app.before_request
@jwt_required(optional=True)
def before_request_main():
    '''
    This function is executed before each request.

    It logs the request method and the request path. It also checks wether the user has a valid JWT and 2fa authentication and stores the result in the g object.
    '''
    try: # last resort error handling

        g.jwt_authenticated = False
        g.twofa_activated = False
        g.twofa_authenticated = False
        g.user = None

        # Check if user has a valid JWT
        if get_jwt_identity():
            logger.debug("User has a valid JWT")
            g.jwt_authenticated = True
            g.user = load_user(db=db, user_id=get_jwt_identity())

            twofa_activated = g.user.get_attribute('twofa_activated')

            # Check if user has 2fa activated
            if twofa_activated == "True":
                logger.debug("User has 2fa activated")
                g.twofa_activated = True
                
                # Check if user is 2fa authenticated
                
                # Get the current time and the timestamp of when the user authenticated with 2fa
                date_now = datetime.strptime(str(datetime.now())[:19], '%Y-%m-%d %H:%M:%S')
                date_2fa = datetime.strptime(get_jwt()["2fa_timestamp"], '%a, %d %b %Y %H:%M:%S %Z')

                # Check if the 2fa timestamp is older than time specified in environment variable
                if (date_now - date_2fa) <= timedelta(minutes=int(os.getenv("2FA_EXPIRATION_MINUTES"))):
                    logger.debug("User is 2fa authenticated")
                    g.twofa_authenticated = True
            
    except Exception as e:
        logger.error(f"Error in before_request: {e}")
