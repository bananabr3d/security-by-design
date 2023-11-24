# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the auth routes of the web application.

# ===== Packages =====
# Package for environment variables
import os

# Packages for Flask
from flask import request, render_template, redirect, url_for, flash, make_response, g
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required, set_access_cookies, unset_jwt_cookies, get_jwt)

# Import app, logger, db, bcrypt object, jwt object, exceptions and models from app package
from app import app, logger, db, bcrypt, jwt, Invalid2FA, ValidJWT, security_questions

# Import models
from app.models.user import User, load_user

# Import datetime for cookie expiration handling
from datetime import datetime, timedelta, timezone

# Import regex for input validation
import re

# Import requests and hashlib for pwnedpasswords API
from requests import get
from hashlib import sha1


# Regex for input validation
regex_email = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
regex_username = re.compile(r'^[a-zA-Z0-9]+([_ -]?[a-zA-Z0-9])*$')
# regex password with at least 1 uppercase, 1 lowercase, 1 number and 1 special character
regex_password = re.compile(r'^.*(?=.{12,128})(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%&?"]).*$')
regex_text = re.compile(r'^[a-zA-Z0-9\s]+$')

# JWT Access Token Refresh Expiration
jwt_token_refresh_expiration = int(int(os.getenv("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES"))/2)

# ===== Help Functions =====

def validate_email(email: str) -> bool:
    '''
    This function validates the email input with a regex.

    email: str

    Returns True if the email is valid, else False.
    '''
    if re.fullmatch(regex_email, email):
        return True
    else:
        logger.warning("User provided a invalid email input")
        flash('Invalid input on "E-Mail"', 'failed')
        return False

def validate_username(username: str) -> bool:
    '''
    This function validates the username input with a regex.

    username: str

    Returns True if the username is valid, else False.
    '''
    if re.fullmatch(regex_username, username):
        return True
    else:
        logger.warning("User provided a invalid username input")
        flash('Invalid input on "Username"', 'failed')
        return False

def validate_password(password: str) -> bool:
    '''
    This function validates the password input with a regex.

    password: str

    Returns True if the password is valid, else False.
    '''
    if re.fullmatch(regex_password, password):
        return True
    else:
        logger.warning("User provided a invalid password input")
        flash('Invalid input on "Password"', 'failed')
        return False

def validate_text(text: str) -> bool:
    '''
    This function validates the text input with a regex.

    text: str

    Returns True if the text is valid, else False.
    '''
    if re.fullmatch(regex_text, text):
        return True
    else:
        logger.warning("User provided a invalid text input")
        flash('Invalid input', 'failed')
        return False

def check_password_breach(password: str) -> bool:
    '''
    This function checks if the password hash is breached. It calls the pwnedpasswords API with the first 5 characters of the password hash.

    password: str

    Returns True if the password is breached, else False.
    '''
    # Hash the password with SHA1
    password_hash = sha1(password.encode('utf-8')).hexdigest()

    # Get the first 5 characters of the password hash in hex format
    password_hash_first_5 = password_hash[:5]

    # Call the pwnedpasswords API
    respond = get(f"https://api.pwnedpasswords.com/range/{password_hash_first_5}")

    # Check if the password hash is breached
    if password_hash[5:].upper() in respond.text:
        logger.warning("User provided a breached password")
        flash('Your provided password is breached, choose another password.', 'failed')
        return True
    else:
        return False

# ===== Routes =====

# === Register ===
@app.route('/register', methods=['GET'])
@jwt_required(optional=True)
def register():
    '''
    This function handles the GET register route.

    Raise ValidJWT if the user is already authenticated.

    Returns the register.html template.
    '''

    if g.jwt_authenticated == True:
        raise ValidJWT
    
    return render_template('register.html')

@app.route('/register', methods=['POST'])
@jwt_required(optional=True)
def register_post():
    '''
    This function handles the POST register route.

    Raise ValidJWT if the user is already authenticated.

    Returns redirect to login if the registration was successful. (+ Creates a new user in the database)
    '''

    if g.jwt_authenticated == True:
        raise ValidJWT

    # = Input Validation =
    # Email address and password

    if not validate_email(request.form['email']) or not validate_username(request.form['username']) or check_password_breach(request.form['password']):
        return redirect(url_for("register"))
    
    # set email in lowercase and username in original case           
    email = request.form['email'].lower()
    username = request.form['username']


    # Check if Email already exists
    if User.find_by_email(db=db, email=email) != None:
        logger.warning("E-Mail already exists")
        flash('E-Mail already exists', 'failed')
        return redirect(url_for("register"))

    # Check if User already exists
    if User.find_by_username(db=db, username=username) != None:
        logger.warning("User already exists")
        flash('Username already exists', 'failed')
        return redirect(url_for("register"))
    
    password = request.form['password'] 

    # hash pw, set user as object and save user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(db=db, email=email, username=username, password=hashed_password)
    user.save(db=db)

    flash('Your account has been created!', 'success')
    logger.debug("User Account has been created successfully")
    return redirect(url_for('login'))

# === Login ===
@app.route('/login', methods=['GET'])
@jwt_required(optional=True)
def login():
    '''
    This function handles the GET login route.

    Raise ValidJWT if the user is already authenticated.

    Returns the login.html template.
    '''

    if g.jwt_authenticated == True:
        raise ValidJWT

    return render_template('login.html')


@app.route('/login', methods=['POST'])
@jwt_required(optional=True)
def login_post():
    '''
    This function handles the POST login route.

    Raise ValidJWT if the user is already authenticated.

    Returns redirect to login_2fa if the login was successful. (+ Creates a new JWT and sets the JWT access cookies)
    '''

    if g.jwt_authenticated == True:
        raise ValidJWT

    # = Input Validation =
    # Username and password

    if not validate_username(request.form['username']) or not validate_password(request.form['password']):
        return redirect(url_for("login"))

    # set username and password in original case
    username = request.form['username']
    password = request.form['password']

    # load user from db
    user = User.find_by_username(db = db, username = username)

    # check if user exists and if password is correct
    if user != None: # if user found
        password_hash = user.get_attribute('password')

        if bcrypt.check_password_hash(password_hash, password) == False: # if the password is wrong
            logger.warning("Wrong username/password combination provided")
            logger.debug("User: '" + username + "' provided a wrong password during the login")
            flash('Wrong username or password', 'failed')
            return redirect(url_for("login"))
        
    else:
        logger.warning("Username could not be found")
        logger.debug(f"User: '{username}' could not be found during the login")
        flash('Wrong username or password', 'failed')
        return redirect(url_for("login"))
    
    # create access token
    access_token = create_access_token(identity=user.get_id(), fresh=timedelta(minutes=jwt_token_refresh_expiration))

    flash('You have been logged in successfully!', 'success')
    logger.debug("User Account has logged in successfully")

    # Set the JWT access cookies in the response and redirect user to login_2fa
    resp = make_response(redirect(url_for('login_2fa')))
    set_access_cookies(response=resp, encoded_access_token=access_token)
    return resp


# === Logout ===
@app.route('/logout', methods=['GET'])
@jwt_required()
def logout():
    '''
    This function handles the logout route and can only be accessed with a JWT Token.

    Returns redirect to login and unsets the JWT access cookies
    '''
    # redirect user to login and unset jwt cookies
    flash('You have been logged out successfully!', 'success')
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(resp)
    return resp


# === Reset password ===
@app.route('/reset-password', methods=['GET'])
@jwt_required(optional=True)
def reset_password():
    '''
    This function handles the GET reset_password route.

    Returns the reset_password.html template.
    '''

    security_questions_show = list()
    security_questions_show.append("Please select a security question...")
    security_questions_show += security_questions

    return render_template('reset_password.html', security_questions=security_questions_show)


@app.route('/reset-password', methods=['POST'])
@jwt_required(optional=True)
def reset_password_post():
    '''
    This function handles the POST reset_password route.

    Returns redirect to login if the reset password was successful. (+ Updates the user password in the database)
    '''

    # = Input Validation =
    # Email address
    if not validate_email(request.form['email']):
        return redirect(url_for('reset_password'))

    # Security Question
    # Check if value is in security_questions
    if not request.form['security_question'] in security_questions:
        logger.warning("User provided a invalid security question input")
        flash('Invalid input on "Security Question"', 'failed')
        return redirect(url_for('reset_password'))
    
    # Answer
    if not validate_text(request.form['answer']):
        logger.warning("User provided a invalid answer input")
        return redirect(url_for('reset_password'))
    
    # New Password
    if not validate_password(request.form['new_password']) or check_password_breach(request.form['new_password']):
        logger.warning("User provided a invalid new password input")
        return redirect(url_for('reset_password'))
    
    
    # Check if email exists
    g.user = User.find_by_email(db=db, email=request.form['email'])
    if g.user == None:
        logger.warning("Email could not be found")
        logger.debug(f"User: '{request.form['email']}' could not be found during the reset password")
        flash('Email could not be found', 'failed')
        return redirect(url_for('reset_password'))
    
    # Check if security question is answered
    if request.form['security_question'] not in g.user.get_attribute('security_questions'):
        logger.warning("User provided a security question that is not answered")
        flash('Your Answer is incorrect', 'failed') # That you cant differ between wrong answer and not answered is a feature, not a bug
        return redirect(url_for('reset_password'))

    # Check if answer is correct for the selected security question
    hashed_answer = g.user.get_security_questions()[request.form['security_question']]

    if bcrypt.check_password_hash(hashed_answer, request.form['answer']) == False:
        flash('Your answer is incorrect', 'failed')
        logger.debug(f"User: '{g.user.get_attribute('username')}' provided a wrong answer to the security question during the reset password")
        return redirect(url_for('reset_password'))

    # Set new password
    hashed_password = bcrypt.generate_password_hash(request.form['new_password']).decode('utf-8')
    g.user.update_attribute(db, attribute="password", value=hashed_password)

    flash('Your password has been changed!', 'success')
    logger.debug(f"User: '{g.user.get_attribute('username')}' has successfully changed its password")
    return redirect(url_for('login'))


# === Add security question ===
@app.route('/add-security-question', methods=['POST'])
@jwt_required()
def add_security_question():
    '''
    This function handles the add_security_question route and can only be accessed with a JWT Token.

    Returns redirect to dashboard if the security question was successfully added. (+ Updates the user security questions in the database)
    '''

    # = Input Validation =
    # Security Question
    # Check if value is between 1 and 5
    if not request.form['security_question'] in security_questions:
        logger.warning("User provided a invalid security question input")
        flash('Invalid input on "Security Question"', 'failed')
        return redirect(url_for('user_info'))
    
    # Answer
    if not validate_text(request.form['answer']):
        logger.warning("User provided a invalid answer input")
        return redirect(url_for('user_info'))
    
    # Check if security question is already answered
    if request.form['security_question'] in g.user.get_attribute('security_questions'):
        logger.warning("User provided a security question that is already answered")
        flash('You already answered this security question', 'failed')
        return redirect(url_for('user_info'))
    
    # Add hash of answer to user security questions
    hashed_answer = bcrypt.generate_password_hash(request.form['answer']).decode('utf-8')
    g.user.add_security_question(db=db, question=request.form['security_question'], answer=hashed_answer)

    flash('Your security question has been added!', 'success')
    logger.debug(f"User: '{g.user.get_attribute('username')}' has successfully added a security question")
    return redirect(url_for('user_info'))


# === Set new password ===      
@app.route('/set-new-password', methods=['POST'])
@jwt_required()
def set_new_password():
    '''
    This function handles the set_new_password route and can only be accessed with a JWT Token.

    Raise Invalid2FA if the user is not 2fa authenticated.

    Returns redirect to dashboard and message if new password couldnt be set.

    Returns redirect to login, unset JWT and flash message if new password was successfully set. (+ Updates the user password in the database)
    '''
    
    # = Input Validation =
    # Password
    if not validate_password(request.form['old_password']) or not validate_password(request.form['new_password']) or check_password_breach(request.form['new_password']):
        flash('Invalid input', 'failed')
        return redirect(url_for('user_info'))
        
    # Check if current password is correct
    if bcrypt.check_password_hash(g.user.get_attribute('password'), request.form['old_password']) == False:
        flash('Current password is incorrect', 'failed')
        logger.debug(f"User: '{g.user.get_attribute('username')}' provided a wrong old password during the set new password")
        return redirect(url_for('user_info'))

    # Set new password
    hashed_password = bcrypt.generate_password_hash(request.form['new_password']).decode('utf-8')
    g.user.update_attribute(db, attribute="password", value=hashed_password)

    flash('Your password has been changed!', 'success')
    logger.debug(f"User: '{g.user.get_attribute('username')}' has successfully changed its password")

    # Unset JWT and redirect to login
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(resp)
    return resp


# === Delete User ===
@app.route('/delete-user', methods=['POST'])
@jwt_required(fresh=True)
def delete_user():
    '''
    This function handles the delete_user route and can only be accessed with a fresh JWT Token.

    Raise Invalid2FA if the user is not 2fa authenticated.

    Returns redirect to dashboard and message if user couldnt be deleted.

    Returns redirect to login, unset JWT and flash message if user was successfully deleted. (+ Deletes the user in the database)
    '''

    # Check if user has 2fa activated, then 2fa authenticated is needed
    if g.twofa_activated and not g.twofa_authenticated:
        logger.warning(f"User: '{g.user.get_attribute('username')}' has 2fa activated, but is not 2fa authenticated")
        flash('You have 2fa activated, you need to authenticate with 2fa to delete your account', 'failed')
        raise Invalid2FA
    
    # Delete user
    g.user.delete(db=db)

    # Check if user is deleted
    if load_user(db=db, user_id=g.user.get_id()) != None:
        logger.warning(f"User: '{g.user.get_attribute('username')}' could not be deleted")
        flash('User could not be deleted', 'failed')
        return redirect(url_for('dashboard'))
    
    logger.debug(f"User: '{g.user.get_attribute('username')}' has successfully deleted its account")

    # Unset JWT and redirect to login
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(resp)
    flash('Your account has been deleted!', 'success')
    return resp

# === Export user account information ===
@app.route('/export-user', methods=['GET'])
@jwt_required(fresh=True)
def export_user():
    '''
    This function handles the export_user route and can only be accessed with a fresh JWT Token.

    Raise Invalid2FA if the user is not 2fa authenticated.

    Returns the export_user.html template.
    '''

    # Check if user has 2fa activated, then 2fa authenticated is needed
    if g.twofa_activated and not g.twofa_authenticated:
        logger.warning(f"User: '{g.user.get_attribute('username')}' has 2fa activated, but is not 2fa authenticated")
        flash('You have 2fa activated, you need to authenticate with 2fa to export your account information', 'failed')
        raise Invalid2FA
    
    # get user data from user object
    user_data = g.user.get_all_key_values()

    # render export_user.html with user_data
    #return render_template('export_user.html', user_data=user_data)

    # return response with json formatted user_data
    return user_data


# ===== Before Request =====
@app.before_request
@jwt_required(optional=True)
def before_request_auth():
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
                
                if "2fa_timestamp" in get_jwt():
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


# === Refresh JWT ===
@app.after_request
def refresh_expiring_jwts(response):
    '''
    This function is called after every request and is used to refresh the JWT access token.

    This function refreshes the JWT access token if the JWT is expiring in less than half of the JWT_ACCESS_TOKEN_EXPIRATION_MINUTES time.
    '''
    try:
        # Get the timestamp of the current JWT
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
                
        # Check if the JWT is expiring in less than half of the JWT_ACCESS_TOKEN_EXPIRATION_MINUTES time
        target_timestamp = datetime.timestamp(now + timedelta(minutes=int(int(os.getenv("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES")) / 2)))
        if (target_timestamp > exp_timestamp):
            # Check if user is 2fa authenticated
            try:
                if g.twofa_authenticated:
                    logger.debug("User has a unfresh token and is 2fa authenticated")

                    # Refresh the JWT with 2fa timestamp
                    access_token = create_access_token(identity=get_jwt_identity(), fresh=False, additional_claims={'2fa_timestamp': get_jwt()["2fa_timestamp"]})
                    set_access_cookies(response=response, encoded_access_token=access_token)
                
                else: # If user is not 2fa authenticated, refresh the JWT without 2fa timestamp
                    logger.debug("User has a unfresh token and is not 2fa authenticated")

                    # Refresh the JWT without 2fa timestamp
                    access_token = create_access_token(identity=get_jwt_identity(), fresh=False)
                    set_access_cookies(response=response, encoded_access_token=access_token)

            except Exception as e:
                logger.error(f"Error: e")
                flash("Internal Server Error, redirect to home", "error")
                return redirect(url_for('home')), 500
                
        return response
    
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response


# === Error handling ===

# Error handler for InvalidSignatureError (when a JWT was provided from the same endpoint but other secret (e.g. CP <-> MPO))
@jwt.invalid_token_loader
def invalid_token_callback(error):
    '''
    This function handles the invalid_token_callback.

    This function redirects the user to the login page and flashes a error message.
    '''
    resp = make_response(redirect(url_for('login')))
    flash('Invalid token, please log in again', 'error')
    logger.debug("User has a invalid token")
    unset_jwt_cookies(response=resp)
    return resp

# Error handler for expired JWT
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    '''
    This function handles the expired_token_callback.

    This function redirects the user to the login page and flashes a error message.
    '''
    resp = make_response(redirect(url_for('login')))
    flash('Your session token has expired, please log in again', 'error')
    logger.debug("User has a expired token")
    unset_jwt_cookies(response=resp)
    return resp

# Error handler for invalid JWT
@jwt.unauthorized_loader #TODO
def custom_unauthorized_response(callback):
    '''
    This function handles the custom_unauthorized_response.

    This function renders the Unauthorized.html template and flashes a error message.
    '''
    #TODO Customize the error response -> render Unauthorized.html -> button available to redirect to login
    flash("You are not authorized to do this.")
    return redirect(url_for('login'))

# Error handler for fresh JWT needed
@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
    '''
    This function handles the token_not_fresh_callback, so the user needs a fresh access token to to this action.

    This function redirects the user to the login page in order to log in again and flashes a error message.
    '''
    flash('You need a fresh token. You have to log in again in order to do this', 'error')
    logger.debug("User has a unfresh token, but needs a fresh one")
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response=resp)
    return resp