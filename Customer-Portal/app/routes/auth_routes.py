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
from app import app, logger, db, bcrypt, jwt, Inactive2FA, Invalid2FA, Active2FA, Valid2FA, ValidJWT

# Import models
from app.models.user import User, load_user

# Import pyotp for 2fa and io, qrcode, base64 for QR code generation
import pyotp, io, qrcode, random
from base64 import b64encode

# Import datetime for cookie expiration handling
from datetime import datetime, timedelta, timezone

# Import regex for input validation
import re

# Regex for input validation
regex_email = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
regex_username = re.compile(r'^[a-zA-Z0-9]+([_ -]?[a-zA-Z0-9])*$')
regex_password = re.compile(r'^.*(?=.{12,128})(?=.*[a-zA-Z])(?=.*\d)(?=.*[!#$%&?"]).*$')
regex_6digits = re.compile(r'^[0-9]{6}$')

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
    
def validate_6digits(text: str) -> bool:
    '''
    This function validates the 6 digit input with a regex.

    text: str

    Returns True if the text is valid, else False.    
    '''
    if re.fullmatch(regex_6digits, text):
        return True
    else:
        logger.warning("User provided a invalid 6 digit input")
        return False


# Verify 2fa
def verify2fa(user: User, otp: str) -> bool:
    '''
    This function verifies the otp with the user secret.

    user: User

    otp: str

    Returns True if the otp is valid, else False.
    '''
    secret = user.get_attribute('twofa_secret')

    if secret == None:
        flash('You have no 2-Factor-Authentification activated!',  'failed')
        return False
    else:
        totp = pyotp.TOTP(secret)

        if totp.verify(otp):
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

    if not validate_email(request.form['email']) or not validate_username(request.form['username']) or not validate_password(request.form['password']) or not validate_password(request.form['password2']):
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
    

    # Compare passwords
    password = request.form['password']
    password2 = request.form['password2']

    if password != password2:
        logger.warning("Different passwords provided during the registration")
        logger.debug("User: " + username + "provided different passwords during the registration")
        flash('Passwords dont match', 'failed')
        return redirect(url_for("register"))
    

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
        logger.debug("User: '" + username + "' could not be found during the login")
        flash('Wrong username or password', 'failed')
        redirect(url_for("login"))
    
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

# === Register 2FA ===
@app.route('/register/2fa', methods=['GET'])
@jwt_required()
def register_2fa():
    '''
    This function handles the GET register_2fa route and can only be accessed with a JWT Token.

    Raise Active2FA if the user has already 2fa activated.

    Raise Valid2FA if the user is already 2fa authenticated.

    Returns the register_2fa.html template. (+ Sets the user attribute twofa_secret)
    '''
    # Check if the user has already 2fa activated
    if g.twofa_activated:
        raise Active2FA

    # Check if the user is already 2fa authenticated
    elif g.twofa_authenticated:
        raise Valid2FA


    # Generate a random secret and update the user attribute
    secret = pyotp.random_base32()
    g.user.update_attribute(db, attribute="twofa_secret", value=secret)

    # Generate the OTP URI for the QR code
    otp_uri = pyotp.TOTP(secret).provisioning_uri(g.user.get_attribute("username"), issuer_name="VoltWave")

    # Generate a QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(otp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Save the image to a BytesIO object
    img_bytes_io = io.BytesIO()
    img.save(img_bytes_io, 'PNG')
    img_bytes_io.seek(0)

    # Encode the image as a base64 data URI
    img_qrcode_data = b64encode(img_bytes_io.read()).decode()

    return render_template('register_2fa.html', secret=secret, img_qrcode_data=img_qrcode_data, jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated)

@app.route('/register/2fa', methods=['POST'])
@jwt_required()
def register_2fa_post():
    '''
    This function handles the POST register_2fa route and can only be accessed with a JWT Token.

    Raise Active2FA if the user has already 2fa activated.

    Raise Valid2FA if the user is already 2fa authenticated.

    Returns redirect to login_2fa if the 2fa verification was successful. (+ Sets the user attribute twofa_activated to True)
    '''
    # Check if the user has already 2fa activated
    if g.twofa_activated:
        raise Active2FA

    # Check if the user is already 2fa authenticated
    elif g.twofa_authenticated:
        raise Valid2FA
    

    # Validate otp format
    if not validate_6digits(text=request.form['otp']):
        flash("The OTP code has a invalid format. The OTP code has to contain 6 digits.")
        return redirect(url_for('register_2fa'))

    # Verify otp
    if verify2fa(user=g.user, otp=request.form['otp']):
        # Set user attribute 2fa activated to True, flash success message and redirect to login_2fa
        g.user.update_attribute(db, "twofa_activated", True)
        flash('2FA Verification Successful', 'success')
        logger.debug("User: '" + g.user.get_attribute("username") + "' has successfully verified its 2fa")

        # Generate 2fa backup codes 10 * (random 6 digit numbers)
        backup_codes = list()
        for i in range(10):
            backup_codes.append(random.randint(100000, 999999)) # "000000" is explicitly excluded

        flash('Your backup codes are: ' + str(backup_codes), 'backup-codes')
        
        # Update user backup codes -> save the hashes of the backup_codes
        backup_codes = [bcrypt.generate_password_hash(str(code)).decode('utf-8') for code in backup_codes]
        g.user.update_attribute(db, "backup_codes", backup_codes)
        
        return redirect(url_for('login_2fa'))
    
    else: # If otp is not valid, flash error message and redirect to register_2fa
        flash('User 2FA could not be verified', 'failed')
        logger.debug("User: '" + g.user.get_attribute("username") + "' failed to verify its 2fa")
        return redirect(url_for('register_2fa'))
    

# === Login 2FA ===      
@app.route('/login/2fa', methods=['GET'])
@jwt_required()
def login_2fa():
    '''
    This function handles the GET login_2fa route and can only be accessed with a JWT Token.

    Raise Inactive2FA if the user has not already 2fa activated.

    Raise Valid2FA if the user is already 2fa authenticated.

    Returns the login_2fa.html template.
    '''
    # Check if the user has 2fa activated
    if not g.twofa_activated:
        raise Inactive2FA
    
    # Check if the user 2fa is already authenticated
    if g.twofa_authenticated:
        raise Valid2FA


    return render_template('login_2fa.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated)
    
@app.route('/login/2fa', methods=['POST'])
@jwt_required()
def login_2fa_post():
    '''
    This function handles the POST login_2fa route and can only be accessed with a JWT Token.

    Raise Inactive2FA if the user has not already 2fa activated.

    Raise Valid2FA if the user is already 2fa authenticated.

    Returns redirect to dashboard if the 2fa authentication was successful. (+ Creates a new JWT and sets the JWT access cookies)
    '''
    # Check if the user has 2fa activated
    if not g.twofa_activated:
        raise Inactive2FA
    
    # Check if the user 2fa is already authenticated
    if g.twofa_authenticated:
        raise Valid2FA


    # Validate otp
    # Validate otp format
    if not validate_6digits(text=request.form['otp']):
        flash("The OTP code has a invalid format. The OTP code has to contain 6 digits.")
        return redirect(url_for('login_2fa'))
    
    # Set otp from form
    otp = request.form['otp']

    # Verify otp
    if verify2fa(user=g.user, otp=otp):
        # Flash success message, log user in and redirect to dashboard
        flash('2FA Authentication Successful', 'success')
        logger.debug("User: '" + g.user.get_attribute("username") + "' has successfully authenticated with 2fa")

        resp = make_response(redirect(url_for('dashboard')))
        access_token = create_access_token(identity=g.user.get_id(), fresh=timedelta(minutes=jwt_token_refresh_expiration), additional_claims={'2fa_timestamp': datetime.now()})
        set_access_cookies(response=resp, encoded_access_token=access_token)

        return resp
    
    else: # If otp is not valid, flash error message and redirect to login_2fa
        flash('User 2FA could not be authenticated', 'failed')
        logger.debug("User: '" + g.user.get_attribute("username") + "' failed to authenticate with 2fa")
        return redirect(url_for('login_2fa'))


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

    # Check if user is 2FA authenticated
    if not g.twofa_authenticated:
        raise Invalid2FA
    
    # = Input Validation =
    # Password
    if not validate_password(request.form['old_password']) or not validate_password(request.form['new_password']) or not validate_password(request.form['new_password2']):
        return redirect(url_for('dashboard'))

    # Compare new passwords
    if request.form['new_password'] != request.form['new_password2']:
        flash('New passwords dont match', 'failed')
        return redirect(url_for('dashboard'))
        
    # Check if current password is correct
    if bcrypt.check_password_hash(g.user.get_attribute('password'), request.form['old_password']) == False:
        flash('Current password is incorrect', 'failed')
        logger.debug("User: '" + g.user.get_attribute("username") + "' provided a wrong old password during the set new password")
        return redirect(url_for('dashboard'))

    # Set new password
    hashed_password = bcrypt.generate_password_hash(request.form['new_password']).decode('utf-8')
    g.user.update_attribute(db, attribute="password", value=hashed_password)

    flash('Your password has been changed!', 'success')
    logger.debug("User: '" + g.user.get_attribute("username") + "' has successfully changed its password")

    # Unset JWT and redirect to login
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(resp)
    return resp

# === Reset 2FA ===     
@app.route('/reset-2fa', methods=['POST'])
@jwt_required()
def reset_2fa():
    '''
    This function handles the reset_2fa route and can only be accessed with a JWT Token.

    Returns to dashboard and message if 2fa couldnt be reset. (Either because of the format or that it is not correct)

    Returns redirect to login if 2fa was successfully reseted. (+ Updates the user 2fa secret + activated status in the database)
    '''
    
    # = Input Validation =
    # Backup Code
    if not validate_6digits(request.form['backup_code']):
        flash("Invalid Backup Code", "error") # Dont send another flash message as if the backup code itself is invalid. So the attacker doesnt know if it has the wrong format or is invalid itself.
        return redirect(url_for('dashboard'))

    # Check if user has backup codes
    backup_codes = g.user.get_backup_codes()
    if backup_codes == None:
        flash("Invalid Backup Code", "error")
        return redirect(url_for('dashboard'))
    
    # Check if backup code is correct
    for backup_code in backup_codes:
        print(backup_code)
        print(request.form['backup_code'])
        print(type(backup_code))
        print(type(request.form['backup_code']))
        if bcrypt.check_password_hash(backup_code, request.form['backup_code']):
            # Update user 2fa secret
            g.user.update_attribute(db, attribute="twofa_secret", value=None)
            # Update user 2fa activated
            g.user.update_attribute(db, attribute="twofa_activated", value=False)
    
            # Unset JWT and redirect to login
            resp = make_response(redirect(url_for('login')))
            flash("Your 2 FA has been reset successfully", "success")
            unset_jwt_cookies(resp)
            return resp
        
    # Send flash message if backup code is not correct
    flash("Invalid Backup Code", "error")
    return redirect(url_for('dashboard'))



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
                logger.error("Error: " + str(e))
                flash("Internal Server Error, redirect to home", "error")
                return redirect(url_for('home')), 500
                
        return response
    
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response


# === Error handling ===

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
@jwt.needs_fresh_token_loader #TODO
def token_not_fresh_callback(jwt_header, jwt_payload):
    '''
    This function handles the token_not_fresh_callback, so the user needs a fresh access token to to this action.

    This function redirects the user to the login page in order to log in again and flashes a error message.
    '''
    flash('You have to log in again in order to do this', 'error')
    logger.debug("User has a unfresh token, but needs a fresh one")
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response=resp)
    return resp