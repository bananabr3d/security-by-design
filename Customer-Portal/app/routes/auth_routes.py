# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the auth routes of the web application.
# Last update: 25.10.2023

# ===== Packages =====
# Package for environment variables
import os

# Packages for Flask
from flask import request, render_template, redirect, url_for, flash, make_response, Response
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required, set_access_cookies, unset_jwt_cookies, get_jwt)

# Import app, logger, db, bcrypt object, jwt object and UnknownRequest Exception from app package
from app import app, logger, db, bcrypt, jwt, UnknownRequest

# Import models
from app.models.user import User, load_user

# Import pyotp for 2fa and io, qrcode, base64 for QR code generation
import pyotp
import io
import qrcode
from base64 import b64encode

# Import datetime for cookie expiration handling
from datetime import datetime, timedelta, timezone

# Import regex for input validation
import re

# Regex for input validation
regex_email = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
regex_username = re.compile(r'^[a-zA-Z0-9]+([_ -]?[a-zA-Z0-9])*$')
regex_password = re.compile(r'^.*(?=.{12,128})(?=.*[a-zA-Z])(?=.*\d)(?=.*[!#$%&?"]).*$')
regex_otp = re.compile(r'^[0-9]{6}$')

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
    
def validate_otp(otp: str) -> bool:
    '''
    This function validates the otp input with a regex.

    otp: str

    Returns True if the otp is valid, else False.    
    '''
    if re.fullmatch(regex_otp, otp):
        return True
    else:
        logger.warning("User provided a invalid otp input")
        flash('Invalid input on "OTP"', 'failed')
        return False


def check_2fa_activated(twofa_activated: str) -> bool:
    '''
    This function checks if the user has 2fa activated.

    twofa_activated: str

    Returns True if the user has 2fa activated, else False.
    '''
    try:
        if twofa_activated == "True":
            return True
        else:
            return False
    except:
        return False

def check_2fa(twofa_activated: str, jwt_token: dict) -> None or Response:
    '''
    This function checks if the user has 2fa activated and if the 2fa timestamp is not older than the time specified in the environment variable.

    twofa_activated: str

    jwt_token: dict

    Returns None if the user is 2fa authenticated, 

    else return a Response redirect to register_2fa if the user has no 2fa activated

    or return a Response redirect to login_2fa if the 2fa timestamp is older than the time specified in the environment variable.
    '''
    try: # check if 2fa is activated
        if twofa_activated != "True":
            resp = make_response(redirect(url_for('register_2fa')))
            flash("You have no 2FA activated", "error")
            return resp
    except:
        resp = make_response(redirect(url_for('register_2fa')))
        flash("You have no 2FA activated", "error")
        return resp	

    try: # check 2fa timestamp
        timestamp = jwt_token["2fa_timestamp"]

        # Get the current time and the timestamp of when the user authenticated with 2fa
        date_now = datetime.strptime(str(datetime.now())[:19], '%Y-%m-%d %H:%M:%S')
        date_2fa = datetime.strptime(timestamp, '%a, %d %b %Y %H:%M:%S %Z')

        # Check if the 2fa timestamp is older than time specified in environment variable
        if (date_now - date_2fa) > timedelta(minutes=int(os.getenv("2FA_EXPIRATION_MINUTES"))):
            resp = make_response(redirect(url_for('login_2fa')))
            flash("You are either not 2FA authenticated or your token expired", "error")
            return resp
    except:
        resp = make_response(redirect(url_for('login_2fa')))
        flash("You are either not 2FA authenticated or your token expired", "error")
        return resp  
     
    return None

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
@app.route('/register', methods=['GET', 'POST'])
@jwt_required(optional=True)
def register():
    '''
    This function handles the register route.

    Returns redirect to dashboard if user is logged in (JWT is present).

    Returns the register.html template if the request method is GET and the user is not logged in (JWT is not present).

    Returns redirect to login if the request method is POST and the user is not logged in (JWT is not present) and the registration was successful. (+ Creates a new user in the database)
    '''
    logger.info(str(request.method) + "-Request on " + request.path)

    try: # last resort error handling

        # Check if request method is POST and user is not logged in (JWT is not present)
        if request.method == 'POST' and get_jwt_identity() == None:

            # = Input Validation =
            # Email address and password

            if not validate_email(request.form['email']) or not validate_username(request.form['username']) or not validate_password(request.form['password']) or not validate_password(request.form['password2']):
                return render_template('register.html')
            
            # set email in lowercase and username in original case           
            email = request.form['email'].lower()
            username = request.form['username']


            # Check if Email already exists
            if User.find_by_email(db=db, email=email) != None:
                logger.warning("E-Mail already exists")
                flash('E-Mail already exists', 'failed')
                # Add JSON Response for APIs? make_response(render_template('register.html'))?
                return render_template('register.html')

            # Check if User already exists
            if User.find_by_username(db=db, username=username) != None:
                logger.warning("User already exists")
                flash('Username already exists', 'failed')
                # Add JSON Response for APIs? make_response(render_template('register.html'))?
                return render_template('register.html')
            

            # Compare passwords
            password = request.form['password']
            password2 = request.form['password2']

            if password != password2:
                logger.warning("Different passwords provided during the registration")
                logger.debug("User: " + username + "provided different passwords during the registration")
                flash('Passwords dont match', 'failed')
                # Add JSON Response for APIs?
                return render_template('register.html')
            

            # hash pw, set user as object and save user
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(db=db, email=email, username=username, password=hashed_password)
            user.save(db=db)

            flash('Your account has been created!', 'success')
            logger.debug("User Account has been created successfully")
            #TODO Add JSON Response for APIs?
            return redirect(url_for('login'))
        
        # Check if request method is GET and user is not logged in (JWT is not present)
        elif request.method =='GET' and get_jwt_identity() == None:       
            return render_template('register.html')
        
        # Check if user is logged in (JWT is present)
        elif get_jwt_identity() != None:
            flash('You are already logged in!', 'success')
            return redirect(url_for('dashboard'))

        # Raise UnknownRequest Exception if request is unexpected
        else:
            logger.warning("Unknown Request on ", request.path)
            raise UnknownRequest 
               
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500

# === Login ===
@app.route('/login', methods=['GET', 'POST']) # Add more details to user
@jwt_required(optional=True)
def login():
    '''
    This function handles the login route.

    Returns redirect to dashboard if user is logged in (JWT is present).

    Returns the login.html template if the request method is GET and the user is not logged in (JWT is not present).

    Returns redirect to login_2fa if the request method is POST and the user is not logged in (JWT is not present) and the login was successful. (+ Creates a new JWT and sets the JWT access cookies)
    '''
    logger.info(str(request.method) + "-Request on " + request.path)

    try: # last resort error handling

        # Check if request method is POST and user is not logged in (JWT is not present)
        if request.method == 'POST' and get_jwt_identity() == None:
            
            # = Input Validation =
            # Username and password

            if not validate_username(request.form['username']) or not validate_password(request.form['password']):
                return render_template('login.html')

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
                    #TODO Add JSON Response for APIs?
                    return render_template('login.html')
                
            else:
                logger.warning("Username could not be found")
                logger.debug("User: '" + username + "' could not be found during the login")
                flash('Wrong username or password', 'failed')
                #TODO Add JSON Response for APIs?
                return render_template('login.html')
            
            # create access token
            access_token = create_access_token(identity=user.get_id(), fresh=timedelta(minutes=jwt_token_refresh_expiration))

            flash('You have been logged in successfully!', 'success')
            logger.debug("User Account has logged in successfully")
            # Add JSON Response for APIs?

            # Set the JWT access cookies in the response and redirect user to login_2fa
            resp = make_response(redirect(url_for('login_2fa')))
            set_access_cookies(response=resp, encoded_access_token=access_token)
            return resp
        
        # Check if request method is GET and user is not logged in (JWT is not present)
        elif request.method =='GET' and get_jwt_identity() == None:
            return render_template('login.html')
        
        # Check if user is logged in (JWT is present)
        elif get_jwt_identity() != None:
            flash('You are already logged in!', 'success')
            return redirect(url_for('dashboard'))
        
        # Raise UnknownRequest Exception if request is unexpected
        else:
            logger.warning("Unknown Request on ", request.path)
            raise UnknownRequest 

    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500

# === Logout ===
@app.route('/logout', methods=['GET'])
@jwt_required()
def logout():
    '''
    This function handles the logout route and can only be accessed with a JWT Token.

    Returns redirect to login and unsets the JWT access cookies
    '''
    logger.info(str(request.method) + "-Request on " + request.path)

    try: # last resort error handling

        # redirect user to login and unset jwt cookies
        flash('You have been logged out successfully!', 'success')
        resp = make_response(redirect(url_for('login')))
        unset_jwt_cookies(resp)
        return resp
    
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        resp = make_response(redirect(url_for('home')))
        unset_jwt_cookies(resp)
        return resp, 500

# === Register 2FA ===
@app.route('/register/2fa', methods=['GET', 'POST'])
@jwt_required()
def register_2fa():
    '''
    This function handles the register_2fa route and can only be accessed with a JWT Token.

    Returns redirect to login_2fa if the user has already 2fa activated.

    Returns the register_2fa.html template if the request method is GET and the user has not already 2fa activated.

    Returns redirect to login_2fa if the request method is POST and the user has not already 2fa activated and the 2fa verification was successful. (+ Sets the user attribute 2fa activated to True)
    '''
    logger.info(str(request.method) + "-Request on " + request.path)

    try: # last resort error handling

        # Check if user has a valid JWT, then load user object
        if get_jwt_identity():
            user = load_user(db=db, user_id=get_jwt_identity())

        # Check if the user has already 2fa activated
        if check_2fa_activated(twofa_activated=user.get_attribute('twofa_activated')):
            flash('You already have 2FA activated', 'error')
            return redirect(url_for('login_2fa'))


        # Check Request Method
        if request.method =='GET':

            # Generate a random secret and update the user attribute
            secret = pyotp.random_base32()
            user.update_attribute(db, attribute="twofa_secret", value=secret)

            # Generate the OTP URI for the QR code
            otp_uri = pyotp.TOTP(secret).provisioning_uri(user.get_attribute("username"), issuer_name="VoltWave") #TODO issuer_name

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

            return render_template('register_2fa.html', secret=secret, img_qrcode_data=img_qrcode_data, loggedin=True)
        
        elif request.method =='POST':
            # Validate otp
            if not validate_otp(request.form['otp']):
                return render_template('register_2fa.html', loggedin=True)

            # Set otp from form
            otp = request.form['otp']

            # Verify otp
            if verify2fa(user=user, otp=otp):
                # Set user attribute 2fa activated to True, flash success message and redirect to login_2fa
                user.update_attribute(db, "twofa_activated", True)
                flash('2FA Verification Successful', 'success')
                logger.debug("User: '" + user.get_attribute("username") + "' has successfully verified its 2fa")
                return redirect(url_for('login_2fa'))
            
            else: # If otp is not valid, flash error message and redirect to register_2fa
                flash('User 2FA could not be verified', 'failed')
                logger.debug("User: '" + user.get_attribute("username") + "' failed to verify its 2fa")
                return redirect(url_for('register_2fa'))
            
        # Raise UnknownRequest Exception if request is unexpected
        else:
            logger.warning("Unknown Request on ", request.path)
            raise UnknownRequest
        
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500

# === Login 2FA ===      
@app.route('/login/2fa', methods=['GET', 'POST'])
@jwt_required()
def login_2fa():
    '''
    This function handles the login_2fa route and can only be accessed with a JWT Token.

    Returns redirect to dashboard if the user is already 2fa authenticated.

    Returns redirect to register_2fa if the user has no 2fa activated.

    Returns the login_2fa.html template if the request method is GET and the user is not already 2fa authenticated.

    Returns redirect to dashboard if the request method is POST and the user is not already 2fa authenticated and the 2fa authentication was successful. (+ Creates a new JWT and sets the JWT access cookies)
    '''
    logger.info(str(request.method) + "-Request on " + request.path)

    try: # last resort error handling

        # Check if user has a valid JWT, then load user object
        if get_jwt_identity():
            user = load_user(db=db, user_id=get_jwt_identity())
        
        # Check if the user has 2fa activated
        if not check_2fa_activated(twofa_activated=user.get_attribute('twofa_activated')):
            flash('You have no 2FA activated', 'error')
            return redirect(url_for('register_2fa'))
        
        # Check if the user 2fa is already authenticated
        if check_2fa(twofa_activated=user.get_attribute('twofa_activated'), jwt_token=get_jwt()) == None:
            return redirect(url_for('dashboard'))


        # Check Request Method
        if request.method =='GET':
            return render_template('login_2fa.html', loggedin=True)
        
        elif request.method =='POST':
            # Validate otp
            if not validate_otp(request.form['otp']):
                return render_template('login_2fa.html', loggedin=True)
            
            # Set otp from form
            otp = request.form['otp']

            # Verify otp
            if verify2fa(user=user, otp=otp):
                # Flash success message, log user in and redirect to dashboard
                flash('2FA Authentication Successful', 'success')
                logger.debug("User: '" + user.get_attribute("username") + "' has successfully authenticated with 2fa")

                resp = make_response(redirect(url_for('dashboard')))
                access_token = create_access_token(identity=user.get_id(), fresh=timedelta(minutes=jwt_token_refresh_expiration), additional_claims={'2fa_timestamp': datetime.now()})
                set_access_cookies(response=resp, encoded_access_token=access_token)

                return resp
            
            else: # If otp is not valid, flash error message and redirect to login_2fa
                flash('User 2FA could not be authenticated', 'failed')
                logger.debug("User: '" + user.get_attribute("username") + "' failed to authenticate with 2fa")
                return render_template('login_2fa.html')
        # Raise UnknownRequest Exception if request is unexpected
        else:
            logger.warning("Unknown Request on ", request.path)
            raise UnknownRequest
        
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500


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
                user = load_user(db=db, user_id=get_jwt_identity())

                if check_2fa(twofa_activated=user.get_attribute('twofa_activated'), jwt_token=get_jwt()) == None:
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