from app import app, logger, db, bcrypt, jwt
from app.models.user import User, load_user
from flask import request, render_template, redirect, url_for, flash, make_response
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required, set_access_cookies, unset_jwt_cookies, get_jwt)
from flask_jwt_extended.exceptions import JWTExtendedException
import pyotp
from datetime import datetime, timedelta
import pyotp
import io
import qrcode
from base64 import b64encode


@app.route('/register', methods=['GET', 'POST']) # Add more details to user
@jwt_required(optional=True)
def register():
    logger.info(str(request.method) + "-Request on " + request.path)

    if request.method == 'POST' and get_jwt_identity() == None:
        username = request.form['username']
        if User.find_by_username(db, username) != None:
            logger.warning("User already exists")
            flash('Username already exists', 'failed')
            # Add JSON Response for APIs? make_response(render_template('register.html'))?
            return render_template('register.html')
        password = request.form['password']
        password2 = request.form['password2']
        if password != password2:
            logger.warning("Different passwords provided during the registration")
            logger.debug("User: " + username + "provided different passwords during the registration")
            flash('Passwords dont match', 'failed')
            # Add JSON Response for APIs?
            return render_template('register.html')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user_data = {'username': username, 'password': hashed_password, 'twofa_secret': None, "twofa_activated": False} #TODO Add more information about user
        user = User(user_data)
        user.save(db)

        flash('Your account has been created!', 'success')
        logger.debug("User Account has been created successfully")
        # Add JSON Response for APIs?
        return redirect(url_for('login'))
    elif request.method =='GET' and get_jwt_identity() == None:       
        return render_template('register.html')
    elif request.method =='GET' and get_jwt_identity() != None:
        flash('You are already logged in!', 'success')
        return redirect(url_for('dashboard'))
    else:
        logger.warning("Unknown Request, unset jwt cookies...")
        resp = make_response(redirect(url_for('register')))
        unset_jwt_cookies(resp)
        return resp

@app.route('/login', methods=['GET', 'POST']) # Add more details to user
@jwt_required(optional=True)
def login():
    logger.info(str(request.method) + "-Request on " + request.path)

    if request.method == 'POST' and get_jwt_identity() == None:
        username = request.form['username']
        password = request.form['password']
        user = User.find_by_username(db = db, username = username)
        if user != None: # if username found
            password_hash = user.get_attribute('password')

            if bcrypt.check_password_hash(password_hash, password) == False: #if the password is wrong
                logger.warning("Wrong username/password combination provided")
                logger.debug("User: '" + username + "' provided a wrong password during the login")
                flash('Wrong username or password', 'failed')
                # Add JSON Response for APIs?
                return render_template('login.html')
            
        else:
            logger.warning("Username could not be found")
            logger.debug("User: '" + username + "' could not be found during the login")
            flash('Wrong username or password', 'failed')
            # Add JSON Response for APIs?
            return render_template('login.html')
        
        access_token = create_access_token(identity=user.get_id())
        flash('You have been logged in successfully!', 'success')
        logger.debug("User Account has logged in successfully")
        # Add JSON Response for APIs?

        resp = make_response(redirect(url_for('login_2fa')))
        set_access_cookies(response=resp, encoded_access_token=access_token)
        return resp
    elif request.method =='GET' and get_jwt_identity() == None:
        return render_template('login.html')
    elif request.method =='GET' and get_jwt_identity() != None:
        flash('You are already logged in!', 'success')
        return redirect(url_for('dashboard'))
    else:
        logger.warning("Unknown Request, unset jwt cookies...")
        resp = make_response(redirect(url_for('register')))
        unset_jwt_cookies(resp)
        return resp

@app.route('/logout', methods=['GET'])
@jwt_required()
def logout():
    logger.info(str(request.method) + "-Request on " + request.path)

    flash('You have been logged out successfully!', 'success')
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(resp)
    return resp

# 2fa
@app.route('/register/2fa', methods=['GET', 'POST'])
@jwt_required()
def register_2fa():
    logger.info(str(request.method) + "-Request on " + request.path)

    if get_jwt_identity():
        user = load_user(db=db, user_id=get_jwt_identity())

    # Check if the user has already a 2fa activated
    if user.get_attribute('twofa_activated') == "True":
        logger.warning("User: '" + user.get_attribute("username") + "' has already a 2fa activated")
        flash('You have already a 2-Factor-Authentification activated!',  'failed')
        return redirect(url_for('login_2fa'))
    
    # Check if the user 2fa is already authenticated
    try:
        if get_jwt()["2fa_timestamp"] != None and (datetime.now() - get_jwt()["2fa_timestamp"]) < timedelta(minutes=5):
            flash("You are already 2FA authenticated", "success")
            return redirect(url_for('dashboard'))
    except:
        logger.error("User: '" + user.get_attribute("username") + "' is not 2fa authenticated")

    # Check Request Method
    if request.method =='GET':
        secret = pyotp.random_base32()
        user.update_attribute(db, attribute="twofa_secret", value=secret)

        # Generate the OTP URI for the QR code
        otp_uri = pyotp.TOTP(secret).provisioning_uri(user.get_attribute("username"), issuer_name="DILLIGAF") #TODO issuer_name

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
        otp = request.form['otp']

        if verify2fa(user=user, otp=otp):
            user.update_attribute(db, "twofa_activated", True)
            flash('2FA Verification Successful', 'success')
            logger.debug("User: '" + user.get_attribute("username") + "' has successfully verified its 2fa")
            return redirect(url_for('login_2fa'))
        else:
            flash('User 2FA could not be verified', 'failed')
            logger.debug("User: '" + user.get_attribute("username") + "' failed to verify its 2fa")
            return redirect(url_for('register_2fa'))
    else:
        logger.warning("Unknown Request, unset jwt cookies...")
        resp = make_response(redirect(url_for('register')))
        unset_jwt_cookies(resp)
        return resp
        
@app.route('/login/2fa', methods=['GET', 'POST'])
@jwt_required()
def login_2fa():
    logger.info(str(request.method) + "-Request on " + request.path)

    if get_jwt_identity():
        user = load_user(db=db, user_id=get_jwt_identity())
    
    # Check if the user has 2fa activated
    if user.get_attribute('twofa_activated') != "True":
        logger.warning("User: '" + user.get_attribute("username") + "' has no 2fa activated")
        flash('You have no 2-Factor-Authentification activated! Redirect to 2fa register',  'failed')
        return redirect(url_for('register_2fa'))
    
    # Check if the user 2fa is already authenticated
    try:
        date_now = datetime.strptime(str(datetime.now())[:19], '%Y-%m-%d %H:%M:%S')
        date_2fa = datetime.strptime((get_jwt()["2fa_timestamp"]), '%a, %d %b %Y %H:%M:%S %Z')
        if (date_now - date_2fa) < timedelta(hours=1):
            flash("You are already 2FA authenticated", "success")
            return redirect(url_for('dashboard'))
    except:
        logger.error("User: '" + user.get_attribute("username") + "' is not 2fa authenticated")

    if request.method =='GET':
        return render_template('login_2fa.html', loggedin=True)
    
    elif request.method =='POST':
        otp = request.form['otp']

        if verify2fa(user=user, otp=otp):
            flash('2FA Authentication Successful', 'success')
            logger.debug("User: '" + user.get_attribute("username") + "' has successfully authenticated with 2fa")
            resp = make_response(redirect(url_for('dashboard')))
            access_token = create_access_token(identity=user.get_id(), additional_claims={'2fa_timestamp': datetime.now()})
            set_access_cookies(response=resp, encoded_access_token=access_token)
            return resp
        else:
            flash('User 2FA could not be authenticated', 'failed')
            logger.debug("User: '" + user.get_attribute("username") + "' failed to authenticate with 2fa")
            return render_template('login_2fa.html')
    else:
        logger.warning("Unknown Request, unset jwt cookies...")
        resp = make_response(redirect(url_for('register')))
        unset_jwt_cookies(resp)
        return resp


def verify2fa(user: User, otp: str) -> bool:
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

@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response=resp)
    return resp

@jwt.unauthorized_loader
def custom_unauthorized_response(callback):
    # Customize the error response -> render Unauthorized.html -> button available to redirect to login
    return redirect(url_for('login'))

# => Flask_jwt-extended
# https://flask-jwt-extended.readthedocs.io/en/stable/optional_endpoints.html