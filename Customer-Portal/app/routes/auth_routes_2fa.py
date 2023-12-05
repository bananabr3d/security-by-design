# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the auth routes for 2fa of the web application.

# ===== Packages =====
# Packages for Flask
from flask import request, render_template, redirect, url_for, flash, make_response, g, Response
from flask_jwt_extended import (
    create_access_token, jwt_required, set_access_cookies, unset_jwt_cookies)

# Import app, logger, bcrypt object, exceptions and models from app package
from app import app, logger, bcrypt, Inactive2FA, Active2FA, Valid2FA

# Import models
from app.models.user import User

# Import pyotp for 2fa and io, qrcode, base64 for QR code generation
import pyotp, io, qrcode, random
from base64 import b64encode

# Import datetime for cookie expiration handling
from datetime import datetime, timedelta

# Import regex for input validation
import re

# Import jwt_token_refresh_expiration from auth_routes
from app.routes.auth_routes import jwt_token_refresh_expiration



# Regex for input validation
regex_6digits = re.compile(r'^[0-9]{6}$')


# ===== Help Functions =====

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
    secret = user['twofa_secret']

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
    g.user["twofa_secret"] = secret

    # Generate the OTP URI for the QR code
    otp_uri = pyotp.TOTP(secret).provisioning_uri(g.user["username"], issuer_name="VoltWave")

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
        g.user["twofa_activated"] = True
        flash('2FA Verification Successful', 'success')
        logger.debug(f"User: '{g.user['username']}' has successfully verified its 2fa")

        # Generate 2fa backup codes 10 * (random 6 digit numbers)
        backup_codes = list()
        for i in range(10):
            backup_codes.append(random.randint(100000, 999999)) # "000000" is explicitly excluded

        flash('Your backup codes are: ' + str(backup_codes), 'backup-codes')
        
        # Update user backup codes -> save the hashes of the backup_codes
        backup_codes = [bcrypt.generate_password_hash(str(code)).decode('utf-8') for code in backup_codes]
        g.user["backup_codes"] = backup_codes
        
        return redirect(url_for('login_2fa'))
    
    else: # If otp is not valid, flash error message and redirect to register_2fa
        flash('User 2FA could not be verified', 'failed')
        logger.debug(f"User: '{g.user['username']}' failed to verify its 2fa")
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
        logger.debug(f"User: '{g.user['username']}' has successfully authenticated with 2fa")

        resp = make_response(redirect(url_for('dashboard')))
        access_token = create_access_token(identity=g.user.get_id(), fresh=timedelta(minutes=jwt_token_refresh_expiration), additional_claims={'2fa_timestamp': datetime.now()})
        set_access_cookies(response=resp, encoded_access_token=access_token)

        return resp
    
    else: # If otp is not valid, flash error message and redirect to login_2fa
        flash('User 2FA could not be authenticated', 'failed')
        logger.debug(f"User: '{g.user['username']}' failed to authenticate with 2fa")
        return redirect(url_for('login_2fa'))


# === Reset 2FA ===     
@app.route('/reset-2fa', methods=['POST'])
@jwt_required()
def reset_2fa():
    '''
    This function handles the reset_2fa route and can only be accessed with a JWT Token.

    Returns to dashboard and message if 2fa couldnt be reset. (Either because of the format or that it is not correct)

    Returns redirect to login if 2fa was successfully reseted. (+ Updates the user 2fa secret + activated status in the database)
    '''

    if g.twofa_authenticated:
        logger.debug(f"User: '{g.user['username']}' tried to reset its 2fa, while being 2fa authenticated")
        return resp_reset_2fa()

    elif "backup_code" in request.form.keys():
        logger.debug(f"User: '{g.user['username']}' tried to reset its 2fa, with a backup code")
    
        # = Input Validation =
        # Backup Code
        if not validate_6digits(request.form['backup_code']):
            flash("Invalid Backup Code", "error") # Dont send another flash message as if the backup code itself is invalid. So the attacker doesnt know if it has the wrong format or is invalid itself.
            return redirect(url_for('dashboard'))

        # Check if user has backup codes
        backup_codes = g.user['backup_codes']
        if backup_codes == None: # Should not happen normally, because the user has to have backup codes to get to this route
            flash("Invalid Backup Code", "error")
            logger.error(f"User: '{g.user['username']}' provided a backup code, but there are none in the database")
            return redirect(url_for('dashboard'))
        
        # Check if backup code is correct
        for backup_code in backup_codes:
            if bcrypt.check_password_hash(backup_code, request.form['backup_code']):
                return resp_reset_2fa()
    
        # Send flash message if backup code is not correct
        flash("Invalid Backup Code", "error")
        return redirect(url_for('dashboard'))
    
    else:
        logger.debug(f"User: '{g.user['username']}' didnt provide a backup code or is 2fa authenticated during the 2fa reset")
        flash("2FA could not be reset", "error")
        return redirect(url_for('dashboard'))

def resp_reset_2fa() -> Response:
    # Update user 2fa secret
    g.user["twofa_secret"] = None
    # Update user 2fa activated
    g.user["twofa_activated"] = False

    g.user["backup_codes"] = None

    # Unset JWT and redirect to login
    resp = make_response(redirect(url_for('login')))
    logger.debug(f"User: '{g.user['username']}' has successfully reset its 2fa")
    flash("Your 2 FA has been reset successfully", "success")
    unset_jwt_cookies(resp)
    return resp
