from flask import request, render_template, redirect, url_for, flash, make_response
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required,
    create_access_token, set_access_cookies, unset_jwt_cookies)
from app import app, logger, db, bcrypt, offline_mode
from app.models.user import User
from app.models.electricity_meter import Electricity_meter
import pyotp

# TODO more comments

@app.route('/')
def home():
    logger.info("Get-Request: Starting Page displayed")
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST']) # Add more details to user
@jwt_required(optional=True)
def register():
    logger.debug("Incoming Request on /register with request method:" + request.method)

    if request.method == 'POST' and not offline_mode and get_jwt_identity() == None:
        username = request.form['username']
        if db.db.users.find_one({"username" : username}) != None: #TODO Change with model functions
            logger.warning("User already exists")
            flash('Username already exists', 'failed')
            # Add JSON Response for APIs?
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
        user_data = {'username': username, 'password': hashed_password}
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

@app.route('/login', methods=['GET', 'POST']) # Add more details to user
@jwt_required(optional=True)
def login():
    logger.debug("Incoming Request on /login with request method:" + request.method)

    if request.method == 'POST' and not offline_mode and get_jwt_identity() == None:
        logger.info(request.form)
        username = request.form['username']
        password = request.form['password']
        user_in_db = db.db.users.find_one({"username" : username}, allow_partial_results=False)
        if user_in_db != None: # if username found
            password_hash = (db.db.users.find_one({"username": username}, allow_partial_results=False))["password"]
        else:
            logger.warning("Username could not be found")
        if db.db.users.find_one({"username" : username}, allow_partial_results=False) == None or bcrypt.check_password_hash(password_hash, password) == False: #if the username doesnt exist or the pw is wrong
            logger.warning("Wrong username/password combination provided")
            logger.debug("User: '" + username + "' provided a wrong password during the login")
            flash('Wrong username or password', 'failed')
            # Add JSON Response for APIs?
            return render_template('login.html')
        
        access_token = create_access_token(identity=username)
        flash('You have been logged in successfully!', 'success')
        logger.debug("User Account has logged in successfully")
        # Add JSON Response for APIs?
        resp = make_response(redirect(url_for('dashboard')))
        set_access_cookies(response=resp, encoded_access_token=access_token)
        return resp
    elif request.method =='GET' and get_jwt_identity() == None:
        return render_template('login.html')
    elif request.method =='GET' and get_jwt_identity() != None:
        flash('You are already logged in!', 'success')
        return redirect(url_for('dashboard'))

@app.route('/logout', methods=['GET']) # Add more details to user
@jwt_required()
def logout():
    logger.debug("Incoming Request on /logout with request method:" + request.method)

    resp = make_response(redirect(url_for('login')))
    unset_jwt_cookies(resp)
    return resp

@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    logger.info("Get-Request: Dashboard displayed")
    currentUser = get_jwt_identity()
    return render_template('dashboard.html')

# @app.route('/activate2fa', methods=['POST'])
# def activate2fa():
#     secret = pyotp.random_base32()
#     user_id = get_curent_userid() # vitali fragen wegen jwt
#     db.db.users.update_one({"_id": user_id}, {"$set": {"2fa_secret": secret}})

# @app.route('/verify2fa', methods=['POST'])
# def verify2fa():

#     user_2fa_code = request.json.get('2fa_code')

#     user_id = get_current_user_id()
#     user = db.db.users.find_one({"_id": user_id}, allow_partial_results=False)

#     if not user:
#         flash('User not found', 'failed')
#         return render_template('verify2fa.html')
    
#     secret = user.get('2fa_secret')

#     if not secret:
#         flash('User has no 2fa',  'failed')
#         return redirect(url_for('index'))
    
#     totp = pyotp.TOTP(secret)

#     if totp.verify(user_2fa_code):
#         token = generate_jwt_token(user_id)
#         flash('Verification Successfull', 'Success')
#     else:
#         flash('User could not be verified', 'failed')

@app.errorhandler(404)
def page_not_found(e):
    logger.info('Request on Page Not Found')
    return render_template('PageNotFound.html'), 404

# => Flask_jwt-extended
# https://flask-jwt-extended.readthedocs.io/en/stable/optional_endpoints.html