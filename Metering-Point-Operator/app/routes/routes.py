# Contributions by: xx, xx
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import g, render_template, flash

# Packages for JWT
from flask_jwt_extended import jwt_required

# Import app, logger and db object from app package
from app import app

# ===== Routes =====

# === Home / Index ===
@app.route('/test')
@jwt_required(optional=True) # optional=True allows to access the route without a valid JWT, but checks it if it is present
def test():
    '''
    This function handles the home page of the web application.
    '''
    return f"Hello World! JWT Auth:{g.jwt_authenticated}, 2FA Enabled: {g.twofa_activated}, 2FA Auth: {g.twofa_authenticated}"

@app.route('/index', methods=['GET'])
@app.route('/home', methods=['GET'])
@app.route('/', methods=['GET'])
@jwt_required() # optional=True allows to access the route without a valid JWT, but checks it if it is present
def home():
    '''
    This function handles the home page of the web application.
    '''
    return render_template('index.html')

@app.route('/maintenance', methods=['GET'])
@jwt_required() # optional=True allows to access the route without a valid JWT, but checks it if it is present
def maintenance():
    '''
    This function handles the maintenance page of the web application.
    '''
    return render_template('maintenance.html')

@app.route('/maintenance', methods=['POST'])
@jwt_required() # optional=True allows to access the route without a valid JWT, but checks it if it is present
def maintenance_post():
    '''
    This function handles the maintenance page of the web application.
    '''

    return render_template('maintenance.html')

@app.route('/user_info/update', methods=['POST'])
@jwt_required() # optional=True allows to access the route without a valid JWT, but checks it if it is present
def user_info_update():
    '''
    This function handles the maintenance page of the web application.
    '''
    return render_template('user_info.html')


@app.route('/overview', methods=['GET'])
@jwt_required() # optional=True allows to access the route without a valid JWT, but checks it if it is present
def overview():
    '''
    This function handles the maintenance page of the web application.
    '''
    return render_template('overview.html')