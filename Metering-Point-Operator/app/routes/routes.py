# Contributions by: xx, xx
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import g

# Packages for JWT
from flask_jwt_extended import jwt_required

# Import app, logger and db object from app package
from app import app

# ===== Routes =====

# === Home / Index ===
@app.route('/test')
@jwt_required(optional=True) # optional=True allows to access the route without a valid JWT, but checks it if it is present
def home():
    '''
    This function handles the home page of the web application.
    '''
    return f"Hello World! JWT Auth:{g.jwt_authenticated}, 2FA Enabled: {g.twofa_activated}, 2FA Auth: {g.twofa_authenticated}"