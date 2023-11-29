# Contributions by: Vitali Bier
# Description: This file contains the admin routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import request, render_template, redirect, url_for, flash, make_response, g
from flask_jwt_extended import jwt_required

# Import app, logger, db, jwt object, exceptions and models from app package
from app import app, logger, db, Invalid2FA

# ===== Routes =====

@app.before_request
@jwt_required(optional=True)
def before_request_admin():
    '''
    This function is executed before each request.

    It checks if the user is a admin
    '''
    try: # last resort error handling

        g.admin = False

        if g.user:
            if g.user.get_attribute("admin") == True:
                logger.debug("User is admin.")

                g.admin = True

    except Exception as e:
        logger.error(f"Error while executing before_request_admin: {e}")