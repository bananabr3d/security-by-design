# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the error routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import render_template, url_for, redirect, flash, g

# Packages for JWT
from flask_jwt_extended import jwt_required

# Import app, logger and db object from app package
from app import app, logger, Inactive2FA, Invalid2FA, Active2FA, Valid2FA, ValidJWT

# ===== Routes =====

# === Error handling ===
@app.errorhandler(Inactive2FA)
def errorhandler_inactive_2fa(errorhandler_error):
    '''
    This function handles the Inactive2FA error of the web application.

    The error is logged and the user is redirected to the register 2FA page.
    '''
    logger.warning(f"Inactive2FA Error Handler: {errorhandler_error}")
    flash("Your 2FA is not activated", "error")
    return redirect(url_for('register_2fa'))

@app.errorhandler(Invalid2FA)
def errorhandler_invalid_2fa(errorhandler_error):
    '''
    This function handles the Invalid2FA error of the web application.

    The error is logged and the user is redirected to the login 2FA page.
    '''
    logger.warning(f"Invalid2FA Error Handler: {errorhandler_error}")
    flash("You are either not 2FA authenticated or your token expired", "error")
    return redirect(url_for('login_2fa'))

@app.errorhandler(Active2FA)
def errorhandler_active_2fa(errorhandler_error):
    '''
    This function handles the Active2FA error of the web application.

    The error is logged and the user is redirected to the login 2FA page.
    '''
    logger.warning(f"Active2FA Error Handler: {errorhandler_error}")
    flash("You already have 2FA actived", "error")
    return redirect(url_for('login_2fa'))

@app.errorhandler(Valid2FA)
def errorhandler_valid_2fa(errorhandler_error):
    '''
    This function handles the Valid2FA error of the web application.

    The error is logged and the user is redirected to the dashboard page.
    '''
    logger.warning(f"Valid2FA Error Handler: {errorhandler_error}")
    flash("You are already 2FA authenticated", "error")
    return redirect(url_for('dashboard'))

@app.errorhandler(ValidJWT)
def errorhandler_valid_jwt(errorhandler_error):
    '''
    This function handles the ValidJWT error of the web application.

    The error is logged and the user is redirected to the dashboard page.
    '''
    logger.warning(f"ValidJWT Error Handler: {errorhandler_error}")
    flash("You are already logged in", "error")
    return redirect(url_for('dashboard'))


@app.errorhandler(404)
@jwt_required(optional=True)
def errorhandler_page_not_found(errorhandler_error):
    '''
    This function handles the error page of the web application.

    The JWT Token is checked and the error page is displayed accordingly.
    '''
    logger.debug(f"Error on Code 404: {errorhandler_error}")

    try: # last resort error handling
        return render_template('PageNotFound.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated), 404
    except Exception as e:
        logger.error("Error: " + str(e))
        flash("Internal Server Error, redirect to home", "error")
        return redirect(url_for('home')), 500
    

@app.errorhandler(500)
def errorhandler_internal_server_error(errorhandler_error):
    '''
    This function handles the internal server error page of the web application. It will be called if an error occurs in the application, but not if errors occur in other error handling or before/after request functions.
    
    The error is logged and the user is redirected to the home page.
    '''
    logger.error(f"Error: {errorhandler_error}")
    flash("Internal Server Error, redirect to home", "error")
    return redirect(url_for('home'))