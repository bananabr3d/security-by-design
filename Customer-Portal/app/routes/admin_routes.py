# Contributions by: Vitali Bier
# Description: This file contains the admin routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import request, render_template, redirect, url_for, flash, make_response, g
from flask_jwt_extended import jwt_required

# Import app, logger, db, jwt object, exceptions and models from app package
from app import app, logger, db, Invalid2FA

# Import from models
from app.models.user import get_user_count, get_usernames


# ===== Routes =====
# === Admin Panel ===
@app.route('/admin', methods=['GET'])
@jwt_required()
def admin_dashboard():
    '''
    This function handles the GET dashboard/admin route.

    Raise Invalid2FA if the user is not 2fa authenticated.

    Returns the admin dashboard template.
    '''
    # Check if the user is 2fa authenticated
    if not g.twofa_authenticated:
        raise Invalid2FA
    
    # Check if the user is an admin
    if not g.user.get_attribute("admin"):
        # If not, redirect to dashboard
        return redirect(url_for('dashboard'))
    
    # Get user count
    user_count = get_user_count(db=db)

    # Get usernames
    usernames = get_usernames(db=db)

    logger.info(f"Admin {g.user.get_attribute('username')} accessed the admin dashboard.")

    # Render the admin dashboard
    return render_template('admin_dashboard.html', user_count=user_count, jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated, username=g.user.get_attribute('username'), admin=g.admin, usernames=usernames)

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
            if g.user.get_attribute("admin") == True or g.user.get_attribute("admin") == "True" or g.user.get_attribute("admin") == "true":
                logger.debug("User is admin.")

                g.admin = True

    except Exception as e:
        logger.error(f"Error while executing before_request_admin: {e}")