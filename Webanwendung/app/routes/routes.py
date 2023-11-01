from flask import request, render_template, make_response, url_for, redirect, flash
from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt, unset_jwt_cookies
from app import app, logger, db
from app.models.user import load_user
from app.models.contract import load_contract
from datetime import datetime, timedelta

# TODO more comments

@app.route('/')
@jwt_required(optional=True)
def home():
    if get_jwt_identity():
        logger.info("Get-Request: Starting Page displayed for logged in user")
        return render_template('index.html', loggedin=True)
    else:
        logger.info("Get-Request: Starting Page displayed for not logged in user")
        return render_template('index.html')



@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    logger.info(str(request.method) + "-Request on " + request.path)

    if get_jwt_identity():
        user = load_user(db=db, user_id=get_jwt_identity())

    # Check if user is 2FA authenticated
    try:
        date_now = datetime.strptime(str(datetime.now())[:19], '%Y-%m-%d %H:%M:%S')
        date_2fa = datetime.strptime((get_jwt()["2fa_timestamp"]), '%a, %d %b %Y %H:%M:%S %Z')
        if (date_now - date_2fa) > timedelta(hours=1):
            resp = make_response(redirect(url_for('login_2fa')))
            flash("You are either not 2FA authenticated or your token expired", "error")
            return resp
    except:
        resp = make_response(redirect(url_for('login_2fa')))
        flash("You are either not 2FA authenticated or your token expired", "error")
        return resp

    contractIDs = user.get_attribute("contract_list")
    return render_template('dashboard.html', loggedin=True, contracts=contracts)

@app.errorhandler(404)
def page_not_found(e):
    logger.info(str(request.method) + "-Request on " + request.path)
    return render_template('PageNotFound.html'), 404