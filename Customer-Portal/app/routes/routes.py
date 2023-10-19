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

    # Add here loading of all contracts of user and then displaying the status, ...
    # contract_list = user.get_attribute("contracts")
    
    # # 1. load data from contract of user
    # for contract_id in contract_list:
    #     contract = load_contract(contract_id)

        # 2. make request on Messstellenbetreiber for data of each contract => How to implement? Do we load a contract.html in the dashboard.html or can we add it here in the return?

    
    #render_template with contract objects for each contract
    return render_template('dashboard.html', loggedin=True, username=user.get_attribute('username'))

@app.errorhandler(404)
def page_not_found(e):
    logger.info(str(request.method) + "-Request on " + request.path)
    return render_template('PageNotFound.html'), 404