# Contributions by: xx, xx
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import g, render_template, flash, request, redirect, url_for
import re

# Packages for JWT
from flask_jwt_extended import jwt_required

from requests import post
from ..models.electricity_meter import em_exists, load_electricity_meter, ElectricityMeter

# Import app, logger and db object from app package
from app import app, logger, db

# ===== Regex =====
em_id_reg = re.compile(r'[A-Za-z0-9]{24}')
duration_reg = re.compile(r'[0-9]{1,3}')


# ===== Routes =====

# === Home / Index ===
@app.route('/test')
@jwt_required(
    optional=True)  # optional=True allows to access the route without a valid JWT, but checks it if it is present
def test():
    '''
    This function handles the home page of the web application.
    '''
    return f"Hello World! JWT Auth:{g.jwt_authenticated}, 2FA Enabled: {g.twofa_activated}, 2FA Auth: {g.twofa_authenticated}"


@app.route('/index', methods=['GET'])
@app.route('/home', methods=['GET'])
@app.route('/', methods=['GET'])
@jwt_required()  # optional=True allows to access the route without a valid JWT, but checks it if it is present
def home():
    '''
    This function handles the home page of the web application.
    '''

    return render_template('index.html')


# ===== Maintainance ======

@app.route('/maintenance', methods=['GET'])
@jwt_required()  # optional=True allows to access the route without a valid JWT, but checks it if it is present
def maintenance():
    '''
    This function handles the maintenance page of the web application.
    '''
    list_em_id = list()
    for em in db.electricity_meter.find({}):
        logger.info(f'laaaaa {em["em_maintain"]}')
        if em['em_maintain']:
            logger.info(f'laaaaa {em['_id']}')
            list_em_id.append(em['_id'])
    logger.info(list_em_id)
    return render_template('maintenance.html', ems=list_em_id)


@app.route('/maintenance', methods=['POST'])
@jwt_required()  # optional=True allows to access the route without a valid JWT, but checks it if it is present
def maintenance_post():
    '''
    This function handles the maintenance page of the web application.
    '''
    # logger.info("Hallo")
    # emmm = db.electricity_meter.find({'em_maintain': True})
    # logger.info("emmm", emmm)
    # for em in emmm:
    #     logger.info("halli", em)
    # logger.info(request.form['electricity_meter_id'])
    if not verify_em_id(request.form['electricity_meter_id']):
        flash('Invalid electricity meter id.')
        return render_template('maintenance.html', ems=db.electricity_meter.find({'em_maintain': True}))
    if not verify_duration(request.form['duration_min']):
        flash('Invalid duration.')
        return render_template('maintenance.html', ems=db.electricity_meter.find({'em_maintain': True}))

    if em_exists(db, request.form['electricity_meter_id']):
        em = load_electricity_meter(db, request.form['electricity_meter_id'])
        logger.info(f"em_ip: {em.get_em_ip()}")
        # logger.info(em)
        if not em.get_em_maintain():
            logger.info(f"Duration: {request.form['duration_min']}")
            post(f'http://{em.get_em_ip()}:5000/api/maintenance', json={'duration': request.form['duration_min']})
            em.toggle_maintain()
        else:
            flash('Electricity meter is already in maintenance mode.')
    else:
        flash('Electricity meter does not exist.')

    list_em_id = list()
    for em in db.electricity_meter.find({}):
        if em['em_maintain']:
            list_em_id.append(em['_id'])
    logger.info(list_em_id)

    return render_template('maintenance.html', ems=list_em_id)

@app.route('/dashboard', methods=['GET'])
@app.route('/overview', methods=['GET'])
@jwt_required()  # optional=True allows to access the route without a valid JWT, but checks it if it is present
def dashboard():
    '''
    This function handles the maintenance page of the web application.
    '''

    list_em_id = list()
    for em in db.electricity_meter.find({}):
        logger.info(f'laaaaa {em['_id'], em['em_value']}')
        em = load_electricity_meter(db, em['_id'])
        list_em_id.append(em)

    return render_template('overview.html', ems=list_em_id)


@app.route('/impressum', methods=['GET'])
def impressum():
    '''
    This function handles the maintenance page of the web application.
    '''
    return render_template('impressum.html')


def verify_em_id(em_id):
    '''
    This function verifies the input of the maintenance form.
    '''
    if re.fullmatch(em_id_reg, em_id):
        logger.info(f"Input em_id:{em_id} verified.")
        return True
    else:
        logger.info(f"Input em_id:{em_id}not verified.")
        return False


def verify_duration(duration):
    if re.fullmatch(duration_reg, duration):
        logger.info(f"Input duration: {duration} verified.")
        return True
    else:
        logger.info(f"Input duration: {duration} not verified.")
        return False
