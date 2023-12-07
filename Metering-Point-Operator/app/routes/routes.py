# Contributions by: xx, xx
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import g, render_template, flash, request

# Packages for JWT
from flask_jwt_extended import jwt_required

from requests import post
from ..models.electricity_meter import em_exists, load_electricity_meter, ElectricityMeter


# Import app, logger and db object from app package
from app import app, logger, db

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
    return render_template('maintenance.html', ems = db.electricity_meter.find({'em_maintain': True}))

@app.route('/maintenance', methods=['POST'])
@jwt_required() # optional=True allows to access the route without a valid JWT, but checks it if it is present
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
    if em_exists(db, request.form['electricity_meter_id']):
        em = load_electricity_meter(db, request.form['electricity_meter_id'])
        #logger.info(em)
        if not em.get_em_maintain():
            post('http://electricity-meter:5000/api/maintenance', json={'duration': request.form['duration_min']})
            em.toggle_maintain()
        else:
            flash('Electricity meter is already in maintenance mode.')
    else:
        flash('Electricity meter does not exist.')
    #TODO request to em with ip and duration

    list_em_id = list()
    for em in db.electricity_meter.find({'em_maintain': True}):
        logger.info('laaaaa', em)
        list_em_id.append(em['_id'])
    logger.info(list_em_id)

    return render_template('maintenance.html', ems= list_em_id)

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


@app.route('/impressum', methods=['GET'])
def impressum():
    '''
    This function handles the maintenance page of the web application.
    '''
    return render_template('impressum.html')