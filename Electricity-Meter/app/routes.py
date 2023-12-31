# Contributions by: Ellen Kistner, Vitali Bier
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Import app from app package
from app import app, logger, toggle_sleep
from flask import make_response, request

# TODO remove
from app import get_em_id, get_em_value, get_manufacturer, get_model, get_serial_number, get_firmware_version
from os import getenv
from hashlib import sha256

# ===== Routes =====

# === Home / Index ===
@app.route('/', methods=['GET'])
def test():
    return f"EM_ID: {get_em_id()}, EM_Value: {get_em_value()}, Manufacturer: {get_manufacturer()}, Model: {get_model()}, Serial Number: {get_serial_number()}, Firmware Version: {get_firmware_version()}"

@app.route('/api/maintenance', methods=['POST'])
def maintenance():
    '''
    This function handles the maintenance page of the web application.
    '''
    if authorize(request.headers.get('Authorization')):
        request.json.get('duration')
        toggle_sleep(request.json.get('duration'))
        return make_response('', 200)
    else:
        return make_response('', 401)

@app.before_request
def before_request():
    '''
    This function is executed before each request.
    '''
    # Check the secret
    # TODO



def authorize(token) -> bool:
    h = sha256()
    h.update(getenv('SECRET_MPO_EM').encode('utf-8'))
    if h.hexdigest() == token:
        return True
    else:
        return False

