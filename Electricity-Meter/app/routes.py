# Contributions by: Ellen Kistner, Vitali Bier
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Import app from app package
from app import app, logger

# TODO remove
from app import get_em_id, get_em_value

# ===== Routes =====

# === Home / Index ===
@app.route('/', methods=['GET'])
def test():

    return [get_em_id(), get_em_value()]

@app.route('/maintenance', methods=['POST']) #TODO
def maintenance():
    '''
    This function handles the maintenance page of the web application.
    '''
    return "test"


@app.before_request
def before_request():
    '''
    This function is executed before each request.
    '''
    # Check the secret
    #TODO