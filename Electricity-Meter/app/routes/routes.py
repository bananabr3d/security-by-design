# Contributions by: Ellen Kistner, Vitali Bier
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Import app from app package
from app import app

# TODO remove
from app.config import get_em_id, get_em_value

# ===== Routes =====

# === Home / Index ===
@app.route('/', methods=['GET'])
def test():

    print(get_em_id())
    print(get_em_value())

    return "test"

@app.route('/maintenance', methods=['POST'])
def maintenance():
    '''
    This function handles the maintenance page of the web application.
    '''
    return "test"