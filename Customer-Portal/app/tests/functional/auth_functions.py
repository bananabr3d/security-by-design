from pyotp import TOTP
from app import logger
from time import sleep


secret = None

backup_codes = None

def get_secret():
    global secret
    return secret

def set_secret(secret_input):
    global secret
    secret = secret_input

def get_backup_codes():
    global backup_codes
    return backup_codes

def set_backup_codes(backup_codes_input):
    global backup_codes
    backup_codes = backup_codes_input

# Register user pytest
def register(client) -> None:
    '''
    Register on user pytest with jwt

    :param client: Flask test client without jwt token

    :return: None
    '''
    request_data = {
        "email": "Pytest@test.test",
        "username": "pytest",
        "password": "PytestPytest123!"
    }

    response = client.post('/register', data=request_data)

    # Check if redirect to login page
    assert response.status_code == 302
    assert response.headers['Location'] == '/login'

# Login user pytest
def login_jwt(client):
    '''
    Login on user pytest with jwt

    :param client: Flask test client without jwt token

    :return: Flask test client with JWT
    '''
    request_data = {
        "username": "pytest",
        "password": "PytestPytest123!",
    }

    response = client.post('/login', data=request_data)

    # Check if redirect to 2fa login page
    assert response.status_code == 302
    assert response.headers['Location'] == '/login/2fa'


    # Check access_token and session cookie
    assert client.get_cookie("access_token_cookie") is not None
    assert client.get_cookie("session") is not None

    return client


# Activate 2fa for user pytest
def activate_2fa(client) -> str:
    '''
    Activate 2fa for user pytest

    :param client: Flask test client with valid jwt token

    :return: otp
    '''
    # Get 2fa otp from /register/2fa
    response = client.get('/register/2fa')
    
    # Get otp from response data value of input id secret
    secret = response.data.decode("utf-8").split('id="secret" value="')[1].split('"')[0]

    set_secret(secret)

    # Generate otp from secret
    otp = TOTP(secret).now()

    # Set request data
    request_data_2fa_register = {
        "otp": otp
    }

    # Post otp to /register/2fa
    response = client.post('/register/2fa', data=request_data_2fa_register)

    # Check if redirect to /login/2fa page
    assert response.status_code == 302
    assert response.headers['Location'] == '/login/2fa'

    return otp

# Validate 2fa for user pytest
def validate_2fa(client, otp: str):
    '''
    Validate 2fa for user pytest

    :param client: Flask test client with valid jwt token

    :param otp: otp to validate

    :return: Flask test client with valid 2fa jwt token
    '''
    request_data_2fa_login = {
        "otp": otp
    }

    # Post otp to /login/2fa
    response = client.post('/login/2fa', data=request_data_2fa_login)

    try:
        # Check if redirect to dashboard page
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'
    except AssertionError:
        logger.error(f"2fa otp: {otp} is invalid, generate new otp in 3 second")
        sleep(3)
        otp = TOTP(get_secret()).now()
        return validate_2fa(client, otp)
        

    return client