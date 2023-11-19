from pytest import fixture
from app import app, logger, db, bcrypt
from app.tests.functional.auth_functions import register, login_jwt, activate_2fa, validate_2fa
from app.models.user import load_user


class TestAuth2FARoutes:
    @fixture(autouse=True)
    def setup(self):
        self.client = app.test_client()

        # Check if account exists, if not create it
        if not db.users.find_one({"username": "pytest"}):
            logger.info("User not existing. Registering...")
            register(self.client)
   
        self.user = load_user(db=db, user_id=db.users.find_one({"username": "pytest"})["_id"])

        # Login with jwt
        self.client = login_jwt(self.client)

        # Disable 2fa for user pytest
        self.user.update_attribute(db=db, attribute="twofa_activated", value="False")

    # GET Requests
    def test_get_register_2fa(self):
        response = self.client.get('/register/2fa')
        assert response.status_code == 200

    def test_get_login_2fa(self):
        # Register 2fa
        activate_2fa(self.client)

        response = self.client.get('/login/2fa')
        assert response.status_code == 200

    # POST Requests
    # Register 2fa route Success
    def test_post_register_2fa(self):
        activate_2fa(self.client)

    # Register 2fa route Fail
    def test_post_register_2fa_otp_invalid(self):
        # Get 2fa otp from /register/2fa
        response = self.client.get('/register/2fa')
        
        # Get otp from response data value of input id secret
        secret = response.data.decode("utf-8").split('id="secret" value="')[1].split('"')[0]

        # Set request data
        request_data_2fa_register = {
            "otp": "12345"
        }

        # Post otp to /register/2fa
        response = self.client.post('/register/2fa', data=request_data_2fa_register)

        # Check if redirect to /register/2fa page
        assert response.status_code == 302
        assert response.headers['Location'] == '/register/2fa'

    def test_post_register_2fa_otp_incorrect(self):
        # Get 2fa otp from /register/2fa
        self.client.get('/register/2fa')

        # Set request data
        request_data_2fa_register = {
            "otp": "123456"
        }

        # Post otp to /register/2fa
        response = self.client.post('/register/2fa', data=request_data_2fa_register)

        # Check if redirect to /register/2fa page
        assert response.status_code == 302
        assert response.headers['Location'] == '/register/2fa'

    # Login 2fa route Success
    def test_post_login_2fa(self):
        # Register 2fa
        otp = activate_2fa(self.client)

        # Validate 2fa
        validate_2fa(self.client, otp)

    # Login 2fa route Fail
    def test_post_login_2fa_otp_invalid(self):
        # Register 2fa
        activate_2fa(self.client)

        # Set request data
        request_data_2fa_login = {
            "otp": "12345"
        }

        # Post otp to /login/2fa
        response = self.client.post('/login/2fa', data=request_data_2fa_login)

        # Check if redirect to /login/2fa page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login/2fa'

    def test_post_login_2fa_otp_incorrect(self):
        # Register 2fa
        activate_2fa(self.client)

        # Set request data
        request_data_2fa_login = {
            "otp": "123456"
        }

        # Post otp to /login/2fa
        response = self.client.post('/login/2fa', data=request_data_2fa_login)

        # Check if redirect to /login/2fa page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login/2fa'

    # Reset 2fa route Successfull
    def test_post_reset_2fa_with_2fa_auth(self):
        # Register 2fa
        otp = activate_2fa(self.client)

        # Validate 2fa
        validate_2fa(self.client, otp)

        # Post to /reset-2fa
        response = self.client.post('/reset-2fa')

        # Check if redirect to /login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'

    def test_post_reset_2fa_with_backup_code(self):
        # Register 2fa
        activate_2fa(self.client)

        # As backup codes are not stored in clear text in db and in flash messages bad to get -> We hash "000000" as a backup code and put it 10 times as a list of the user in the db
        backup_code = "000000"
        # Hash backup code
        backup_code_hash = bcrypt.generate_password_hash(backup_code).decode('utf-8')
        backup_codes = [backup_code_hash] * 10

        # Update user backup codes
        self.user.update_attribute(db=db, attribute="backup_codes", value=backup_codes)        

        request_data = {
            "backup_code": backup_code
        }

        # Post to /reset-2fa
        response = self.client.post('/reset-2fa', data=request_data)

        # Check if redirect to /login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'

    # Reset 2fa route Fail
    def test_post_reset_2fa_without_2fa_and_backup_code(self):
        # Post to /reset-2fa
        response = self.client.post('/reset-2fa')

        # Check if redirect to /dashboard page
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'

    def test_post_reset_2fa_backup_code_invalid(self):
        # Register 2fa
        activate_2fa(self.client)

        # Set request data
        request_data = {
            "backup_code": "12345"
        }

        # Post to /reset-2fa
        response = self.client.post('/reset-2fa', data=request_data)

        # Check if redirect to /dashboard page
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'

    def test_post_reset_2fa_backup_code_incorrect(self):
        # Register 2fa
        activate_2fa(self.client)

        # Set request data
        request_data = {
            "backup_code": "123456"
        }

        # Post to /reset-2fa
        response = self.client.post('/reset-2fa', data=request_data)

        # Check if redirect to /dashboard page
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'