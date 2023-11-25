from pytest import fixture
from app import app, db, logger
from app.tests.functional.auth_functions import login_jwt, register, activate_2fa, validate_2fa

class TestAuthRoutes:
    @fixture(autouse=True)
    def setup(self):
        self.client = app.test_client()

        # Check if account exists, if not create it
        if not db.users.find_one({"username": "pytest"}):
            logger.info("User not existing. Registering...")
            register(self.client)

        # Check if account has 2fa enabled, then disable it
        if db.users.find_one({"username": "pytest"})["twofa_activated"]:
            logger.info("2fa already enabled. Disabling...")
            db.users.update_one({"username": "pytest"}, {"$set": {"twofa_activated": False}})

    # GET Requests
    def test_get_register(self):
        response = self.client.get('/register')
        assert response.status_code == 200

    def test_get_login(self):
        response = self.client.get('/login')
        assert response.status_code == 200

    def test_get_reset_password_route(self):
        response = self.client.get('/reset-password')
        assert response.status_code == 200

    # POST Requests
    # Register Successfull
    def test_post_register(self):
        # Check if account is already existing, then delete it
        if db.users.find_one({"username": "pytest"}):
            logger.info("User already existing. Deleting...")
            db.users.delete_one({"username": "pytest"})

        register(self.client)

    # Register Failed
    def test_post_register_email_invalid(self):
        request_data = {
            "email": "Pytest",
            "username": "pytest1",
            "password": "PytestPytest123!",
            "password2": "PytestPytest123!"
        }

        response = self.client.post('/register', data=request_data)

        # Check if redirect to register page
        assert response.status_code == 302
        assert response.headers['Location'] == '/register'
    
    def test_post_register_username_invalid(self):
        request_data = {
            "email": "Pytest1@test.test",
            "username": "pytest!",
            "password": "PytestPytest123!",
            "password2": "PytestPytest123!"
        }

        response = self.client.post('/register', data=request_data)

        # Check if redirect to register page
        assert response.status_code == 302
        assert response.headers['Location'] == '/register'

    def test_post_register_password_invalid(self):
        request_data = {
            "email": "Pytest1@test.test",
            "username": "pytest1",
            "password": "testtest123!",
            "password2": "testtest123!"
        }

        response = self.client.post('/register', data=request_data)

        # Check if redirect to register page
        assert response.status_code == 302
        assert response.headers['Location'] == '/register'

    def test_post_register_passwords_not_matching(self):
        request_data = {
            "email": "Pytest1@test.test",
            "username": "pytest1",
            "password": "PytestPytest123!",
            "password2": "TestTest123"
        }

        response = self.client.post('/register', data=request_data)

        # Check if redirect to register page
        assert response.status_code == 302
        assert response.headers['Location'] == '/register'

    def test_post_register_existing_email(self):
        request_data = {
            "email": "Pytest@test.test",
            "username": "pytest1",
            "password": "PytestPytest123!",
            "password2": "PytestPytest123!"
        }

        response = self.client.post('/register', data=request_data)

        # Check if redirect to register page
        assert response.status_code == 302
        assert response.headers['Location'] == '/register'

    def test_post_register_existing_username(self):
        request_data = {
            "email": "Pytest1@test.test",
            "username": "pytest",
            "password": "PytestPytest123!",
            "password2": "PytestPytest123!"
        }

        response = self.client.post('/register', data=request_data)
        
        # Check if redirect to register page
        assert response.status_code == 302
        assert response.headers['Location'] == '/register'

    # Login Failed
    def test_post_login_username_invalid(self):
        request_data = {
            "username": "pytest!",
            "password": "PytestPytest123!",
        }

        response = self.client.post('/login', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'

    def test_post_login_password_invalid(self):
        request_data = {
            "username": "pytest",
            "password": "testtest123!",
        }

        response = self.client.post('/login', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'

    def test_post_login_username_not_found(self):
        request_data = {
            "username": "Pytest",
            "password": "PytestPytest123!",
        }

        response = self.client.post('/login', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'

    def test_post_login_password_not_matching(self):
        request_data = {
            "username": "pytest",
            "password": "PytestPytest123!!",
        }

        response = self.client.post('/login', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'

    # Login Successfull
    def test_post_login(self):
        login_jwt(self.client)

    # Security Question Successfull
    def test_post_security_question(self):
        request_data = {
            "security_question": "What is your favorite color?",
            "answer": "Blue"
        }
        
        # Login with jwt
        self.client = login_jwt(self.client)

        response = self.client.post('/add-security-question', data=request_data)

        # Check if redirect to user info page
        assert response.status_code == 302
        assert response.headers['Location'] == '/user_info'

    # Security Question Failed
    def test_post_security_question_not_useable(self):
        request_data = {
            "security_question": "What is your favorite color?PWNED",
            "answer": "Red"
        }
        
        # Login with jwt
        self.client = login_jwt(self.client)

        response = self.client.post('/add-security-question', data=request_data)

        # Check if redirect to user info page
        assert response.status_code == 302
        assert response.headers['Location'] == '/user_info'

    def test_post_security_question_already_answered(self):
        request_data = {
            "security_question": "What is your favorite color?",
            "answer": "Red"
        }
        
        # Login with jwt
        self.client = login_jwt(self.client)

        response = self.client.post('/add-security-question', data=request_data)

        # Check if redirect to user info page
        assert response.status_code == 302
        assert response.headers['Location'] == '/user_info'

    def test_post_security_question_invalid_answer(self):
        request_data = {
            "security_question": "What is your mother's maiden name?",
            "answer": "Red!"
        }
        
        # Login with jwt
        self.client = login_jwt(self.client)

        response = self.client.post('/add-security-question', data=request_data)

        # Check if redirect to user info page
        assert response.status_code == 302
        assert response.headers['Location'] == '/user_info'

    # Reset Password with Security Question Failed
    def test_post_reset_password_email_invalid(self):
        request_data = {
            "email": "pytest",
            "security_question": "What is your favorite color?",
            "answer": "Blue",
            "password": "PytestPytest123!",
            "password2": "PytestPytest123!"
        }

        response = self.client.post('/reset-password', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/reset-password'

    def test_post_reset_password_security_question_invalid(self):
        request_data = {
            "email": "pytest@test.test",
            "security_question": "What is your favorite color?PWNED",
            "answer": "Blue",
            "new_password": "PytestPytest123!"
        }

        response = self.client.post('/reset-password', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/reset-password'

    def test_post_reset_password_answer_invalid(self):
        request_data = {
            "email": "pytest@test.test",
            "security_question": "What is your favorite color?",
            "answer": "Red",
            "new_password": "PytestPytest123!"
        }

        response = self.client.post('/reset-password', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/reset-password'

    def test_post_reset_password_password_invalid(self):
        request_data = {
            "email": "pytest@test.test",
            "security_question": "What is your favorite color?",
            "answer": "Blue",
            "new_password": "testtest123!"
        }

        response = self.client.post('/reset-password', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/reset-password'

    # Reset Password with Security Question Successfull
    def test_post_reset_password(self):
        request_data = {
            "email": "pytest@test.test",
            "security_question": "What is your favorite color?",
            "answer": "Blue",
            "new_password": "PytestPytest123!"
        }

        response = self.client.post('/reset-password', data=request_data)

        # Check if redirect to login page
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'

    # Set new Password Failed
    def test_post_set_new_password_old_password_invalid(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Activate 2fa for user pytest
        otp = activate_2fa(self.client)
        
        # Get 2fa access_token_cookie and session
        self.client = validate_2fa(self.client, otp)

        request_data = {
            "old_password": "testtest123!",
            "new_password": "TestTest1234!",
            "new_password2": "TestTest1234!"
        }

        response = self.client.post('/set-new-password', data=request_data)

        # Check if redirect to login page and cookies are unset
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'
        assert self.client.get_cookie("access_token_cookie") is not None

    def test_post_set_new_password_new_password_invalid(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Activate 2fa for user pytest
        otp = activate_2fa(self.client)
        
        # Get 2fa access_token_cookie and session
        self.client = validate_2fa(self.client, otp)

        request_data = {
            "old_password": "PytestPytest123!",
            "new_password": "testtest123!",
            "new_password2": "testtest123!"
        }

        response = self.client.post('/set-new-password', data=request_data)

        # Check if redirect to login page and cookies are unset
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'
        assert self.client.get_cookie("access_token_cookie") is not None

    def test_post_set_new_password_old_password_doesnt_match(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Activate 2fa for user pytest
        otp = activate_2fa(self.client)
        
        # Get 2fa access_token_cookie and session
        self.client = validate_2fa(self.client, otp)

        request_data = {
            "old_password": "PytestPytest123!!",
            "new_password": "TestTest1234!",
            "new_password2": "TestTest1234!"
        }

        response = self.client.post('/set-new-password', data=request_data)

        # Check if redirect to login page and cookies are unset
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'
        assert self.client.get_cookie("access_token_cookie") is not None

    def test_post_set_new_password_new_passwords_dont_match(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Activate 2fa for user pytest
        otp = activate_2fa(self.client)
        
        # Get 2fa access_token_cookie and session
        self.client = validate_2fa(self.client, otp)

        request_data = {
            "old_password": "PytestPytest123!",
            "new_password": "TestTest1234!",
            "new_password2": "TestTest1234!!"
        }

        response = self.client.post('/set-new-password', data=request_data)

        # Check if redirect to login page and cookies are unset
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'
        assert self.client.get_cookie("access_token_cookie") is not None

    # Set new Password Successfull
    def test_post_set_new_password(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Activate 2fa for user pytest
        otp = activate_2fa(self.client)
        
        # Get 2fa access_token_cookie and session
        self.client = validate_2fa(self.client, otp)

        request_data = {
            "old_password": "PytestPytest123!",
            "new_password": "PytestPytest123!",
            "new_password2": "PytestPytest123!"
        }

        response = self.client.post('/set-new-password', data=request_data)

        # Check if redirect to login page and cookies are unset
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'
        assert self.client.get_cookie("access_token_cookie") is None
