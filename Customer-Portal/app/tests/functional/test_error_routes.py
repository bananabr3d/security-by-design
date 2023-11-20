from pytest import fixture
from app import app, db, logger
from app.tests.functional.auth_functions import register, login_jwt, activate_2fa, validate_2fa

class TestErrorRoutes:
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

    def test_get_404_route(self):
        response = self.client.get('/404')
        assert response.status_code == 404

    def test_errorhandler_500(self):
        request_data = {
            "username": "pytest"
        }
        response = self.client.post('/login', data=request_data)
        assert response.status_code == 400

    def test_errorhandler_inactive2fa(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        response = self.client.get('/login/2fa')
        assert response.status_code == 302
        assert response.headers['Location'] == '/register/2fa'

    def test_errorhandler_invalid2fa(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Register 2fa
        activate_2fa(self.client)

        response = self.client.get('/dashboard')
        assert response.status_code == 302
        assert response.headers['Location'] == '/login/2fa'

    def test_errorhandler_active2fa(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Register 2fa
        activate_2fa(self.client)

        response = self.client.get('/register/2fa')
        assert response.status_code == 302
        assert response.headers['Location'] == '/login/2fa'

    def test_errorhandler_valid2fa(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Register 2fa
        otp = activate_2fa(self.client)

        # Validate 2fa
        validate_2fa(self.client, otp)

        response = self.client.get('/login/2fa')
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'

    def test_errorhandler_validjwt(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        response = self.client.get('/login')
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'

    def test_errorhandler_invalidjwt(self):
        response = self.client.get('/dashboard')
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'