from pytest import fixture
from app import app, db, logger
from app.tests.functional.auth_functions import register, login_jwt, activate_2fa, validate_2fa

def add_user_information():
    '''
    Adds the required user information (date_of_birth, address (PLZ, Street, street house number, city, country, phone_number, name, surname), etc.) to the database.
    '''
    db.users.update_one({"username": "pytest"}, {"$set": {"date_of_birth": "01.01.1970"}})
    # Address is a dictionary
    db.users.update_one({"username": "pytest"}, {"$set": {"address": {"plz": "12345", "street": "Teststreet", "street_house_number": "1", "city": "Testcity", "country": "Testcountry"}}})
    db.users.update_one({"username": "pytest"}, {"$set": {"phone_number": "0123456789"}})
    db.users.update_one({"username": "pytest"}, {"$set": {"name": "Testname"}})
    db.users.update_one({"username": "pytest"}, {"$set": {"surname": "Testsurname"}})

class TestPrivateRoutes:
    @fixture(autouse=True)
    def setup(self):
        self.client = app.test_client()

        # Check if account exists, if not create it
        if not db.users.find_one({"username": "pytest"}):
            logger.info("Creating pytest account...")
            register(self.client)

        # Check if account has 2fa enabled, then disable it
        if db.users.find_one({"username": "pytest"})["twofa_activated"]:
            logger.info("2fa already enabled. Disabling...")
            db.users.update_one({"username": "pytest"}, {"$set": {"twofa_activated": False}})

    # GET Requests
    def test_get_dashboard_route(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Register 2fa
        otp = activate_2fa(self.client)

        # Login with 2fa
        self.client = validate_2fa(self.client, otp)


        response = self.client.get('/dashboard')
        assert response.status_code == 200

    def test_get_user_info_route(self):
        # Login with jwt
        self.client = login_jwt(self.client)

        # Register 2fa
        otp = activate_2fa(self.client)

        # Login with 2fa
        self.client = validate_2fa(self.client, otp)

        response = self.client.get('/user-info')
        assert response.status_code == 200
