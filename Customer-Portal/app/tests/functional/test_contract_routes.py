from pytest import fixture
from app import app, db, logger
from app.tests.functional.auth_functions import register, login_jwt, activate_2fa, validate_2fa, get_secret
from app.models.user import load_user
from app.models.contract import load_contract
from pyotp import TOTP

class TestContractRoutes:
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

        # Check if account has 2fa enabled, if not enable it
        if self.user.get_attribute("twofa_activated") != "True":
            logger.info("2fa enabled. Enabling...")
            otp = activate_2fa(self.client)

        # Login with 2fa
        otp = TOTP(get_secret()).now()

        self.client = validate_2fa(self.client, otp)

        # Check if contract_list is empty, if not empty it and delete contract in contract db
        if self.user.get_contract_list() != [] or db.contracts.find_one({"electricity_meter_id": "pytest"}) != None:
            logger.info("Contract list not empty. Deleting all contracts...")
            # Set empty contract list
            self.user.update_attribute(db=db, attribute="contract_list", value=[])
            # Delete contracs in contract db
            db.contracts.delete_one({"electricity_meter_id": "pytest"})

    # POST Requests
    # Add Contract Route Success
    def test_add_contract_route(self):
        request_data = {
            "electricity_meter_id": "pytest" #TODO Adjust after updating the contract route
        }

        response = self.client.post('/add-contract', data=request_data)
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'

        # load all contracts of user
        self.user = load_user(db=db, user_id=db.users.find_one({"username": "pytest"})["_id"]) # Get newest user object for updated contract list
        contract_list = self.user.get_contract_list()
        
        logger.debug(f"Contract list: {contract_list}") #TODO Remove

        assert len(contract_list) == 1

        # Check if contract is in contract list, else assert False
        for contract_id in contract_list:
            Contract = load_contract(db, contract_id=contract_id)
            if Contract != None and Contract.get_attribute("electricity_meter_id") == request_data["electricity_meter_id"]:
                assert True
                return
        
        assert False

    # Add Contract Route Fail
    def test_add_contract_route_em_already_exists(self):
        request_data = {
            "electricity_meter_id": "pytest" #TODO Adjust after updating the contract route
        }

        # Add contract to user
        self.test_add_contract_route()

        response = self.client.post('/add-contract', data=request_data)

        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'

        # load all contract objects of user
        self.user = load_user(db=db, user_id=db.users.find_one({"username": "pytest"})["_id"]) # Get newest user object for updated contract list
        contract_list = self.user.get_contract_list()
        
        logger.debug(f"Contract list: {contract_list}") #TODO Remove

        assert len(contract_list) == 1

    def test_add_contract_route_em_invalid(self): #TODO
        pass