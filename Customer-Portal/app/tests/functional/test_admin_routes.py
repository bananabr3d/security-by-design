from pytest import fixture
from app import app, db, logger
from app.tests.functional.auth_functions import register, login_jwt, activate_2fa, validate_2fa

class TestAdminRoutes:
    @fixture(autouse=True)
    def setup(self):
        self.client = app.test_client()

        # Check if account exists, if not create it
        if not db.users.find_one({"username": "pytest_admin"}):
            logger.info("Creating pytest_admin account...")
            register(self.client)

        # Check if account has 2fa enabled, then disable it
        if db.users.find_one({"username": "pytest_admin"})["twofa_activated"]:
            logger.info("2fa already enabled. Disabling...")
            db.users.update_one({"username": "pytest_admin"}, {"$set": {"twofa_activated": False}})

  #  def test_admin_dashboard_route(self):
        # Login with jwt
        self.client = login_jwt(self.client, username="pytest_admin", password="adminpassword")

        response = self.client.get('/admin')
        assert response.status_code == 200
        # Add more assertions based on your application's behavior

   # def test_confirm_contract_termination_route(self):
        # Implement similar setup and login steps as above if needed
        # Then test the '/admin/confirm-contract-termination/<contract_id>' route

        response = self.client.post('/admin/confirm-contract-termination/contract_id')
        assert response.status_code == 200
        # Add more assertions based on your application's behavior

  #  def test_decline_contract_termination_route(self):
        # Implement similar setup and login steps as above if needed
        # Then test the '/admin/decline-contract-termination/<contract_id>' route

        response = self.client.post('/admin/decline-contract-termination/contract_id')
        assert response.status_code == 200
        # Add more assertions based on your application's behavior

# Add more test methods for other admin routes as needed
