# from pytest import fixture
# from app import app, db, logger
# from app.tests.functional.auth_functions import login_jwt, register, activate_2fa, validate_2fa
#
#
# class TestRoutes:
#     @fixture(autouse=True)
#     def setup(self):
#
#         # todo umschreiben für maintain
#         self.client = app.test_client()
#
#         # Check if account exists, if not create it
#         if not db.users.find_one({"username": "pytest"}):
#             logger.info("User not existing. Registering...")
#             register(self.client)
#
#         # Check if account has 2fa enabled, then disable it
#         if db.users.find_one({"username": "pytest"})["twofa_activated"]:
#             logger.info("2fa already enabled. Disabling...")
#             db.users.update_one({"username": "pytest"}, {"$set": {"twofa_activated": False}})
#
#     def test_maintain(self):
#         response = self.client.get('/maintain')
#         assert response.status_code == 200
#
#
#     def test_post_maintain(self):
#         #todo umschreiben für post maintain
#
#         em_id = db.electricity_meter.find_one({})["_id"]
#         request_data = {
#             "electricity_meter_id": em_id,
#             "duration_min": 2,
#
#         }
#
#         response = self.client.post(':5000/maintenance', data=request_data)
#
#         # Check if redirect to register page
#         assert db.electricity_meter.find_one({"_id": em_id})["em_maintain"] == True
#         assert response.status_code == 200
