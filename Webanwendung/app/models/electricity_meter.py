# Add here information and function about the electricity_meter:
# register em
# update_heartbeat and status
# delete em
# find_em
# List all ems from ID List


# Change to "Netzstellenbetreiber"
from app import logger #, login_manager
from flask_login import UserMixin
from bson.objectid import ObjectId

#TODO: logger, db commands
#@login_manager.user_loader
def load_user(db, user_id):
    return Electricity_meter(db.db.electricity_meter.find_one({'_id': ObjectId(user_id)}))

class Electricity_meter(UserMixin): # Add more details to user
    def __init__(self, user_data):
        self.user_data = user_data

    def get_id(self):
        return str(self.user_data['_id'])

    def find_by_username(self, db, username):
        user_data = db.db.electricity_meter.find_one({'username': username})
        return Electricity_meter(user_data) if user_data else None

    def save(self, db):
        db.db.electricity_meter.insert_one(self.user_data)

    # Define other user-related methods here

    @classmethod
    def create_user(cls, username, password):
        user_data = {'username': username, 'password': password}
        return cls(user_data)

    # Define other class methods as needed
