from app import login_manager, logger
from flask_login import UserMixin
from bson.objectid import ObjectId

#TODO: logger, db commands
@login_manager.user_loader
def load_user(user_id):
    return User(mongo.db.users.find_one({'_id': ObjectId(user_id)}))

class User(UserMixin): # Add more details to user
    def __init__(self, user_data):
        self.user_data = user_data

    def get_id(self):
        return str(self.user_data['_id'])

    def find_by_username(self, username):
        user_data = mongo.db.users.find_one({'username': username})
        return User(user_data) if user_data else None

    def save(self):
        mongo.db.users.insert_one(self.user_data)

    # Define other user-related methods here

    @classmethod
    def create_user(cls, username, password):
        user_data = {'username': username, 'password': password}
        return cls(user_data)

    # Define other class methods as needed
