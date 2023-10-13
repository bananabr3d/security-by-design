from app import logger
from flask_login import UserMixin
from bson.objectid import ObjectId
import datetime

#TODO: logger, more information about user
def load_user(db, user_id):
    return User(db.db.users.find_one({'_id': ObjectId(user_id)}))

class User(UserMixin): # Add more details to user
    def __init__(self, user_data) -> None:
        self.user_data = user_data

    def get_id(self) -> str:
        return str(self.user_data['_id'])
    
    def get_attribute(self, attribute: str) -> str:
        return str(self.user_data[attribute])
    
    def update_attribute(self, db, attribute: str, value: str) -> None:
        if self.get_attribute(attribute=attribute) != None: # Check if user has the attribute
            db.db.users.update_one({'_id': self.user_data['_id']}, {'$set': {attribute: value}})

    def find_by_username(db, username: str):
        user_data = db.db.users.find_one({'username': username}, allow_partial_results=False)
        return User(user_data) if user_data else None
    
    def add_contract(self, db, contract_id: int) -> None: #Get the list of contracts and append the new one
        contract_list = (db.db.users.find_one({'_id': self.user_data['_id']})['contracts']).append(contract_id)
        db.db.users.update_one({'_id': self.user_data['_id']}, {'$push': {'contracts': contract_list}})

    def save(self, db) -> None:
        db.db.users.insert_one(self.user_data)

    # Define other user-related methods here

    @classmethod
    def create_user(cls, username:str, password:str, twofa_secret:str = None, twofa_activated:bool = False): #TODO Add more information about user for creation
        logger.debug("Creating a new user with following attributes: " + [username, password, twofa_secret, twofa_activated])
        user_data = {'username': username, 'password': password, 'twofa_secret': twofa_secret, 'twofa_activated': twofa_activated}
        return cls(user_data)

    # Define other class methods as needed
