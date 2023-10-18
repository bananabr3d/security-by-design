from app import DBConnectionError
from flask_pymongo import pymongo
from bson.objectid import ObjectId

#TODO: more information about user
def load_user(db, user_id:str):
    try:
        user_data = db.db.users.find_one({'_id': ObjectId(user_id)}, allow_partial_results=False)
    except:
        raise DBConnectionError
        
    return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], contract_list=user_data["contract_list"]) if user_data else None # Add here user attributes

class User(): # Add more details to user
    def __init__(self, db:pymongo.database.Database, email:str, username:str, password:str, twofa_secret:str = None, twofa_activated:bool = False, contract_list:list = []) -> None:
        self.user_data = {'email': email, 'username': username, 'password': password, 'twofa_secret': twofa_secret, 'twofa_activated': twofa_activated, 'contract_list': contract_list}

        try:
            user_data = db.db.users.find_one({'email': email}, allow_partial_results=False)
            if user_data:
                self.user_data['_id'] = user_data['_id']
        except:
            raise DBConnectionError
        
    def get_id(self) -> str:
        return str(self.user_data['_id'])
    
    def get_attribute(self, attribute: str) -> str:
        return str(self.user_data[attribute])
    
    def update_attribute(self, db: pymongo.database.Database, attribute: str, value: str) -> None:
        if self.get_attribute(attribute=attribute) != None: # Check if user has the attribute
            try:
                db.db.users.update_one({'_id': self.user_data['_id']}, {'$set': {attribute: value}})
            except:
                raise DBConnectionError

    def find_by_username(db: pymongo.database.Database, username: str):
        try:
            user_data = db.db.users.find_one({'username': username}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], contract_list=user_data["contract_list"]) if user_data else None # Add here user attributes
    
    def find_by_email(db: pymongo.database.Database, email: str):
        try:
            user_data = db.db.users.find_one({'email': email}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], contract_list=user_data["contract_list"]) if user_data else None # Add here user attributes
    

    def add_contract(self, db: pymongo.database.Database, contract_id: int) -> None: #Get the list of contracts and append the new one
        try:
            contract_list = (db.db.users.find_one({'_id': self.user_data['_id']})['contracts']).append(contract_id) # load the contracts and append the new contract id
            db.db.users.update_one({'_id': self.user_data['_id']}, {'$push': {'contracts': contract_list}}) # update the contract list
        except:
            raise DBConnectionError
        
    def save(self, db:pymongo.database.Database) -> None:
            try:
                db.db.users.insert_one(self.user_data)

                user_data = db.db.users.find_one({'email': self.user_data["email"]}, allow_partial_results=False)
                self.user_data["_id"] = user_data["_id"]
            except:
                raise DBConnectionError

    # Define other user-related methods here
