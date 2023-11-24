from app import DBConnectionError, logger
from flask_pymongo import pymongo
from bson.objectid import ObjectId
from app.models.contract import load_contract

def load_user(db, user_id:str):
    try:
        user_data = db.users.find_one({'_id': ObjectId(user_id)}, allow_partial_results=False)
    except:
        raise DBConnectionError
        
    return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], contract_list=user_data["contract_list"], backup_codes=user_data["backup_codes"], security_questions=user_data["security_questions"]) if user_data else None # Add here user attributes

class User():
    def __init__(self, db:pymongo.database.Database, email:str, username:str, password:str, twofa_secret:str = None, twofa_activated:bool = False, contract_list:list = [], backup_codes:list = [], security_questions:dict = {}) -> None:
        self.user_data = {'email': email, 'username': username, 'password': password, 'twofa_secret': twofa_secret, 'twofa_activated': twofa_activated, 'contract_list': contract_list, 'backup_codes': backup_codes, 'security_questions': security_questions}

        try:
            user_data = db.users.find_one({'email': email}, allow_partial_results=False)
            if user_data:
                self.user_data['_id'] = user_data['_id']
        except:
            raise DBConnectionError
        
    def get_id(self) -> str:
        return str(self.user_data['_id'])
    
    def get_attribute(self, attribute: str) -> str:
        return str(self.user_data[attribute])
    
    def get_contract_list(self) -> list:
        return self.user_data['contract_list']
    
    def get_backup_codes(self) -> list:
        return self.user_data['backup_codes']
    
    def get_security_questions(self) -> dict:
        return self.user_data['security_questions']
    
    def get_all_key_values(self) -> dict:
        '''
        Returns a dict with all key value pairs of the user_data dict except _id, password, twofa_secret, backup_codes, security_questions
        '''
        temp_user_data = self.user_data.copy() # Create a copy of user_data to not change the original dict

        # Remove _id, password, twofa_secret, backup_codes, security_questions from user_data
        temp_user_data.pop('_id')
        temp_user_data.pop('password')
        temp_user_data.pop('twofa_secret')
        temp_user_data.pop('backup_codes')
        temp_user_data.pop('security_questions')

        return temp_user_data
    
    def update_attribute(self, db: pymongo.database.Database, attribute: str, value: str) -> None:
        if self.get_attribute(attribute=attribute) != None: # Check if user has the attribute
            try:
                db.users.update_one({'_id': self.user_data['_id']}, {'$set': {attribute: value}})
            except:
                raise DBConnectionError
        else:
            raise AttributeError

    def find_by_username(db: pymongo.database.Database, username: str):
        try:
            user_data = db.users.find_one({'username': username}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], contract_list=user_data["contract_list"], backup_codes=user_data["backup_codes"], security_questions=user_data["security_questions"]) if user_data else None # Add here user attributes
    
    def find_by_email(db: pymongo.database.Database, email: str):
        try:
            user_data = db.users.find_one({'email': email}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], contract_list=user_data["contract_list"], backup_codes=user_data["backup_codes"], security_questions=user_data["security_questions"]) if user_data else None # Add here user attributes
    

    def add_contract(self, db: pymongo.database.Database, contract_id: int) -> None: #Get the list of contracts and append the new one
        try:
            db.users.update_one({'_id': self.user_data['_id']}, {'$push': {'contract_list': contract_id}}) # update the contract list
        except:
            raise DBConnectionError
        
    def remove_contract(self, db: pymongo.database.Database, contract_id: int) -> None: #Get the list of contracts and remove the one
        try:
            db.users.update_one({'_id': self.user_data['_id']}, {'$pull': {'contract_list': contract_id}}) # update the contract list
        except:
            raise DBConnectionError
        
        # Check if contract is removed
        try:
            user_data = db.users.find_one({'_id': self.user_data['_id']}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        if contract_id in user_data['contract_list']:
            logger.error(f"Contract with ID '{contract_id}' could not be removed from user with ID '{self.get_id()}'.")
        
    def add_security_question(self, db: pymongo.database.Database, question: str, answer: str) -> None:
        try:
            db.users.update_one({'_id': self.user_data['_id']}, {'$set': {'security_questions.' + question: answer}})
        except:
            raise DBConnectionError

    def remove_security_question(self, db: pymongo.database.Database, question: str) -> None:
        try:
            db.users.update_one({'_id': self.user_data['_id']}, {'$unset': {'security_questions.' + question: ""}})
        except:
            raise DBConnectionError
        
        # Check if security question is removed
        try:
            user_data = db.users.find_one({'_id': self.user_data['_id']}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        if question in user_data['security_questions']:
            logger.error(f"Security question with question '{question}' could not be removed from user with ID '{self.get_id()}'.")

    def save(self, db:pymongo.database.Database) -> None:
            try:
                db.users.insert_one(self.user_data)

                user_data = db.users.find_one({'email': self.user_data["email"]}, allow_partial_results=False)
                self.user_data["_id"] = user_data["_id"]
            except:
                raise DBConnectionError
            
    def delete(self, db:pymongo.database.Database) -> None:
        try:
            db.users.delete_one({'_id': self.user_data['_id']})
        except:
            raise DBConnectionError
        
        # Check if user is deleted
        try:
            user_data = db.users.find_one({'_id': self.user_data['_id']}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        if user_data:
            logger.error(f"User with ID '{self.get_id()}' could not be deleted.")
        
        logger.debug(f"User with ID '{self.get_id()}' successfully deleted.")

        # Check if user has contracts and delete them
        for contract_id in self.get_contract_list():
            contract = load_contract(db=db, contract_id=contract_id)
            contract.delete(db=db)
            logger.debug(f"Contract with ID '{contract_id}' of user with ID '{self.get_id()}' successfully deleted.")