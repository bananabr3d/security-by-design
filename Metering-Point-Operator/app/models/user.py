from app import DBConnectionError, logger
from flask_pymongo import pymongo
from bson.objectid import ObjectId

def load_user(db, user_id:str):
    try:
        user_data = db.users.find_one({'_id': ObjectId(user_id)}, allow_partial_results=False)
    except:
        raise DBConnectionError
        
    return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], backup_codes=user_data["backup_codes"], security_questions=user_data["security_questions"]) if user_data else None # Add here user attributes

class User():
    def __init__(self, db:pymongo.database.Database, email:str, username:str, password:str, twofa_secret:str = None, twofa_activated:bool = False, backup_codes:list = [], security_questions:dict = {}) -> None:
        self.user_data = {'email': email, 'username': username, 'password': password, 'twofa_secret': twofa_secret, 'twofa_activated': twofa_activated, 'backup_codes': backup_codes, 'security_questions': security_questions}
        self.db = db
        try:
            user_data = db.users.find_one({'email': email}, allow_partial_results=False)
            if user_data:
                self.user_data['_id'] = user_data['_id']
        except:
            raise DBConnectionError

    def __getitem__(self, key: str) -> str:
        return self.user_data[key]

    def __setitem__(self, key: str, value: str) -> None:
        if key in self.user_data:
            self.user_data[key] = value

            try:
                self.db.users.update_one({'_id': self.user_data['_id']}, {'$set': {key: value}})
            except:
                raise DBConnectionError
        else:
            raise AttributeError


    def get_id(self) -> str:
        return str(self.user_data['_id'])
    
    def get_attribute(self, attribute: str) -> str:
        return str(self.user_data[attribute])
    
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
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], backup_codes=user_data["backup_codes"], security_questions=user_data["security_questions"]) if user_data else None # Add here user attributes
    
    def find_by_email(db: pymongo.database.Database, email: str):
        try:
            user_data = db.users.find_one({'email': email}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], backup_codes=user_data["backup_codes"], security_questions=user_data["security_questions"]) if user_data else None # Add here user attributes

    @classmethod
    def find_by_id(cls, db: pymongo.database.Database, user_id: str):
        '''
        Returns the user with the given ID.
        '''
        try:
            user_data = db.users.find_one({'_id': ObjectId(user_id)}, allow_partial_results=False)
        except:
            raise DBConnectionError

        return User(db=db,
                    email=user_data["email"],
                    username=user_data["username"],
                    password=user_data["password"],
                    twofa_secret=user_data["twofa_secret"],
                    twofa_activated=user_data["twofa_activated"],

                    backup_codes=user_data["backup_codes"],
                    security_questions=user_data["security_questions"]) if user_data else None  # Add here user attributes

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

    def save(self) -> None:
            try:
                self.db.users.insert_one(self.user_data)

                user_data = self.db.users.find_one({'email': self.user_data["email"]}, allow_partial_results=False)
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
        
        logger.info(f"User with ID '{self.get_id()}' successfully deleted.")
