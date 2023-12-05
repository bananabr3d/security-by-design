from app import DBConnectionError, logger
from flask_pymongo import pymongo
from bson.objectid import ObjectId
from app.models.contract import Contract
from datetime import date

def get_user_count(db: pymongo.database.Database) -> int:
    '''
    Returns the number of users in the database.
    '''
    try:
        user_count = db.users.count_documents({})
    except:
        raise DBConnectionError

    return user_count

def get_usernames(db: pymongo.database.Database) -> list:
    '''
    Returns a list of all usernames in the database.
    '''
    try:
        usernames = db.users.distinct('username')
    except:
        raise DBConnectionError

    return usernames


class User():
    def __init__(self, db:pymongo.database.Database, email:str, 
                 username:str, password:str, twofa_secret:str = None, 
                 twofa_activated:bool = False, contract_list:list = [], 
                 backup_codes:list = [], security_questions:dict = {}, 
                 admin:bool = False, date_of_birth:date = None, address_plz:int = None, 
                 address_street:str = None, address_street_house_number:int = None, 
                 address_city:str = None, address_country:str = None, 
                 phone_number:str = None, name:str = None, surname:str = None) -> None:
        '''
        Creates a new user object.
        '''

        self._db = db

        address = {'plz': address_plz, 'street': address_street, 
                   'street_house_number': address_street_house_number, 
                   'city': address_city, 'country': address_country}
        
        self.user_data = {'email': email, 'username': username, 'password': password, 
                          'twofa_secret': twofa_secret, 'twofa_activated': twofa_activated, 
                          'contract_list': contract_list, 'backup_codes': backup_codes, 
                          'security_questions': security_questions, 'admin': admin, 
                          'date_of_birth': date_of_birth, 'address': address, 'phone_number': phone_number,
                          'name': name, 'surname': surname}

        try:
            user_data = self._db.users.find_one({'email': email}, allow_partial_results=False)
            if user_data:
                self.user_data['_id'] = user_data['_id']
        except:
            raise DBConnectionError
    
    @classmethod
    def find_by_id(cls, db:pymongo.database.Database, user_id:str):
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
                    contract_list=user_data["contract_list"], 
                    backup_codes=user_data["backup_codes"], 
                    security_questions=user_data["security_questions"], 
                    admin=user_data["admin"],
                    date_of_birth=user_data["date_of_birth"], 
                    address_plz=user_data["address"]["plz"],
                    address_street=user_data["address"]["street"], 
                    address_street_house_number=user_data["address"]["street_house_number"],
                    address_city=user_data["address"]["city"], 
                    address_country=user_data["address"]["country"], 
                    phone_number=user_data["phone_number"],
                    name=user_data["name"],
                    surname=user_data["surname"]) if user_data else None # Add here user attributes

    @classmethod 
    def find_by_username(cls, db:pymongo.database.Database, username: str):
        '''
        Returns the user with the given username.
        '''
        try:
            user_data = db.users.find_one({'username': username}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], 
                    twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], 
                    contract_list=user_data["contract_list"], backup_codes=user_data["backup_codes"], 
                    security_questions=user_data["security_questions"], admin=user_data["admin"], 
                    date_of_birth=user_data["date_of_birth"], address_plz=user_data["address"]["plz"],
                    address_street=user_data["address"]["street"], address_street_house_number=user_data["address"]["street_house_number"],
                    address_city=user_data["address"]["city"], address_country=user_data["address"]["country"],
                    phone_number=user_data["phone_number"], name=user_data["name"], surname=user_data["surname"]) if user_data else None # Add here user attributes
    
    @classmethod
    def find_by_email(cls, db:pymongo.database.Database, email: str):
        '''
        Returns the user with the given email.
        '''
        try:
            user_data = db.users.find_one({'email': email}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], 
                    twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], 
                    contract_list=user_data["contract_list"], backup_codes=user_data["backup_codes"], 
                    security_questions=user_data["security_questions"], admin=user_data["admin"],
                    date_of_birth=user_data["date_of_birth"], address_plz=user_data["address"]["plz"],
                    address_street=user_data["address"]["street"], address_street_house_number=user_data["address"]["street_house_number"],
                    address_city=user_data["address"]["city"], address_country=user_data["address"]["country"],
                    phone_number=user_data["phone_number"], name=user_data["name"], surname=user_data["surname"]) if user_data else None # Add here user attributes
    
    @classmethod
    def find_by_contract_id(cls, db:pymongo.database.Database, contract_id: str):
        '''
        Returns the user with the given contract_id.
        '''
        try:
            # Find user with contract_id in contract_list list
            user_data = db.users.find_one({'contract_list': { '$in': [str(contract_id)] }} , allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return User(db=db, email=user_data["email"], username=user_data["username"], password=user_data["password"], 
                    twofa_secret=user_data["twofa_secret"], twofa_activated=user_data["twofa_activated"], 
                    contract_list=user_data["contract_list"], backup_codes=user_data["backup_codes"], 
                    security_questions=user_data["security_questions"], admin=user_data["admin"],
                    date_of_birth=user_data["date_of_birth"], address_plz=user_data["address"]["plz"],
                    address_street=user_data["address"]["street"], address_street_house_number=user_data["address"]["street_house_number"],
                    address_city=user_data["address"]["city"], address_country=user_data["address"]["country"],
                    phone_number=user_data["phone_number"], name=user_data["name"], surname=user_data["surname"]) if user_data else None

    def __getitem__(self, key: str) -> str:
        return self.user_data[key]
    
    def __setitem__(self, key: str, value: str) -> None:
        if key in self.user_data:
            self.user_data[key] = value

            try:
                self._db.users.update_one({'_id': self.user_data['_id']}, {'$set': {key: value}})
            except:
                raise DBConnectionError
        else:
            raise AttributeError

    def get_id(self) -> str:
        return str(self.user_data['_id'])

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
        
    def update_address(self, attribute: str, value: str) -> None:
        '''
        Updates the address of the user.
        '''
        try:
            self.user_data['address'][attribute] = value
            self._db.users.update_one({'_id': self.user_data['_id']}, {'$set': {'address.' + attribute: value}})
        except:
            raise DBConnectionError

    def add_contract(self, contract_id: int) -> None: #Get the list of contracts and append the new one
        '''
        Adds a contract to the user.
        '''
        try:
            self.user_data['contract_list'] = self['contract_list'].append(contract_id)
            self._db.users.update_one({'_id': self.user_data['_id']}, {'$push': {'contract_list': contract_id}}) # update the contract list
        except:
            raise DBConnectionError
        
    def remove_contract(self, contract_id: int) -> None: #Get the list of contracts and remove the one
        '''
        Removes a contract from the user.
        '''
        try:
            self.user_data['contract_list'] = self['contract_list'].remove(contract_id)
            self._db.users.update_one({'_id': self.user_data['_id']}, {'$pull': {'contract_list': contract_id}}) # update the contract list
        except:
            raise DBConnectionError
        
        # Check if contract is removed
        try:
            user_data = self._db.users.find_one({'_id': self.user_data['_id']}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        if contract_id in user_data['contract_list']:
            logger.error(f"Contract with ID '{contract_id}' could not be removed from user with ID '{self.get_id()}'.")
        
    def add_security_question(self, question: str, answer: str) -> None:
        '''
        Adds a security question to the user.
        '''
        try:
            self.user_data['security_questions'][question] = answer
            self._db.users.update_one({'_id': self.user_data['_id']}, {'$set': {'security_questions.' + question: answer}})
        except:
            raise DBConnectionError

    def remove_security_question(self, question: str) -> None:
        '''
        Removes a security question from the user.
        '''
        try:
            self.user_data['security_questions'].pop(question)
            self._db.users.update_one({'_id': self.user_data['_id']}, {'$unset': {'security_questions.' + question: ""}})
        except:
            raise DBConnectionError
        
        # Check if security question is removed
        try:
            user_data = self._db.users.find_one({'_id': self.user_data['_id']}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        if question in user_data['security_questions']:
            logger.error(f"Security question with question '{question}' could not be removed from user with ID '{self.get_id()}'.")

    def save(self) -> None:
        '''
        Saves the user to the database.
        '''
        try:
            self._db.users.insert_one(self.user_data)

            user_data = self._db.users.find_one({'email': self.user_data["email"]}, allow_partial_results=False)
            self.user_data["_id"] = user_data["_id"]
        except:
            raise DBConnectionError
            
    def delete(self) -> None:
        '''
        Deletes the user from the database.
        '''
        try:
            self._db.users.delete_one({'_id': self.user_data['_id']})
        except:
            raise DBConnectionError
        
        # Check if user is deleted
        try:
            user_data = self._db.users.find_one({'_id': self.user_data['_id']}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        if user_data:
            logger.error(f"User with ID '{self.get_id()}' could not be deleted.")
        
        logger.debug(f"User with ID '{self.get_id()}' successfully deleted.")

        # Check if user has contracts and delete them
        for contract_id in self['contract_list']:
            contract = Contract.find_by_id(db=self._db, contract_id=contract_id)
            contract.delete(db=self._db)
            logger.debug(f"Contract with ID '{contract_id}' of user with ID '{self.get_id()}' successfully deleted.")