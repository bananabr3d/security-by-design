from app import DBConnectionError, logger
from bson.objectid import ObjectId
from flask_pymongo import pymongo

def load_contract(db: pymongo.database.Database, contract_id: str):
    try:
        contract_data = db.contracts.find_one({'_id': ObjectId(contract_id)}, allow_partial_results=False)
    except:
        raise DBConnectionError
    
    return Contract(db=db,
                     electricity_meter_id=contract_data["electricity_meter_id"],
                     startdate=contract_data["startdate"],
                     enddate=contract_data["enddate"],
                     renew_period=contract_data["renew_period"],
                     auto_renew=contract_data["auto_renew"],
                     notes = contract_data["notes"],
                     address_plz=contract_data["address"]["PLZ"],
                     address_street=contract_data["address"]["Street"],
                     address_street_number=contract_data["address"]["Street_Number"],
                     address_city=contract_data["address"]["City"],
                     address_country=contract_data["address"]["Country"]
                     ) if contract_data else None

def load_contract_data(user, db: pymongo.database.Database) -> list:
    contract_list = user.get_contract_list()
    contract_data_list = list()

    for contract_id in contract_list:
        # Load contract data using the load_contract function
        contract = load_contract(db, contract_id)
        if contract != None:
            contract_data_list.append(contract)
        else:
            logger.warning(f"The contract with the ID {contract_id} of the user {user.get_id()} could not be found.")                                    

    return contract_data_list

class Contract():
    def __init__(self, db: pymongo.database.Database, electricity_meter_id: int, startdate: str, enddate: str, renew_period: int, auto_renew: bool, notes:str, address_plz:str, address_street:str, address_street_number:str, address_city:str, address_country: str) -> None:
        self.contract_data = {"electricity_meter_id": electricity_meter_id, "startdate": startdate, "enddate": enddate, "renew_period": renew_period, "auto_renew": auto_renew, "notes": notes, "address": {"PLZ": address_plz, "Street": address_street, "Street_Number": address_street_number, "City": address_city, "Country": address_country}}

        try:
            contract_data = db.contracts.find_one({'electricity_meter_id': electricity_meter_id}, allow_partial_results=False)
            if contract_data:
                self.contract_data['_id'] = contract_data['_id']
        except:
            raise DBConnectionError

    def get_id(self) -> str:
        return str(self.contract_data['_id'])
    
    def get_attribute(self, attribute: str) -> str:
        return str(self.contract_data[attribute])
    
    def update_attribute(self, db: pymongo.database.Database, attribute: str, value: str) -> None:
        if self.get_attribute(attribute=attribute) != None: # Check if contract has the attribute
            try:
                db.contracts.update_one({'_id': self.user_data['_id']}, {'$set': {attribute: value}})
            except:
                raise DBConnectionError
    
    def find_contract_by_electricity_meter_id(db: pymongo.database.Database, electricity_meter_id: int):
        try:
            contract_data = db.contracts.find_one({'electricity_meter_id': electricity_meter_id}, allow_partial_results=False)
        except:
            raise DBConnectionError
        
        return Contract(db=db, electricity_meter_id=contract_data["electricity_meter_id"]) if contract_data else None

    def save(self, db: pymongo.database.Database) -> None:
        try:
            db.contracts.insert_one(self.contract_data)

            contract_data = db.contracts.find_one({'electricity_meter_id': self.contract_data["electricity_meter_id"]}, allow_partial_results=False)
            self.contract_data["_id"] = contract_data["_id"]
        except:
            raise DBConnectionError

    def delete(self, db: pymongo.database.Database) -> None:
        try:
            db.contracts.delete_one({'_id': self.contract_data["_id"]})
        except:
            raise DBConnectionError