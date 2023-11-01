from app import logger
from flask_login import UserMixin
from bson.objectid import ObjectId

#TODO: logger, db commands, more information about contract
def load_contract(db, contract_id):
    return Contract(db.db.contracts.find_one({'_id': ObjectId(contract_id)}))

def load_contract_data(user, db):
    # Implement the logic to load contract data for the user
    contract_list = user.get_attribute("contracts")
    contract_data = []

    for contract_id in contract_list:
        # Load contract data using the load_contract function
        contract = load_contract(db, contract_id)
        contract_data.append({
            '_id': contract.get_id(),
            'electricity_meter_id': contract.contract_data.get('electricity_meter_id'),
            # Add more contract data fields 
        })

    return contract_data

class Contract(UserMixin): # Add more details to user
    def __init__(self, contract_data) -> None:
        self.contract_data = contract_data

    def get_id(self) -> str:
        return str(self.contract_data['_id'])

    def save(self, db) -> None:
        db.db.contracts.insert_one(self.contract_data)

    # def remove(self, db) -> None:

    # Define other user-related methods here

    @classmethod
    def create_contract(cls, electricity_meter_id: int): #TODO add more here
        contract_data = {'electricity_meter_id': electricity_meter_id}
        return cls(contract_data)

    # Define other class methods as needed
