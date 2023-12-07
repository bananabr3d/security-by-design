# Contributions by: Andrey Dubilyer, Ellen Kistner
# Description: This file contains the regular routes of the web application.


from app import DBConnectionError, logger
from bson.objectid import ObjectId


def load_electricity_meter(db, em_id: str):
    try:
        em_data = db.electricity_meter.find_one({'_id': ObjectId(em_id)}, allow_partial_results=False)
        logger.info(em_data)
    except:
        raise DBConnectionError

    return ElectricityMeter(db=db, em_id=em_data['_id'], em_value=em_data['em_value'], em_status=em_data['em_status'],
                            em_error=em_data['em_error'],
                            em_last_update=em_data['em_last_update'], em_manufacturer=em_data['em_manufacturer'],
                            em_model=em_data['em_model'], em_firmware_version=em_data['em_firmware_version'],
                            em_serial_number=em_data[
                                'em_serial_number'],
                            em_maintain=em_data['em_maintain'],
                            em_ip=em_data['em_ip']) if em_data else None  # Add here user attributes


def em_exists(db, em_id):
    try:
        em_data = db.electricity_meter.find_one({'_id': ObjectId(em_id)}, allow_partial_results=False)
    except:
        raise DBConnectionError

    return True if em_data else False


class ElectricityMeter:
    # constructor with me_id, me_value, me_status, me_error, me_last_update
    def __init__(self, db, em_id, em_value, em_status, em_error, em_last_update, em_manufacturer, em_model,
                 em_serial_number, em_firmware_version, em_maintain, em_ip):
        self.db = db
        self.em_id = em_id
        self.em_value = em_value
        self.em_status = em_status
        self.em_error = em_error
        self.em_last_update = em_last_update
        self.em_manufacturer = em_manufacturer
        self.em_model = em_model
        self.em_serial_number = em_serial_number
        self.em_firmware_version = em_firmware_version
        self.em_maintain = em_maintain
        self.em_ip = em_ip

    def save(self, db) -> None:
        try:
            db.electricity_meter.insert_one({'_id': self.em_id, 'em_value': self.em_value, 'em_status': self.em_status,
                                             'em_error': self.em_error, 'em_last_update': self.em_last_update,
                                             'em_manufacturer': self.em_manufacturer, 'em_model': self.em_model,
                                             'em_serial_number': self.em_serial_number,
                                             'em_firmware_version': self.em_firmware_version,
                                             'em_maintain': self.em_maintain, 'em_ip': self.em_ip})
        except:
            DBConnectionError()

    def get_em_maintain(self):
        return self.em_maintain

    def get_em_id(self):
        return self.em_id

    def get_db(self):
        return self.db

    def get_em_value(self):
        return self.em_value

    def isfree(self, db, ):
        self.em_status = db.electricity_meter.find_one({'_id': ObjectId(self.em_id)})['em_status']
        return self.em_status

    def get_em_error(self):
        return self.em_error

    def get_em_last_update(self):
        return self.em_last_update

    def set_em_value(self, em_value):
        try:
            self.em_value = em_value
            self.db.users.update_one({'_id': self.em_id}, {'$set': {'em_value': em_value}})
        except:
            DBConnectionError()

    def set_em_status(self, em_status):
        try:
            self.em_status = em_status
            self.db.users.update_one({'_id': self.em_id}, {'$set': {'em_status': em_status}})
        except:
            DBConnectionError()

    def set_em_error(self, em_error):
        try:
            self.em_error = em_error
            self.db.users.update_one({'_id': self.em_id}, {'$set': {'em_error': em_error}})
        except:
            DBConnectionError()

    def set_em_last_update(self, em_last_update):
        try:
            self.em_last_update = em_last_update
            self.db.users.update_one({'_id': self.em_id}, {'$set': {'em_last_update': em_last_update}})
        except:
            DBConnectionError()

    def update_em_value(self, em_value):
        try:
            self.em_value = em_value
            self.db.users.update_one({'_id': self.em_id}, {'$set': {'em_value': em_value}})
        except:
            DBConnectionError()

    def toggle_maintain(self):
        if self.em_maintain:
            self.em_maintain = False
            self.db.users.update_one({'_id': self.em_id}, {'$set': {'em_maintain': False}})
        else:  # if not self.em_maintain
            self.em_maintain = True
            self.db.users.update_one({'_id': self.em_id}, {'$set': {'em_maintain': True}})
