from app import DBConnectionError


def load_user(db, em_id: str):
    try:
        em_data = db.electricity - meter.find_one({'em_id': ObjectId(em_id)}, allow_partial_results=False)
    except:
        raise DBConnectionError

    return ElectricityMeter(db=db, em_id=em_data['em_id'], em_value=em_data['em_value'],
                            em_last_update=em_data['em_last_update']) if user_data else None  # Add here user attributes


class ElectricityMeter:
    # constructor with me_id, me_value, me_status, me_error, me_last_update
    def __init__(self, db, em_id, em_value, em_status, em_error, em_last_update):
        self.db = db
        self.em_id = em_id
        self.em_value = em_value
        self.em_status = em_status
        self.em_error = em_error
        self.em_last_update = em_last_update

    def get_em_id(self):
        return self.em_id

    def get_db(self):
        return self.db

    def get_em_value(self):
        return self.em_value

    def get_em_status(self):
        return self.em_status

    def get_em_error(self):
        return self.em_error

    def get_em_last_update(self):
        return self.em_last_update

    def set_em_value(self, em_value):
        try:
            self.em_value = em_value
            db.users.update_one({'em_id': self.em_id}, {'$set': {'em_value': em_value}})
        except:
            DBConnectionError()

    def set_em_status(self, em_status):
        try:
            self.em_status = em_status
            db.users.update_one({'em_id': self.em_id}, {'$set': {'em_status': em_status}})
        except:
            DBConnectionError()

    def set_em_error(self, em_error):
        try:
            self.em_error = em_error
            db.users.update_one({'em_id': self.em_id}, {'$set': {'em_error': em_error}})
        except:
            DBConnectionError()

    def set_em_last_update(self, em_last_update):
        try:
            self.em_last_update = em_last_update
            db.users.update_one({'em_id': self.em_id}, {'$set': {'em_last_update': em_last_update}})
        except:
            DBConnectionError()

    def update_em_value(self, em_value):
        try:
            self.em_value = em_value
            db.users.update_one({'em_id': self.em_id}, {'$set': {'em_value': em_value}})
        except:
            DBConnectionError()

