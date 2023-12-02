



class ElectricityMeter:
    #constructor with me_id, me_value, me_status, me_error, me_last_update
    def __init__(self, me_id, me_value, me_status, me_error, me_last_update):
        self.me_id = me_id
        self.me_value = me_value
        self.me_status = me_status
        self.me_error = me_error
        self.me_last_update = me_last_update
    def get_me_id(self):
        return self.me_id