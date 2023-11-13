from flask import Flask

import os
from time import sleep

import logging


from urllib.parse import quote_plus
from flask_pymongo import pymongo

app = Flask(__name__)

class DBConnectionError(Exception):
    pass

#logger
#format = logging.Formatter('%(asctime)s [%(levelnamename)-5.5s] - %(message)s')
logger = logging.getLogger(__name__)


def db_conn() -> pymongo.database.Database or None:

    try:
       if os.getenv('LOCALDB') == 'True':
            logger.info('Metering-Point-Operator: Connencting to local DB')
            client = pymongo. MongoClient(f"mongodb://{os.getenv('MONGODB_USER')}:{quote_plus(os.getenv('MONGODB_PW'))}@mongodb:27018" )
       else:
           return None

       db = client.get_database('webapp')

       db.db.test.findone()


    except Exception as e:
        logger.debug(f'Error: {e}')


for i in range(3):
    try:
        db = db_conn()
        if db == None:
            raise DBConnectionError
        else:
            logger.info('DB connection established')
            break
    except:
        logger.error(f'DB Connection Error. Try {i+1} of 3')
        sleep(5)
    if i == 3:
        raise DBConnectionError