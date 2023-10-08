# ===== Packages =====
# Package for environment variables
import os
from dotenv import load_dotenv
load_dotenv()

# Packages for logging
import logging

# Packages for Flask
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# Packages for MongoDB
from flask_pymongo import pymongo
import urllib
from bson.objectid import ObjectId

# Packages for testing the .env file
from app.tests.unit import verify_env


# ===== Exception Classes =====
class DBConnectionError(Exception):
    "Raised when an error occures while connecting to the MongoDB"
    pass

class ConfigurationError(Exception):
    "Raised when an error occures on the configurations (.env)"
    pass

# ===== Getter and Setter =====


# ===== Program configs =====

# logger
def set_logger(logger:logging.Logger, format:logging.Formatter, log_level:str="DEBUG") -> logging.Logger:
    if log_level == 'ERROR':
        logger.setLevel(logging.ERROR)
    elif log_level == 'INFO':
        logger.setLevel(logging.INFO)
    elif log_level == 'WARNING':
        logger.setLevel(logging.WARNING)
    elif log_level == 'CRITICAL':
        logger.setLevel(logging.CRITICAL)
    elif log_level == 'DEBUG':
        logger.setLevel(logging.DEBUG)
    else:
        print('Log level couldnt be recognized given. Example: "INFO"')
        print('Defaulting to DEBUG logging.')
        logger.setLevel(logging.DEBUG)
    logging.basicConfig(filename='debug.log', filemode='w', encoding='utf-8', level=logger.level)
    logger.debug('###  Started Webanwendung  ###')
    return logger

# Establish logging
format = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s \n")
logger = logging.getLogger(__name__)

# set self.logger level
logger = set_logger(logger=logger, format=format, log_level="DEBUG")


# Test .env variables
expected_environment_variables = ["SECRET_KEY", "MONGODB_USER", "MONGODB_PW", "MONGODB_CLUSTER", "MONGODB_SUBDOMAIN"]

try:
    assert verify_env.verify_all(expected_environment_variables=expected_environment_variables) == True
    logger.info(".env file verified")
except:
    logger.error(".env file could not be verified")
    raise ConfigurationError

# Configure the flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# ===== Program start =====        

# MongoDB Atlas configuration and connection
try:
    client = pymongo.MongoClient("mongodb+srv://" + os.getenv("MONGODB_USER") + ":" + urllib.parse.quote_plus(os.getenv("MONGODB_PW")) + "@" + os.getenv("MONGODB_CLUSTER") + "." + os.getenv("MONGODB_SUBDOMAIN") + ".mongodb.net/?retryWrites=true&w=majority")
except Exception as e:
    logger.error("DB connection Error: ", e)
    raise DBConnectionError

logger.info("DB connection established")
db = client.get_database('webapp')

#TODO
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from app import routes