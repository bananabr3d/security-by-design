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
#from flask_login import LoginManager #TODO
from flask_jwt_extended import JWTManager

# Packages for MongoDB
from flask_pymongo import pymongo
import urllib
from bson.objectid import ObjectId

# Packages for testing the .env file
from app.tests.unit import verify_env

# For cookie expiration handling
from datetime import timedelta


# ===== Exception Classes =====
class DBConnectionError(Exception):
    "Raised when an error occures while connecting to the MongoDB"
    pass

class ConfigurationError(Exception):
    "Raised when an error occures on the configurations (.env)"
    pass

class UserAlreadyExists(Exception):
    "Raised when an user provides a username that is already in the database"
    pass

class WrongPassword(Exception):
    "Raised when an user provides a wrong password to its username during the login"
    pass

class DifferentPasswords(Exception):
    "Raised when an user provides different passwords during the registration"
    pass

class WrongElectricityMeterID(Exception):
    "Raised when a user provides a electricity meter ID that is not available in the DB"
    pass



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

# Online Mode is the default mode, offline cuts the connection to the MongoDB and then only basic functionality is enabled.
offline_mode = False

try:
    assert verify_env.verify_all(expected_environment_variables=expected_environment_variables) == True
    logger.info(".env file verified")
except:
    logger.error(".env file could not be verified")
    logger.info("Offline Mode activated...")
    offline_mode = True
    #raise ConfigurationError

# Configure the flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") # not used?
app.config['JWT_SECRET_KEY'] = os.getenv("SECRET_KEY")

app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False #Only allow JWT cookies sent with https

app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']# , 'refresh']

# set cookie paths: Refresh and Access Cookies
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'

# Enable CSRF Protection
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_CSRF_CHECK_FORM'] = True

# Set cookie expiration
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
#app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)

# ===== Program start =====        

# MongoDB Atlas configuration and 
if not offline_mode:
    try:
        client = pymongo.MongoClient("mongodb+srv://" + os.getenv("MONGODB_USER") + ":" + urllib.parse.quote_plus(os.getenv("MONGODB_PW")) + "@" + os.getenv("MONGODB_CLUSTER") + "." + os.getenv("MONGODB_SUBDOMAIN") + ".mongodb.net/?retryWrites=true&w=majority")
        logger.info("DB connection established")
        db = client.get_database('webapp')
    except Exception as e:
        logger.error("DB connection Error: ", e)
        raise DBConnectionError
else:
    db = 1


bcrypt = Bcrypt(app)

from app.routes import routes
from app.routes import contract_routes
from app.routes import auth_routes