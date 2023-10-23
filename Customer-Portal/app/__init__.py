# Contributions by: Vitali Bier, Julian Flock
# Description: This file is the main file of the web application. It contains the configuration of the Flask app, the MongoDB connection and the logger.
# Last update: 23.10.2023

# ===== Packages =====
# Packages for environment variables
import os
from dotenv import load_dotenv
load_dotenv()

# Packages for logging
import logging
from sys import stderr

# Packages for Flask
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager

# Packages for MongoDB
from flask_pymongo import pymongo
import urllib
from time import sleep

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

class UnknownRequest(Exception):
    "Raised when an unknown request is made"
    pass

# ===== Program configurations =====

# === Logger ===
# Set logger function
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
    consoleHandler = logging.StreamHandler(stderr)
    consoleHandler.setFormatter(format)
    logger.addHandler(consoleHandler)
    logger.debug('###  Started Webanwendung  ###')
    return logger

# Establish logging
format = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s \n")
logger = logging.getLogger(__name__)

# set logger with level from environment variable
logger = set_logger(logger=logger, format=format, log_level=os.getenv("LOGGING_LEVEL"))

# === Verify .env file ===
# Test .env variables
expected_environment_variables = ["SECRET_KEY", "JWT_SECRET_KEY", "MONGODB_USER", "MONGODB_PW", "MONGODB_CLUSTER", "MONGODB_SUBDOMAIN", "JWT_ACCESS_TOKEN_EXPIRATION_MINUTES", "2FA_EXPIRATION_MINUTES"]

try:
    assert verify_env.verify_all(expected_environment_variables=expected_environment_variables) == True
    logger.info(".env file verified")
except:
    logger.error(".env file could not be verified")
    raise ConfigurationError

# === Flask app configurations ===
app = Flask(__name__)

# Set secret keys for the app and the JWT Token
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") # Used for flashing messages
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY") # Used for the JWT Token

# Set JWT Token location and security
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True # If True: Only allow JWT cookies sent with https

# set cookie paths: Access Cookie
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'

# Enable CSRF Protection
app.config['JWT_COOKIE_CSRF_PROTECT'] = False #TODO try to do True -> error on post login/2fa
app.config['JWT_CSRF_IN_COOKIES'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True

# Cookie settings
app.config['JWT_COOKIE_SAMESITE'] = "Strict"

# Set cookie expiration
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES"))) # Set to 30min, afterwards the access_token is invalid.

jwt = JWTManager(app)

# ===== Program start =====        

# === MongoDB connection ===
def db_connection() -> pymongo.database.Database or None:
    # MongoDB Atlas configuration and test connection 
    try:
        client = pymongo.MongoClient("mongodb+srv://" + os.getenv("MONGODB_USER") + ":" + urllib.parse.quote_plus(os.getenv("MONGODB_PW")) + "@" + os.getenv("MONGODB_CLUSTER") + "." + os.getenv("MONGODB_SUBDOMAIN") + ".mongodb.net/?retryWrites=true&w=majority")
        db = client.get_database('webapp')

        db.db.test.find_one()

        return db
    except Exception as e:
        logger.debug("Error: " + str(e))
        return None

# Try to connect to the MongoDB 5 times with 5 seconds delay after a error
for i in range(5):
    try:
        db = db_connection()
        if db == None:
            raise DBConnectionError
        else:
            logger.info("DB connection established")
            break
    except:
        logger.error("DB connection Error. Try another " + str(5-i) + " times...")
        sleep(5)
        
    if i == 4:
        raise DBConnectionError

# Create Bcrypt object
bcrypt = Bcrypt(app)

# === Import routes ===
from app.routes import routes
from app.routes import contract_routes
from app.routes import auth_routes