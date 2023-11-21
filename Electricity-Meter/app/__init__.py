# Contributions by: Ellen Kistner, Vitali Bier
# Description: This file is the main file of the web application. It contains the configuration of the Flask app, the MongoDB connection and the logger.

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

# Packages for Electricity Meter configuration
from app.config import get_em_id, get_em_value, initialize, count
from threading import Timer
from requests import post

# ===== Program configurations =====

# === Logger ===
def set_logger(logger:logging.Logger, format:logging.Formatter, log_level:str="DEBUG") -> logging.Logger:
    '''
    This function sets the logger with the given log level and format.
    '''
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
    file_handler = logging.FileHandler('app.log')
    file_handler.setFormatter(format)
    logger.addHandler(consoleHandler)
    logger.addHandler(file_handler)
    logger.debug('###  Started Server  ###')
    return logger

# Establish logging
format = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s \n")
logger = logging.getLogger(__name__)

# set logger with level from environment variable
logger = set_logger(logger=logger, format=format, log_level=os.getenv("LOGGING_LEVEL"))

# === Flask app configurations ===
app = Flask(__name__)

# Set secret keys for the app and the JWT Token
app.config['SECRET_KEY'] = os.urandom(24)

# === EM Initialisation ===
if get_em_id() == None or get_em_value() == None: #TODO test
    initialize()

logger.debug(f"ID: {get_em_id()}")
logger.debug(f"Initialisation Value: {get_em_value()}")

def heartbeat():
    '''
    This function sends a heartbeat to the metering-point-operator every 10 seconds.
    '''
    logger.debug("Sending heartbeat...")
    logger.debug(f"Value: {get_em_value()}")
    #post("http://metering-point-operator:5000/api/heartbeat", json={"id": get_em_id(), "value": get_em_value(), "secret": os.getenv("SECRET_MPO_EM")}) TODO

    # Count up the value
    count()

    Timer(10, heartbeat).start() # Change time accordingly

heartbeat()