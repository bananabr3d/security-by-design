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
from threading import Timer
from requests import post
from random import randint
from bson.objectid import ObjectId
from hashlib import sha256

# ===== Global Variables =====

sleep = False

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

em_id = ObjectId()
em_value = randint(0,50000)

maintenance_mode = False

manufacturer_list = ["EMH-metering", "EasyMeter", "eBZ", "Zwawe"]
manufacturer = manufacturer_list[randint(0, len(manufacturer_list) - 1)]
model = f"{randint(1, 9)}.{randint(0, 9)}.{randint(0, 9)}.{randint(0, 9)}"
serial_number = f"{randint(10000000, 99999999)}-{randint(10000000, 99999999)}-{randint(10000000, 99999999)}"
firmware_version = f"{randint(1, 9)}.{randint(0, 9)}.{randint(0, 9)}"

# ===== Functions =====
def get_em_id() -> ObjectId:
    '''
    This function returns the ID of the electricity meter.
    '''
    return em_id

def get_manufacturer() -> str:
    '''
    This function returns the manufacturer of the electricity meter.
    '''
    return manufacturer

def get_model() -> str:
    '''
    This function returns the model of the electricity meter.
    '''
    return model

def get_serial_number() -> str:
    '''
    This function returns the serial number of the electricity meter.
    '''
    return serial_number

def get_firmware_version() -> str:
    '''
    This function returns the firmware version of the electricity meter.
    '''
    return firmware_version

def get_em_value() -> int:
    '''
    This function returns the value of the electricity meter.
    '''
    return em_value

def set_em_value(value:int) -> None:
    '''
    This function sets the value of the electricity meter.
    '''
    global em_value
    em_value = value

logger.info(f"ID: {get_em_id()}")
logger.debug(f"Initialisation Value: {get_em_value()}")





def heartbeat():
    '''
    This function sends a heartbeat to the metering-point-operator every 10 seconds.
    '''
    # Check if maintenance mode is active, if so, check again in 10 seconds
    if maintenance_mode:
        Timer(10, heartbeat).start()
        return
    
    # Count up the em_value
    set_em_value(get_em_value() + randint(11, 33)) # Change value accordingly

    logger.info("Sending heartbeat...")
    logger.debug(f"Value: {get_em_value()}")
    # Build sha256 hash of the secret ("SECRET_MPO_EM")
    h = sha256()
    h.update(os.getenv("SECRET_MPO_EM").encode("utf-8"))
    # Send the heartbeat to the metering-point-operator
    global sleep
    if not sleep:
        post(f"http://metering-point-operator:5000/api/heartbeat/{get_em_id()}", json={"em_value": get_em_value(),
                                                                                       "manufacturer": get_manufacturer(),
                                                                                       "model": get_model(),
                                                                                       "serial_number": get_serial_number(),
                                                                                       "firmware_version": get_firmware_version()},
             headers={"Authorization": h.hexdigest()})
    else:
        logger.info("electricity_meter is sleeping...")

    Timer(10, heartbeat).start() # Change time accordingly

heartbeat()