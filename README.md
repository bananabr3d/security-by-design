# security-by-design

## Introduction
Hi, and welcome!

In this project, we are going to create a Dashboard-Website with a user management in order to monitor and control the Electricity meter of a user. The Electricity meters are going to be simulated by another application.

The website and the application will be written in python. Therefore we use Flask for both and additionally MongoDB (+HTML, CSS (+Bootstrap), JS) for the website.

The group of 4 people will be devided in half in order to create both components:

Web-App:
- Vitali Bier
- Julian Flock

App:
- Ellen Kistner
- Andrey Dubilyer

Thereby is Vitali Bier the project leader.

### Ideas
In the Beginning, we decided on the chosen stack. But there were also other ideas, like the MERN Stack for the web-app, as we have collected a lot of experience with it, or a easy-to-use wordpress site. In the end, the python stack won for the usability, flexibility and our experience in its usage.

## Structure
### Folder Structure
```
security-by-design/
    ├── Anwendung/
    ├── Webanwendung/
        ├── app/
        |    ├── __init__.py
        |    ├── routes.py
        |    ├── models/
        |    |    ├── __init__.py
        |    |    ├── electricity_meter.py
        |    |    ├── user.py
        |    ├── templates/
        |    |    ├── ...
        |    ├── static/
        |    |    ├── style.css
        |    ├── verification/
        |    |    ├── verify_env.py
        |    |    ├── ...
        ├── run.py
        ├── requirements.txt
        ├── .env
        ├── Dockerfile
```

### Webpage Structure
```
http://coming.soon/
    ├── register/
    ├── login/
    ├── dashboard/
    |    ├── < electricity-meter-ID >/
```

## Installation and Usage
### Docker
The web-app and the app have been dockerized. Both of them can be deployed with the docker-compose.yml. Therefore it is important to edit the amount of deployed applications, as they represent the Electricity meter (a electricity meter is only available to add to a user, if the application is deployed):

(Code representation will be added later)

#### Build and run the containers

In order to then build and deploy the containers, you have to create a .env file in the following directory:

```
Webanwendung/app/.env
```

and with the following environment variables (values are examples):

```
SECRET_KEY=secret-key
    MONGODB_USER=user
    MONGODB_PW=password
    MONGODB_CLUSTER=cluster
    MONGODB_SUBDOMAIN=gc5y7mr
```

The keys are being used as a part of the uri as following:

```
mongodb+srv://<MONGODB_USER>:<MONGODB_PW>@<MONGODB_CLUSTER>.<MONGODB_SUBDOMAIN>.mongodb.net/?retryWrites=true&w=majority
```

Now the containers can be build with the following command executed in the root directory (and docker + docker-compose installed):

```
docker-compose build
```

Finally the containers can be started by:

```
docker-compose up
```

And the frontend of the web-app is visible on port 5000 (http://localhost:5000).

#### Debug with Logs
If the docker container does not work or has to be troubleshooted, the debug logs are in the docker container. As long as the docker container was not restartet, the logs are inspectable inside the docker container in the debug.log (in the root directory). The content can be displayed when executing "cat debug.log" inside the docker container cli.


### Register a user
In order to register a user you need the following information:
- username
- password
- (2fa app)
- (birthday date)
- (gender)
- (...)

With these information you can go to the website: "http://coming.soon/register" and register your user. Afterwards, you will be forwarded to the Login Page.

### Login as a user
In order to login with a user you need the following information:
- username
- password
- (2fa)

With these information you can go to the website: "http://coming.soon/login" and login. Afterwards, you will be forwarded to the Dashboard.

### Dashboard
The Dasboard is a fully representation of your current Electricity Meters status and your energy consumption. If you want to get into a more detailed overview or maintainance of a electricity meter you can click on it's ID.

Screenshots coming soon...

### Add a Electricity Meter to your Dashboard / Bind it to your user
Coming soon...

### Maintain your Electricity Meter
Coming soon...

## Coding Instructions
Logging will be managed by the python package "logging". Therefore there are 5 different logging levels defined:
- info
- warning
- critical
- error
- debug

These have to be used in the expected places in order to get information about the program and to debug it in case. The logs are going to be logged into the "debug.log" file. After restarting the application, the debug.log will be overwritten!

Here are examples for establishing the logger and using it afterwards in the code:

```python
# ===== Set Logger in the beginning =====
# (preferred in the __init__.py of the app folder)

# import logger
import logging

# set logger function
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

# Establish logger
format = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s \n")
logger = logging.getLogger(__name__)

# set self.logger (+level)
logger = set_logger(logger=logger, format=format, log_level="DEBUG")
```

```python
# ===== Using the logger in code =====

# import the logger from the app (module)
from app import logger

# If you want to use it inside functions:
def xyz(logger:logging.logger): # Here you have to import the logging module as well
    logger.info("xyz has been called") # info can be changed with the logging levels, mentioned above

# If you call the function, dont forget to give the logger to it as a parameter
xyz(logger=logger)

# If you dont call a function, you can simply use the logger as follows:
logger.info("i love logging <3")
```

### Swagger Documentation
A swagger documentation is available on each app in its directory.


### Web App HTTPS
https://stackoverflow.com/questions/29458548/can-you-add-https-functionality-to-a-python-flask-web-server
-> openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
into "Webanwendung" folder

### Helpful Docs
For pymongo help:
https://pymongo.readthedocs.io/en/stable/api/pymongo/collection.html#pymongo.collection.Collection