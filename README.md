# security-by-design

## Introduction
Hi, and welcome!

In this project, we are going to develop 3 components. The first one is a customer portal with a user management, where the customer can register and login. After that, he can add a contract with his electricity meter to his dashboard. In the dashboard, he can see his electricity meters and their current status. The customer portal also supports roles, so that a administrator has access to a special dashboard, where he can monitor the user activities, whitelist blocked IPs and active inactive users.

The second component is a metering point operator, which is responsible for the electricity meters. It can add electricity meters to its database and update their status. When the customer wants to add a contract to his dashboard, the metering point operator will be informed and checks if the electricity meter is available. If it is, the contract will be added to the dashboard.

The metering point operator also has a portal, where the technicians can login and maintain the electricity meters.

The third component is the electricity meter itself. It will send the current status of the electricity meter to the metering point operator and can be maintained by technicians.

#

The websites support 2FA (2 factor authentication) with TOTP (time-based one-time password) and the communication between the components is secured by a shared authentication secret and TLS. The customer and technician can visit the websites based on secure HTTPS connections.

The component backends will be written in python. Therefore we use Flask and additionally MongoDB for the database. The frontend will be designed by HTML, CSS (+Bootstrap) and JavaScript. The communication between the components will be done by REST APIs.

#

The group consists of 4 members, which are:

- Andrey Dubilyer
- Ellen Kistner
- Julian Flock
- Vitali Bier

And the project leader is **Vitali Bier**.

The responsibilities for each component are as follows:

Customer-Portal:
- Vitali Bier
- Julian Flock

Metering-Point-Operator & Electricity Meter:
- Ellen Kistner
- Andrey Dubilyer
- Vitali Bier

Authentication:
- Vitali Bier

### Ideas
In the Beginning, we decided on the chosen stack. But there were also other ideas, like the MERN Stack for the web-app, as we have collected a lot of experience with it, or a easy-to-use wordpress site. In the end, the python stack won for the usability, flexibility and our experience in its usage.

## Table of Contents
- [security-by-design](#security-by-design)
  - [Introduction](#introduction)
  - [Ideas](#ideas)
  - [Table of Contents](#table-of-contents)
  - [Structure](#structure)
    - [Folder Structure](#folder-structure)
    - [Website Structure](#website-structure)
  - [Installation and Usage](#installation-and-usage)
    - [Docker](#docker)
      - [Build and run the containers](#build-and-run-the-containers)
      - [Debug with Logs](#debug-with-logs)
    - [User manual](#user-manual)
      - [Register a user](#register-a-user)
      - [Login as a user](#login-as-a-user)
      - [Register your 2FA](#register-your-2fa)
      - [Login with your 2FA](#login-with-your-2fa)
      - [Dashboard](#dashboard)
      - [Add a Contract to your Dashboard / Bind it to your user](#add-a-contract-to-your-dashboard--bind-it-to-your-user)
    - [Technician Manual](#technician-manual)
      - [Maintain a Electricity Meter](#maintain-a-electricity-meter)
  - [Coding Instructions](#coding-instructions)
    - [Logging](#logging)
    - [Secure Coding Instructions](#secure-coding-instructions)
    - [Swagger Documentation](#swagger-documentation)
    - [Certificates](#certificates)
    - [Helpful Docs](#helpful-docs)

## Structure
### Folder Structure
```
security-by-design/
    ├── README.md
    ├── docker-compose.yml
    ├── docker-compose-localdb.yml
    ├── nginx.conf
    ├── pytest.ini
    ├── certs/
    |   ├── ssl-bundle.crt
    |   ├── ...
    ├── Metering-Point-Operator/
    |   ├── Dockerfile
    |   ├── requirements.txt
    |   ├── run.py
    |   ├── swagger.yaml
    |   ├── test_run_tests.py
    |   ├── app/
    |       ├── __init__.py
    |       ├── routes/
    |       |    ├── routes.py
    |       ├── models/
    |       |    ├── user.py
    |       ├── templates/
    |       |    ├── ...
    |       ├── static/
    |            ├── style.css
    |            ├── ...
    ├── Electricity-Meter/
    |   ├── Dockerfile
    |   ├── requirements.txt
    |   ├── run.py
    |   ├── swagger.yaml
    |   ├── test_run_tests.py
    |   ├── app/
    |       ├── __init__.py
    |       ├── routes.py
    ├── Customer-Portal/
        ├── Dockerfile
        ├── requirements.txt
        ├── run.py
        ├── swagger.yaml
        ├── test_run_tests.py
        ├── app/
        |    ├── __init__.py
        |    ├── routes/
        |    |    ├── routes.py
        |    |    ├── admin_routes.py
        |    |    ├── auth_routes.py
        |    |    ├── auth_routes_2fa.py
        |    |    ├── contract_routes.py
        |    |    ├── error_routes.py
        |    ├── models/
        |    |    ├── contract.py
        |    |    ├── user.py
        |    ├── templates/
        |    |    ├── ...
        |    ├── static/
        |    |    ├── style.css
        |    |    ├── ...
        |    ├── tests/
        |    |    ├── ...
```

### Website Structure
#TODO
```
https://voltwave.systems/
    ├── home/
    ├── index/
    ├── about/
    ├── impressum/
    ├── register/
    |    ├── 2fa/
    ├── login/
    |    ├── 2fa/
    ├── user-info
    ├── dashboard/
    |    ├── ...
https://systems.voltwave.systems/
    ├── home/
    ├── index/
    ├── about/
    ├── impressum/
    ├── register/
    |    ├── 2fa/
    ├── login/
    |    ├── 2fa/
    ├── dashboard/
    |    ├── ...
```

## Installation and Usage
### Docker
The 3 components are dockerized and can be deployed with the docker-compose.yml or docker-compose-localdb.yml file. Therefore it is important to edit the amount of deployed Electricity-Meter. (A electricity meter is only available to add to a user, if the em is deployed):

(Representation will be added later) #TODO

A nginx container is used as a reverse proxy and is also dockerized. It is used to redirect the traffic to the correct component. The nginx.conf file is used to configure the nginx container.

#### Build and run the containers

In order to build and deploy the docker containers, you have to create a .env file in the following directories:

```
Customer-Portal/app/.env
Metering-Point-Operator/app/.env
```

and with the following environment variables (values are examples):

```
SECRET_KEY=secret-key
JWT_SECRET_KEY=jwt-secret-key
MONGODB_USER=user
MONGODB_PW=password
MONGODB_CLUSTER=cluster    <-- Used in MongoDB Atlas
MONGODB_SUBDOMAIN=f3vvcc5  <-- Used in MongoDB Atlas
JWT_ACCESS_TOKEN_EXPIRATION_MINUTES=30
2FA_EXPIRATION_MINUTES=60
```

NOTE: Credentials

The credentials for the MongoDB have to be different for each component, as they are used to connect to different databases.

NOTE: MongoDB Atlas VS Local MongoDB

All keys are needed in order to launch the applications, but only the relevant ones are used.

#

As there are 2 versions on how to deploy this app (local MongoDB / MongoDB Atlas) the keys are used as a part of the uri as following:

```
Local MongoDB:
mongodb://<MONGODB_USER>:<MONGODB_PW>@mongodb:27017/

MongoDB Atlas:
mongodb+srv://<MONGODB_USER>:<MONGODB_PW>@<MONGODB_CLUSTER>.<MONGODB_SUBDOMAIN>.mongodb.net/?retryWrites=true&w=majority
```

If the local DB version is used, you also need a mongodb.env in the root directory (the same directory as the docker-compose.yml file) with the following content:

```
MONGO_INITDB_ROOT_USERNAME=user
MONGO_INITDB_ROOT_PASSWORD=password
```

#

For the certificates, you have to provide a ssl-bundle.crt (certificate, intermediate certificate and root certificate concatenated) and for the components a self signed certificate and key (cert.pem and key.pem). More informations about the certificates can be found in the Coding Instructions > Certificates.

#

Now the containers can be build with the following command executed in the root directory (and docker + docker-compose installed):

```
docker-compose -f docker-compose.yml build
or:
docker-compose -f docker-compose-localdb.yml build
```

Finally the containers can be started by:

```
docker-compose -f docker-compose.yml up
or:
docker-compose -f docker-compose-localdb.yml up
```

The websites will then be accessable at "https://127.0.0.1:443" and "https://127.0.0.1:8443".

#### Debug with Logs
If the docker container does not work or has to be troubleshooted, the debug logs are displayed in the docker container console in "stderr" and in the debug.log (in the root directory), too. As long as the docker container was not restartet, the logs are inspectable inside the docker container. The content can be displayed when executing "cat debug.log" inside the docker container cli or new content can be displayed continiously with "tail -F debug.log".


### User manual
#### Register a user
In order to register a user you need the following information:
- email-address
- username
- password
- (birthday date)
- (gender)
- (...)
#TODO

With these information you can go to the website: "https://voltwave.systems/register" and register your user. Afterwards, you will be forwarded to the Login Page.

#### Login as a user
In order to login with a user you need the following information:
- username
- password

With these information you can go to the website: "https://voltwave.systems/login" and login. Afterwards, you will be forwarded to the 2FA Registration Page.

#### Register your 2FA
On the 2FA Registration Page ("https://voltwave.systems/register/2fa") you will get displayed your 2FA secret. You can either scan the QR code with your 2FA app or copy the secret and paste it into your 2FA app. After that, you have to enter the 6 digit code, which is displayed in your 2FA app. If the code is correct, you will be forwarded to the 2FA Login Page.

#### Login with your 2FA
On the 2FA Login Page ("https://voltwave.systems/login/2fa") you have to enter the 6 digit code, which is displayed in your 2FA app. If the code is correct, you will be forwarded to the Dashboard.

#### Dashboard
The Dasboard is a fully representation of your current Electricity Meters status and your energy consumption. If you want to get into a more detailed overview of a electricity meter you can click on it's ID. Also you can see your contracts or add new ones to your dashboard.

Screenshots coming soon...
#TODO

#### User-info Page
On the User-info Page ("https://voltwave.systems/user-info") you can see your user information, like email, username and authentication status. You can also change your password, add security quesitons, reset your 2FA and delete your account.

#### Add a Contract to your Dashboard / Bind it to your user
Coming soon...
#TODO

### Technician Manual
Coming soon...
#TODO

#### Maintain a Electricity Meter
Coming soon...
#TODO

## Coding Instructions
### Logging
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

# Or you can import it directly from the app (module) and use it as follows:
from app import logger

# Then, you can simply use the logger as follows:
logger.info("i love logging <3")
```

### Secure Coding Instructions
In order to code securely, there are some rules to follow. These are:
- Implement Error and Exception Handling by using try-except blocks ("last resort error handling")
- Use the logging module for logging
- Use the python package "dotenv" for environment variables
- Document your code, your functions and your API endpoints
- Update your requirements.txt file after installing new packages and check for newer versions of the packages
- Check the needed imported packages, if they are really needed and only import the used functions and variables from them
- https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/assets/docs/OWASP_SCP_Quick_Reference_Guide_v21.pdf



### Swagger Documentation
A swagger documentation is available on each component in its directory.


### Certificates
For the websites, a ssl-bundle.crt (certificate, intermediate certificate and root certificate concatenated) is needed and for the components a self signed certificate and key (cert.pem and key.pem) are needed. The ssl-bundle.crt is used for the nginx container and the cert.pem and key.pem are used for the components. The self-signed certificates can be generated with the following command:

```
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```
https://stackoverflow.com/questions/29458548/can-you-add-https-functionality-to-a-python-flask-web-server

Then the cert.pem and key.pem have to be copied into the component directories and the ssl-bundle.crt into the certs directory.

### Helpful Docs
For pymongo help:
https://pymongo.readthedocs.io/en/stable/api/pymongo/collection.html#pymongo.collection.Collection