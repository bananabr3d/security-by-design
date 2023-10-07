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
security-by-design/
    ├── Anwendung/
    ├── Webanwendung/
        ├── app/
        |    ├── __init__.py
        |    ├── routes/
        |    |    ├── __init__.py
        |    |    ├── public.py
        |    |    ├── protected.py
        |    ├── models/
        |    |    ├── __init__.py
        |    |    ├── user.py
        |    ├── templates/
        |    ├── static/
        |    |    ├── ...
        |    ├── verification/
        |    |    ├── verify_env.py
        |    |    ├── ...
        ├── config.py
        ├── run.py
        ├── requirements.txt
        ├── .env
        ├── tests.py
        ├── Dockerfile


### Webpage Structure

http://coming.soon/
    ├── register/
    ├── login/
    ├── dashboard/
    |    ├── < electricity-meter-ID >/


## Installation and Usage
### Docker
The web-app and the app have been dockerized. Both of them can be deployed with the docker-compose.yml. Therefore it is important to edit the amount of deployed applications, as they represent the Electricity meter (a electricity meter is only available to add, if the application is deployed):

(Code representation will be added later)

### Register a user
In order to register a user you need the following information:
- username
- password
(- 2fa app)
(- birthday date)
(- gender)
(- ...)

With these information you can go to the website: "http://coming.soon/register" and register your user. Afterwards, you will be forwarded to the Login Page.

### Login as a user
In order to login with a user you need the following information:
- username
- password
(- 2fa)

With these information you can go to the website: "http://coming.soon/login" and login. Afterwards, you will be forwarded to the Dashboard.

### Dashboard
The Dasboard is a fully representation of your current Electricity Meters status and your energy consumption.

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

These have to be used in the expected places in order to get information about the program and to debug it in case.

Here are examples for establishing the logger and using it afterwards in the code:

Coming soon...

### Helpful Docs
For pymongo help:
https://pymongo.readthedocs.io/en/stable/api/pymongo/collection.html#pymongo.collection.Collection