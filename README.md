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


## Installation and Usage
### Docker
The web-app and the app have been dockerized. Both of them can be deployed with the docker-compose.yml. Therefore it is important to edit the amount of deployed applications, as they represent the Electricity meter (mapping: 1 user has 1 electricity meter):

(Code representation will be added later)

### Register a user
Coming soon...

### Dashboard
Coming soon...

## Helpful Docs
For pymongo help:
https://pymongo.readthedocs.io/en/stable/api/pymongo/collection.html#pymongo.collection.Collection