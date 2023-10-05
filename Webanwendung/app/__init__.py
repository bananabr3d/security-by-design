# ===== Packages =====
# Package for environment variables
import os
from dotenv import dotenv_values, load_dotenv

# Packages for Flask
from flask import Flask
#from flask_bcrypt import Bcrypt
#from flask_login import LoginManager

# Packages for MongoDB
from flask_pymongo import pymongo
import urllib
from bson.objectid import ObjectId

# ===== Program start =====

# Configure the dotenv environment variables
#config = dotenv_values(".env")
load_dotenv()

# Configure the flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# MongoDB Atlas configuration
#app.config['MONGO_URI'] = config["MONGODB_URI"]
client = pymongo.MongoClient("mongodb+srv://" + os.getenv("MONGODB_USER") + ":" + urllib.parse.quote_plus(os.getenv("MONGODB_PW")) + "@" + os.getenv("MONGODB_CLUSTER") + ".f3vvcc5.mongodb.net/?retryWrites=true&w=majority")
db = client.get_database('webapp')

#user_collection = pymongo.collection.Collection(db, 'users')
#db.users.insert_one({"name": "John"})
client.drop_database("webapp")


#bcrypt = Bcrypt(app)
#login_manager = LoginManager(app)
#login_manager.login_view = 'login'

#from app import routes