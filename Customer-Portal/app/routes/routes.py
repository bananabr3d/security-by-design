# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import render_template, g

# Packages for JWT
from flask_jwt_extended import jwt_required

# Import app and db object from app package
from app import app, db, Invalid2FA, security_questions

# Import models
from app.models.contract import load_contract_data

# Import regex
from re import compile, fullmatch

# Import datetime
from datetime import datetime

# ===== Regex =====
# Regex for date_of_birth (YYYY-MM-DD)
date_of_birth_regex = compile(r'^\d{4}-\d{2}-\d{2}$')

# Regex for address_plz, address_street_house_number (5 digits)
address_plz_regex = compile(r'^\d{5}$')

# Regex for address_street, address_city, address_country (only letters, äöüÄÖÜß and spaces)
address_street_city_country_regex = compile(r'^[a-zA-ZäöüÄÖÜß ]+$')

# Regex for address_street_house_number (only digits, up to 5)
address_street_house_number_regex = compile(r'^\d{1,5}$')

# Regex for phone_number (e.g. +4915227515341, 015227515341) with a upper limit of 13 digits (china) after the + sign
phone_number_regex = compile(r'^\+?\d{6,13}$')

# ===== Routes =====

# === Home / Index ===
@app.route('/index', methods=['GET'])
@app.route('/home', methods=['GET'])
@app.route('/', methods=['GET'])
@jwt_required(optional=True) # optional=True allows to access the route without a valid JWT, but checks it if it is present
def home():
    '''
    This function handles the home page of the web application.
    '''
    return render_template('index.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated)

# === Dashboard ===
@app.route('/dashboard', methods=['GET'])
@jwt_required() # jwt_required() requires a valid JWT to access the route
def dashboard():
    '''
    This function handles the dashboard page of the web application.

    The JWT Token is required and the 2fa is checked. Then the dashboard page is displayed accordingly.
    '''
        
    if not g.twofa_authenticated:
        raise Invalid2FA
    
    # 1. load all contract objects of user
    contract_list = load_contract_data(g.user, db)

    transformed_contract_list = list()

    # Transform contract objects in list to dicts
    for contract in contract_list:
        temp_contract = {"_id": contract.get_id(), "electricity_meter_id": contract.get_attribute("electricity_meter_id")}#TODO: Add more attributes
        transformed_contract_list.append(temp_contract)

    # 2. make request on Messstellenbetreiber for data of each contract => How to implement? Do we load a contract.html in the dashboard.html or can we add it here in the return?
    
    #render_template with contract objects for each contract
    return render_template('dashboard.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated, admin=g.admin, username=g.user.get_attribute('username'), contract_list=transformed_contract_list)

# === About ===
@app.route('/about', methods=['GET'])
def about():
    '''
    This function handles the about page of the web application.
    '''
    return render_template('about.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated)

# === Impressum ===
@app.route('/impressum', methods=['GET'])
def impressum():
    '''
    This function handles the impressum page of the web application.
    '''
    return render_template('impressum.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated)