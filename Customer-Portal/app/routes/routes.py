# Contributions by: Vitali Bier, Julian Flock
# Description: This file contains the regular routes of the web application.

# ===== Packages =====
# Packages for Flask
from flask import render_template, g, request, redirect, url_for, flash

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

# === Add user info ===
@app.route('/user-info/update', methods=['GET'])
@jwt_required()
def update_user_info():
    '''
    This function handles the updating of user information.
    '''
    # Check which information the user has already provided, provide in template
    user_information = g.user.get_all_key_values()
    user_information.pop('username')
    user_information.pop('email')
    user_information.pop('twofa_activated')
    user_information.pop('contract_list')
    user_information.pop('admin')

    # Now only the following keys shall be remaining: date_of_birth, address_plz, address_street, address_street_house_number, address_city, address_country, phone_number (and maybe more in the future)
    # Check which of these keys are None and add them to a list and remove them from user_information
    not_provided_information = list()
    remove_keys = list()

    for key in user_information:
        if user_information[key] == None:
            not_provided_information.append(key)
            remove_keys.append(key)
    
    for key in remove_keys:
        user_information.pop(key)

    return render_template('update_user_info.html', jwt_authenticated=g.jwt_authenticated, twofa_activated=g.twofa_activated, twofa_authenticated=g.twofa_authenticated, not_provided_information=not_provided_information, user_information=user_information)

@app.route('/user-info/update', methods=['POST'])
@jwt_required()
def update_user_info_post():
    '''
    This function handles the adding of user information.
    '''
    # Check which key value pairs came in the request, update user object accordingly and save
    request_data = request.form

    print(request_data)

    keys = list()

    # Check regex for each key value pair and if valid, add to list
    for key in request_data:
        if request_data[key] != '':
            if key == 'date_of_birth':
                # Check if date_of_birth is valid
                if not fullmatch(date_of_birth_regex, request_data[key]):
                    flash('Please enter a valid date of birth.', 'error')
                    return redirect(url_for('update_user_info'))
                
                # Check if date_of_birth is in the past
                if request_data[key] > datetime.now().strftime('%Y-%m-%d'):
                    flash('Please enter a date of birth in the past.', 'error')
                    return redirect(url_for('update_user_info'))
                
                # Check if date_of_birth is at least 18 years ago
                if datetime.now().year - int(request_data[key][0:4]) < 18:
                    flash('You must be at least 18 years old.', 'error')
                    return redirect(url_for('update_user_info'))
                
                # Check if date_of_birth is at most 120 years ago
                if datetime.now().year - int(request_data[key][0:4]) > 120:
                    flash('Please enter a valid date of birth.', 'error')
                    return redirect(url_for('update_user_info'))
                
                keys.append(key)

            elif key == 'address_plz':
                # Check if address_plz is valid
                if not fullmatch(address_plz_regex, request_data[key]):
                    flash('Please enter a valid postal code.', 'error')
                    return redirect(url_for('update_user_info'))
                
                keys.append(key)

            elif key == 'address_street':
                # Check if address_street is valid
                if not fullmatch(address_street_city_country_regex, request_data[key]):
                    flash('Please enter a valid street name.', 'error')
                    return redirect(url_for('update_user_info'))
                
                keys.append(key)
                
            elif key == 'address_street_house_number':
                # Check if address_street_house_number is valid
                if not fullmatch(address_street_house_number_regex, request_data[key]):
                    flash('Please enter a valid house number.', 'error')
                    return redirect(url_for('update_user_info'))
                
                keys.append(key)

            elif key == 'address_city':
                # Check if address_city is valid
                if not fullmatch(address_street_city_country_regex, request_data[key]):
                    flash('Please enter a valid city name.', 'error')
                    return redirect(url_for('update_user_info'))
                
                keys.append(key)

            elif key == 'address_country':
                # Check if address_country is valid
                if not fullmatch(address_street_city_country_regex, request_data[key]):
                    flash('Please enter a valid country name.', 'error')
                    return redirect(url_for('update_user_info'))
                
                keys.append(key)

            elif key == 'phone_number':
                # Check if phone_number is valid 
                if not fullmatch(phone_number_regex, request_data[key]):
                    flash('Please enter a valid phone number.', 'error')
                    return redirect(url_for('update_user_info'))
                
                keys.append(key)

            else:
                flash('An error occurred.', 'error')
                return redirect(url_for('update_user_info'))

    # Update user object
    for key in keys:
        g.user.update_attribute(db=db, attribute=key, value=request_data[key])

    flash('Your information has been updated successfully.', 'success')
    return redirect(url_for('update_user_info'))