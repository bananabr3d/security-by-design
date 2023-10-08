from flask import request, render_template, redirect, url_for, flash
from app import app, logger, db, bcrypt, WrongPassword, DifferentPasswords
from app.models.user import User


@app.route('/')
def home():
    logger.info("Get-Request: Starting Page displayed")
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST']) # Add more details to user
def register():
    logger.debug("Incoming Request on /register with request method:" + request.method)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        if password != password2:
            logger.warning("Different passwords provided during the registration")
            logger.debug("User: " + username + "provided different passwords during the registration")
            raise DifferentPasswords
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {'username': username, 'password': hashed_password}
        user = User(user_data)
        user.save(db)
        flash('Your account has been created!', 'success')
        logger.debug("User Account has been created successfully")
        return redirect(url_for('login'))
    elif request.method =='GET':
        return render_template('register.html')

@app.route('/login', methods=['GET', 'POST']) # Add more details to user
def login():
    logger.debug("Incoming Request on /login with request method:" + request.method)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = 1 # temporarly
        try:
            assert bcrypt.check_password_hash(password_hash, password).decode('utf-8') == True #TODO
        except:
            logger.warning("Wrong username/password combination provided")
            logger.debug("User: " + username + "provided a wrong password during the login")
            raise WrongPassword
        #TODO login the user, give him a jwt token
        flash('You have been logged in successfully!', 'success')
        logger.debug("User Account has logged in successfully")
        return redirect(url_for('dashboard'))
    elif request.method =='GET':
        return render_template('login.html')


# => Flask_jwt-extended
# https://flask-jwt-extended.readthedocs.io/en/stable/optional_endpoints.html