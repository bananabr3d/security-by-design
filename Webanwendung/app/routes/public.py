from flask import request, render_template, redirect, url_for, flash
from app import app, bcrypt, logger
from app.models.user import User

#TODO: logger
@app.route('/')
def home():
    return render_template('public/home.html')

@app.route('/register', methods=['GET', 'POST']) # Add more details to user
def register():
    logger.debug("Incoming Request on /register with request method:", request.method)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {'username': username, 'password': hashed_password}
        user = User(user_data)
        user.save()
        flash('Your account has been created!', 'success')
        logger.debug("User Account has been created successfully")
        return redirect(url_for('login'))
    elif request.method =='GET':
        return render_template('../static/register.html')
    else:
        logger.warning("Request Warning, Method: On /register: " + request.method)

@app.route('/login', methods=['GET', 'POST']) # Add more details to user
def login():
    logger.debug("Incoming Request on /login with request method:", request.method)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {'username': username, 'password': hashed_password}
        user = User(user_data)
        user.save()
        flash('You have been logged in successfully!', 'success')
        logger.debug("User Account has logged in successfully")
        return redirect(url_for('home'))
    elif request.method =='GET':
        return render_template('../static/login.html')
    else:
        logger.warning("Request Warning, Method: On /login: " + request.method)
