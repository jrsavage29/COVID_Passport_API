#!usr/bin/env python3
import pymongo
from flask import Flask
from flask import abort
from flask import request
from flask import redirect
from flask import render_template
from flask import session
from flask import flash
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import requests
import json
import os

app = Flask(__name__)
#in order to use session to keep the client-side sessions secure
app.secret_key = os.urandom(16).hex()

#use the session user to get the current user using the system and access their information

#dictionary holding the users for the API
users = {
    "admin" : generate_password_hash("secret"),
}


@app.route('/', methods = ['GET', 'POST']) #enter correct credentials to enter site
def login():
    error = None

    if(request.method == 'POST'):

        if(request.form.get("facial login")):
            return redirect('/login-facial')

        elif(request.form.get("login")):
            username = request.form.get("user")
            password = request.form.get("passw")

            if username in users and check_password_hash(users.get(username), password):
                session["user"] = username
                flash('You were successfully logged in!')
                return redirect(f'/dashboard/{username}')
            else:
                error = 'Invalid username or password. Please try again!'

    return render_template('login.html', error = error)

@app.route('/login-facial', methods = ['POST', 'GET']) #if the user fails the facial, they get redirected to the main login page
def detect_face():
    return f"""<h1> Welcome to facial login!</h1> """

@app.route('/dashboard/<username>', methods = ['POST', 'GET']) #The main dashboard for after successfully logging in
def dashboard(username):
    if(not session.get('user')):
        return redirect('/')
        
    return render_template('dashboard.html', value = username)

@app.route('/newUser', methods = ['POST', 'GET']) #for creating a new account
def newUser():
    return "<h1> Create a new account </h1>"

@app.route('/passport-info/<username>', methods = ['POST', 'GET']) #for users to see their passport information
def display_info(username):
     return "<h1> Display users' passport information</h1>"

@app.route('/update', methods = ['POST', 'GET']) #for users to update their information and then return back to the dashboard
def update_info():
     return "<h1> Allow users to update information for passport </h1>"

@app.route('/register-facial', methods = ['POST', 'GET']) #register users' faces (User must have credentials first!)
def register_facial():
     return "<h1> Register new faces here </h1>"

@app.route('/covid-map', methods = ['POST', 'GET'])
def show_covid_stats():
     return "<h1>Display a live covid map here </h1>"




if __name__ == "__main__":
    app.run(host = 'localhost', port = 3000, debug = True)    
