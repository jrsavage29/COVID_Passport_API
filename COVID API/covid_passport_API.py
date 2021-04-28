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
    "admin" : {"PW" : generate_password_hash("secret"), 
                "FN" : "Bob", 
                "MI" : "I.",
                "LN" : "Simpson",
                "DOB" : "N/A",
                "Prod1" : "Moderna",
                "DR1" : "N/A",
                "Site1" : "NRHC",
                "Prod2" : "Moderna",
                "DR2" : "N/A",
                "Site2" : "NRHC",
                "Notes" : "This is filler!"},
}

administrators = {
    "Jamahl" : generate_password_hash("Secret")
}


@app.route('/', methods = ['GET', 'POST']) #enter correct credentials to enter site
def login():
    error = None

    if(not session.get('user')):
        if(request.method == 'POST'):

            if(request.form.get("QR login")):
                return redirect('/login-QR')
            
            elif(request.form.get("General Email")):
                return redirect('/get-help/')

            elif(request.form.get("login")):
                username = request.form.get("user")
                password = request.form.get("passw")

                if (username in users and check_password_hash(users.get(username).get("PW"), password)):
                    session["user"] = username
                    flash('You were successfully logged in!')
                    return redirect(f'/user-dashboard/{username}')
                elif(username in administrators and check_password_hash(administrators.get(username), password)):
                    session["user"] = username
                    flash('You were successfully logged in!')
                    return redirect(f'/admin-dashboard/')
                else:
                    error = 'Invalid username or password. Please try again!'

        return render_template('login.html', error = error)
    else:
        if('user' in session and session['user'] in administrators.keys()):
            return redirect(f'/admin-dashboard/')

        elif('user' in session and session['user'] in users.keys()):
            username = session['user']
            return redirect(f'/user-dashboard/{username}')


@app.route('/login-QR', methods = ['POST', 'GET']) #User can choose to be redirected back to the login screen if they no longer want to scan QR code
def detect_QR():
    error = None
    #flash message when Qr is detected
    #send error when Qr code is wrong
    return render_template('scan_qr.html', error = error)

@app.route('/display-passport', methods = ['POST', 'GET'])#If user passed the qr code scanner, their passport is displayed
def display_users_QR():
    #have option to return back to login screen
    return render_template('display_qr_passport.html', value = "Temp User")

@app.route('/user-dashboard/<username>', methods = ['POST', 'GET']) #The main dashboard for after successfully logging in
def dashboard(username):
    #dashboard will also show current covid statistics
    if(not session.get('user')):
        return redirect('/')
    
    return render_template('dashboard.html', value = username)
    

@app.route('/admin-dashboard/', methods = ['POST', 'GET']) #The main dashboard for after successfully logging in (for admins)
def admin_dashboard():
    
    if(not session.get('user')):
        return redirect('/')
    return render_template('admin_dashboard.html')
    

@app.route('/admin-add-user/', methods = ['POST', 'GET']) #for creating a new account with an associated QR code (Only admins can do this)
def newUser():
    if(not session.get('user')):
        return redirect('/')

    return render_template('admin_new_user.html')

@app.route('/passport-info/<username>', methods = ['POST', 'GET']) #for users to see their passport information while logged in
def display_info(username):
    if(not session.get('user')):
        return redirect('/')

    return render_template('check_passport.html', value = username)

@app.route('/change-password/<username>', methods = ['POST', 'GET']) #for users to see their passport information
def change_password(username):
    #if old password doesn't match before assigning new password then send an error
    #if new password is the same as the old password, then send error about it
    error = None

    if(not session.get('user')):
        return redirect('/')

    return render_template('new_password.html', value = username, error = error )

@app.route('/admin-update/', methods = ['POST', 'GET']) #for admin to update a user's information
def update_info():
    #if admin updates username then go ahead and delete the old user but copy the data over 
    if(not session.get('user')):
        return redirect('/')

    return render_template('admin_update_user.html')

@app.route('/admin-delete/', methods = ['POST', 'GET']) #for admins to delete a user from the system
def delete_user():
    if(not session.get('user')):
        return redirect('/')

    return render_template('admin_delete_user.html')

@app.route('/admin-search/', methods = ['POST', 'GET']) #for admins to search for a user and display them in the system
def search_user():
    error = None
    #send error if user not found
    if(not session.get('user')):
        return redirect('/')

    return render_template('admin_search_users.html', error = error)


@app.route('/new-QR/<username>', methods = ['POST', 'GET']) #register users' new QR code (User must have credentials first!)
def new_QR(username):
    if(not session.get('user')):
        return redirect('/')

    return render_template('generate_qr.html', value = username)

@app.route('/send-issue/<username>', methods = ['POST', 'GET']) #Users can send an email to the admin
def user_send_email(username):
    msg = None

    if(not session.get('user')):
        return redirect('/')
    
    return render_template('send_issue.html', value = username, msg = msg)

@app.route('/get-help/', methods = ['POST', 'GET']) #Users can send an email to the admin
def send_help_email():
    msg = None
    
    return render_template('get_help.html', msg = msg)


@app.route('/logout', methods = ['POST', 'GET'])
def logout():
    session.pop('user') 
    return render_template('logout.html')




if __name__ == "__main__":
    app.run(host = 'localhost', port = 3000, debug = True)    
