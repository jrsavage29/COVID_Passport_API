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
    "first" : {"PW" : generate_password_hash("secret"), 
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
                "Notes" : "This is filler!",
                "QR" : "N/A"},
    "tempUser123" : {"PW" : generate_password_hash("pass123"), 
                "FN" : "Roger", 
                "MI" : "J.",
                "LN" : "Kirk",
                "DOB" : "N/A",
                "Prod1" : "Phizer",
                "DR1" : "N/A",
                "Site1" : "NRHC",
                "Prod2" : "Phizer",
                "DR2" : "N/A",
                "Site2" : "NRHC",
                "Notes" : "This is filler!",
                "QR" : "N/A"},
}

#store the bytes version of QR code as the key and the users' information as the value

QRs = {
    "randomqrstring" : {}

}

administrators = {
    "jamahl29" : {"PW":generate_password_hash("jam123"),
                "FN" : "Jamahl", 
                "MI" : "R.",
                "LN" : "Savage",
                "DOB" : "N/A"},
    "chance7" : {"PW":generate_password_hash("cha123"),
                "FN" : "Chance", 
                "MI" : "N.",
                "LN" : "Messer",
                "DOB" : "N/A"}
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
                elif(username in administrators and check_password_hash(administrators.get(username).get("PW"), password)):
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

    return render_template('display_qr_passport.html', QRs = QRs)

@app.route('/user-dashboard/<username>', methods = ['POST', 'GET']) #The main dashboard for after successfully logging in
def dashboard(username):
    #dashboard will also show current covid statistics
    if(not session.get('user')):
        return redirect('/')
    
    return render_template('dashboard.html', username = username)
    

@app.route('/admin-dashboard/', methods = ['POST', 'GET']) #The main dashboard for after successfully logging in (for admins)
def admin_dashboard():
    #displays all admins and current users
    if(not session.get('user')):
        return redirect('/')
    return render_template('admin_dashboard.html', users = users, admins = administrators)
    

@app.route('/admin-add-user/', methods = ['POST', 'GET']) #for creating a new account with an associated QR code (Only admins can do this)
def newUser():

    error = None
    success = None
    if(not session.get('user')):
        return redirect('/')
    #Prevent duplicate usernames. Throw error if so.
    if(request.method == 'POST'):
        if(request.form.get("add")):

            #if the admin selected for the new account to be made into an admin account
            if(request.form.get("MakeAdmin") and request.form.get("new_user") not in administrators):
                new_user = request.form.get("new_user")
                new_admin_dict_entry = {"PW": generate_password_hash(request.form.get("new_passw")),
                                        "FN" : request.form.get("fname"),
                                        "MI" : request.form.get("mi"),
                                        "LN" : request.form.get("lname"),
                                        "DOB" : request.form.get("dob"),}

                administrators[new_user] = new_admin_dict_entry
                success = f"Successfully Added Admin {new_user} To The Service!"

            #else the account will be made as a regular user account
            elif(not request.form.get("MakeAdmin") and request.form.get("new_user") not in users):
                new_user = request.form.get("new_user")
                new_user_dict_entry = {"PW": generate_password_hash(request.form.get("new_passw")),
                                        "FN" : request.form.get("fname"),
                                        "MI" : request.form.get("mi"),
                                        "LN" : request.form.get("lname"),
                                        "DOB" : request.form.get("dob"),
                                        "Prod1" : request.form.get("dosename1"),
                                        "DR1" : request.form.get("dr1"),
                                        "Site1" : request.form.get("site1"),
                                        "Prod2" : request.form.get("dosename2"),
                                        "DR2" : request.form.get("dr2"),
                                        "Site2" : request.form.get("site2"),
                                        "Notes" : request.form.get("notes"),
                                        "QR" : "insert QR generator function",}

                users[new_user] = new_user_dict_entry
                success = f"Successfully Added User {new_user} To The Service!"

            else:
                error = 'That user already exists! Try using a different username.'

    return render_template('admin_new_user.html', error = error, success = success)

@app.route('/passport-info/<username>', methods = ['POST', 'GET']) #for users to see their passport information while logged in
def display_info(username):
    if(not session.get('user')):
        return redirect('/')

    return render_template('check_passport.html', username = username, user_info = users[username])

@app.route('/change-password/<username>', methods = ['POST', 'GET']) #for users to see their passport information
def change_password(username):
    #if old password doesn't match before assigning new password then send an error
    #if new password is the same as the old password, then send error about it
    error = None

    if(not session.get('user')):
        return redirect('/')

    return render_template('new_password.html', username = username, error = error )

@app.route('/admin-update/', methods = ['POST', 'GET']) #for admin to update a user's information
def update_info():
    error = None
    success = None
    #if admin updates username then go ahead and delete the old user but copy the data over 
    if(not session.get('user')):
        return redirect('/')
    
    if(request.method == 'POST'):
        query_user = request.form.get("query_user")
        #updating info for an admin
        if(request.form.get("updateAdmin")):
            if( query_user in administrators):
                if(request.form.get("fname")):
                    administrators[query_user]["FN"] = request.form.get("fname")

                if(request.form.get("mi")):
                    administrators[query_user]["MI"] = request.form.get("mi")

                if(request.form.get("lname")):
                    administrators[query_user]["LN"] = request.form.get("lname")

                if(request.form.get("dob")):
                    administrators[query_user]["DOB"] = request.form.get("dob")

                if(request.form.get("new_passw")):
                    administrators[query_user]["PW"] = generate_password_hash(request.form.get("new_passw"))

                success = f"Admin {query_user} Has Had Their Information Updated!"
            else:
                error = f"Admin {query_user} Is Not In This System!"

        #else updating info regular user
        else:
            if(query_user in users):

                if(request.form.get("fname")):
                    users[query_user]["FN"] = request.form.get("fname")

                if(request.form.get("mi")):
                    users[query_user]["MI"] = request.form.get("mi")

                if(request.form.get("lname")):
                    users[query_user]["LN"] = request.form.get("lname")

                if(request.form.get("dob")):
                    users[query_user]["DOB"] = request.form.get("dob")

                if(request.form.get("new_passw")):
                    users[query_user]["PW"] = generate_password_hash(request.form.get("new_passw"))

                if(request.form.get("dosename1")):
                    users[query_user]["Prod1"] = request.form.get("dosename1")

                if(request.form.get("dr1")):
                    users[query_user]["DR1"] = request.form.get("dr1")

                if(request.form.get("site1")):
                    users[query_user]["Site1"] = request.form.get("site1")

                if(request.form.get("dosename2")):
                    users[query_user]["Prod2"] = request.form.get("dosename2")

                if(request.form.get("dr2")):
                    users[query_user]["DR2"] = request.form.get("dr2")

                if(request.form.get("site2")):
                    users[query_user]["Site2"] = request.form.get("site2")

                if(request.form.get("notes")):
                    users[query_user]["Notes"] = request.form.get("notes")
                    
                success = f"User {query_user} Has Had Their Information Updated!"
            
            else:
               error = f"User {query_user} Is Not In This System!" 

    return render_template('admin_update_user.html', error = error, success = success)

@app.route('/admin-delete/', methods = ['POST', 'GET']) #for admins to delete a user from the system
def delete_user():
    #if admin deletes themselves, make sure to pop session user as well so they go back to the login page
    if(not session.get('user')):
        return redirect('/')
    if(request.method == 'POST'):
        pass

    return render_template('admin_delete_user.html')

@app.route('/admin-search/', methods = ['POST', 'GET']) #for admins to search for a user 
def search_user():
    error = None
    #send error if user not found
    if(not session.get('user')):
        return redirect('/')

    return render_template('admin_search_users.html', error = error)

@app.route('/admin-search-results/{username}', methods = ['POST', 'GET']) #for admins to display search results in the system
def search_user_results(username):
    results = None
    #if user presses Go Back button, redirect back to admin-search
    if(not session.get('user')):
        return redirect('/')

    return render_template('admin_display_search_results.html', results = results)

@app.route('/generate-new-QR/<username>', methods = ['POST', 'GET']) #register users' new QR code (User must have credentials first!)
def new_QR(username):
    if(not session.get('user')):
        return redirect('/')

    return render_template('generate_qr.html', username = username)

@app.route('/display-new-QR/<username>', methods = ['POST', 'GET']) #displays users' new QR code after registering new QR code
def display_new_QR(username):
    if(not session.get('user')):
        return redirect('/')

    return render_template('display_new_qr.html', username = username)

@app.route('/send-issue/<username>', methods = ['POST', 'GET']) #Users can send an email to the admin
def user_send_email(username):
    msg = None

    if(not session.get('user')):
        return redirect('/')
    
    return render_template('send_issue.html', username = username, msg = msg)

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
