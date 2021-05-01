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
import random
import time
import string
import os
import smtplib
from email.message import EmailMessage
from pyzbar import pyzbar
import cv2
import pyqrcode
from PIL import Image

app = Flask(__name__)
# in order to use session to keep the client-side sessions secure
app.secret_key = os.urandom(16).hex()

# email address that will be the sender (has 2 step verification setup so requires app passwords on google)
# learn about this process https://www.youtube.com/watch?v=JRCJ6RtE3xU
email_address = 'jrsvt23@gmail.com'
# password for email was stored as an environment variable
email_pw = os.environ.get('jrsvt23_pw')
receiver_email = 'jamahl29@vt.edu'

# use the session user to get the current user using the system and access their information

# dictionary holding the users for the API
users = {
    "first": {"PW": generate_password_hash("secret"),
              "FN": "Bob",
              "MI": "I.",
              "LN": "Simpson",
              "DOB": "N/A",
              "Prod1": "Moderna",
              "DR1": "N/A",
              "Site1": "NRHC",
              "Prod2": "Moderna",
              "DR2": "N/A",
              "Site2": "NRHC",
              "Notes": "This is filler!",
              "QR": "randomstring"},
    "tempUser123": {"PW": generate_password_hash("pass123"),
                    "FN": "Roger",
                    "MI": "J.",
                    "LN": "Kirk",
                    "DOB": "N/A",
                    "Prod1": "Phizer",
                    "DR1": "N/A",
                    "Site1": "NRHC",
                    "Prod2": "Phizer",
                    "DR2": "N/A",
                    "Site2": "NRHC",
                    "Notes": "This is filler!",
                    "QR": "randomString2"},
}

# store the bytes version of QR code as the key and the users' information as the value

administrators = {
    "jamahl29": {"PW": generate_password_hash("jam123"),
                 "FN": "Jamahl",
                 "MI": "R.",
                 "LN": "Savage",
                 "DOB": "1999-01-29"},
    "chance7": {"PW": generate_password_hash("cha123"),
                "FN": "Chance",
                "MI": "R.",
                "LN": "Messer",
                "DOB": "N/A"}
}

# user database
userDB = pymongo.MongoClient().Users
# admin database
adminDB = pymongo.MongoClient().Admins


# used for deleting the qr code image in the /static folder
def delete_pngs():
    # change your path for different system
    folder_path = r'C:/Users/crmes/PycharmProjects/COVID_Passport_API-main/COVID_Passport_API-main/COVID API/static'
    
    test = os.listdir(folder_path)
    # taking a loop to remove all the images
    # using ".png" extension to remove only png images
    # using os.remove() method to remove the files
    for images in test:
        if images.endswith(".png"):
            os.remove(os.path.join(folder_path, images))


# used for generating the strings used to make QR codes
def random_string(length=15):
    character_set = string.ascii_letters
    generated_string = ''.join(random.choice(character_set) for i in range(length))
    # concatenate a time stamp to ensure string will always be unique
    time_stamp = str(time.time())

    return generated_string + time_stamp


def read_barcodes(frame):
    qr = pyzbar.decode(frame)
    QRText = ""
    for qr in qr:
        x, y, w, h = qr.rect
        QRText = qr.data.decode('utf-8')
        print(QRText)
        cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)

    return frame, QRText


def createUserQR(name):
    qr = pyqrcode.create(name)
    qr.png(f"static/{name}.png", scale=8)
    print('Created QR code')


def decodeUserQR(QRFile):
    data = pyzbar.decode(Image.open(QRFile))
    return data


def cameraReadQR():
    camera = cv2.VideoCapture(0)
    ret, frame = camera.read()
    text = ""
    while ret:
        ret, frame = camera.read()
        frame, text = read_barcodes(frame)
        cv2.imshow('Barcode reader', frame)
        # Get rid of text != "" to remove camera turning off after getting a QR code
        if (cv2.waitKey(1) == ord("q")) or text != "":
            break
    camera.release()
    cv2.destroyAllWindows()

    return text


# insert into the database
# need the database, the document, the user dictionary
def insertIntoDB(db, doc, userDict):
    for username in userDict:
        # check if the ID already exists
        if db[doc].count_documents({"_id": username}) == 0:
            # create a unique ID
            userDict[username]['_id'] = username
            db[doc].insert_one(userDict[username])


# update a current user in the database
# need the database, the document, the user dictionary, and the user to update
def updateUserDB(db, doc, userDict, userToUpdate):
    db[doc].replace_one({"_id": userToUpdate}, userDict[userToUpdate])


# remove a user from the database
# need the database, the document, and the user to remove
def deleteFromDB(db, doc, userToRemove):
    db[doc].delete_one({"_id": userToRemove})


# enter correct credentials to enter site
@app.route('/', methodss=['GET', 'POST'])
def login():
    error = None

    if not session.get('user'):
        if request.method == 'POST':
            if request.form.get("QR login"):
                return redirect('/login-QR')
            elif request.form.get("General Email"):
                return redirect('/get-help/')
            elif request.form.get("login"):
                username = request.form.get("user")
                password = request.form.get("passw")
                if username in users and check_password_hash(users.get(username).get("PW"), password):
                    session["user"] = username
                    flash('You were successfully logged in!')
                    return redirect(f'/user-dashboard/{username}')
                elif username in administrators and check_password_hash(administrators.get(username).get("PW"), password):
                    session["user"] = username
                    flash('You were successfully logged in!')
                    return redirect(f'/admin-dashboard/')
                else:
                    error = 'Invalid username or password. Please try again!'
    else:
        if 'user' in session and session['user'] in administrators.keys():
            return redirect(f'/admin-dashboard/')
        elif 'user' in session and session['user'] in users.keys():
            username = session['user']
            return redirect(f'/user-dashboard/{username}')

    return render_template('login.html', error=error)


# User can choose to be redirected back to the login screen if they no longer want to scan QR code
@app.route('/login-QR', methods=['POST', 'GET'])
def detect_QR():
    error = None
    # flash message when Qr is detected
    # send error when Qr code is wrong
    if request.method == 'POST':
        readString = cameraReadQR()
        print(readString)
        for username in users:
            if users[username]["QR"] == readString:
                flash("Your QR Code was successfully scanned!")
                return redirect(f"/display-passport/{username}")
            else:
                error = "Your QR code is either invalid or couldn't be read properly!"

    return render_template('scan_qr.html', error=error)


# If user passed the qr code scanner, their passport is displayed
@app.route('/display-passport/<username>', methods=['POST', 'GET'])
def display_users_QR(username):
    user_info = users[username]
    # have option to return back to login screen
    if request.method == 'POST':
        return redirect('/')

    return render_template('display_qr_passport.html', user_info=user_info, username=username)


# The main dashboard for after successfully logging in
@app.route('/user-dashboard/<username>', methods=['POST', 'GET'])
def dashboard(username):
    # dashboard will also show current covid statistics
    # statistics thanks to the following article:
    # https://medium.com/analytics-vidhya/novel-coronavirus-covid-19-tracker-app-using-flask-1fd08dc314b6
    if not session.get('user'):
        return redirect('/')

    covid_data_content = requests.get("https://corona.lmao.ninja/v2/all")
    covid_data = covid_data_content.json()
    cases = "{:,}".format(covid_data['cases'])
    recovered = "{:,}".format(covid_data['recovered'])
    deceased = "{:,}".format(covid_data['deaths'])

    return render_template('dashboard.html', username=username, cases=cases, recovered=recovered, deceased=deceased)
    

# The main dashboard for after successfully logging in (for admins)
@app.route('/admin-dashboard/', methods=['POST', 'GET'])
def admin_dashboard():
    # displays all admins and current users
    if not session.get('user'):
        return redirect('/')

    return render_template('admin_dashboard.html', users=users, admins=administrators)


# for creating a new account with an associated QR code (Only admins can do this)
@app.route('/admin-add-user/', methods=['POST', 'GET'])
def newUser():
    error = None
    success = None

    if not session.get('user'):
        return redirect('/')
    # Prevent duplicate usernames. Throw error if so.
    if request.method == 'POST':
        if request.form.get("add"):
            # if the admin selected for the new account to be made into an admin account
            if request.form.get("MakeAdmin") and request.form.get("new_user") not in administrators:
                new_user = request.form.get("new_user")
                new_admin_dict_entry = {"PW": generate_password_hash(request.form.get("new_passw")),
                                        "FN": request.form.get("fname"),
                                        "MI": request.form.get("mi"),
                                        "LN": request.form.get("lname"),
                                        "DOB": request.form.get("dob"), }
                administrators[new_user] = new_admin_dict_entry
                success = f"Successfully added admin {new_user} to the service!"
                insertIntoDB(adminDB, "Info", administrators)
            # else the account will be made as a regular user account
            elif not request.form.get("MakeAdmin") and request.form.get("new_user") not in users:
                new_user = request.form.get("new_user")
                new_user_dict_entry = {"PW": generate_password_hash(request.form.get("new_passw")),
                                       "FN": request.form.get("fname"),
                                       "MI": request.form.get("mi"),
                                       "LN": request.form.get("lname"),
                                       "DOB": request.form.get("dob"),
                                       "Prod1": request.form.get("dosename1"),
                                       "DR1": request.form.get("dr1"),
                                       "Site1": request.form.get("site1"),
                                       "Prod2": request.form.get("dosename2"),
                                       "DR2": request.form.get("dr2"),
                                       "Site2": request.form.get("site2"),
                                       "Notes": request.form.get("notes"),
                                       "QR": random_string(), }
                users[new_user] = new_user_dict_entry
                success = f"Successfully added user {new_user} to the service!"
                insertIntoDB(userDB, "Info", users)
            else:
                error = 'That user already exists! Try using a different username.'

    return render_template('admin_new_user.html', error=error, success=success)


# for users to see their passport information while logged in
@app.route('/passport-info/<username>', methods=['POST', 'GET'])
def display_info(username):
    if not session.get('user'):
        return redirect('/')

    return render_template('check_passport.html', username=username, user_info=users[username])


# for users to see their passport information
@app.route('/change-password/<username>', methods=['POST', 'GET'])
def change_password(username):
    # if old password doesn't match before assigning new password then send an error
    # if new password is the same as the old password, then send error about it
    error = None
    success = None

    if not session.get('user'):
        return redirect('/')

    if request.method == 'POST':
        old_pass = request.form.get("oldPW")
        new_pass = request.form.get("newPW")
        # Make sure the user typed in their correct current password
        if check_password_hash(users.get(username).get("PW"), old_pass):
            if not request.form.get("newPW"):
                error = "You Did Not Enter A New Password!"
            elif old_pass == new_pass:
                error = "Your new password can not be the same as your old password!"
            else:
                new_pass = generate_password_hash(new_pass)
                users[username]["PW"] = new_pass
                success = "Your password has been changed successfully!"
                updateUserDB(userDB, "Info", users, username)
        # else they must have incorrectly typed in their current password
        else:
            error = "Your old password does not match what is in the system!"

    return render_template('new_password.html', username=username, error=error, success=success)


# for admin to update a user's information
@app.route('/admin-update/', methods=['POST', 'GET'])
def update_info():
    error = None
    success = None
    # if admin updates username then go ahead and delete the old user but copy the data over
    if not session.get('user'):
        return redirect('/')
    
    if request.method == 'POST':
        query_user = request.form.get("query_user")
        # updating info for an admin
        if request.form.get("updateAdmin"):
            if query_user in administrators and query_user != "jamahl29":
                if request.form.get("fname"):
                    administrators[query_user]["FN"] = request.form.get("fname")
                if request.form.get("mi"):
                    administrators[query_user]["MI"] = request.form.get("mi")
                if request.form.get("lname"):
                    administrators[query_user]["LN"] = request.form.get("lname")
                if request.form.get("dob"):
                    administrators[query_user]["DOB"] = request.form.get("dob")
                if request.form.get("new_passw"):
                    administrators[query_user]["PW"] = generate_password_hash(request.form.get("new_passw"))
                success = f"Admin {query_user} has had their information updated!"
                updateUserDB(adminDB, "Info", administrators, query_user)
            elif query_user in administrators and query_user == "jamahl29":
                error = f"You can not edit the head admin {query_user}!"
            else:
                error = f"Admin {query_user} is not in this system!"
        # else updating info regular user
        else:
            if query_user in users:
                if request.form.get("fname"):
                    users[query_user]["FN"] = request.form.get("fname")
                if request.form.get("mi"):
                    users[query_user]["MI"] = request.form.get("mi")
                if request.form.get("lname"):
                    users[query_user]["LN"] = request.form.get("lname")
                if request.form.get("dob"):
                    users[query_user]["DOB"] = request.form.get("dob")
                if request.form.get("new_passw"):
                    users[query_user]["PW"] = generate_password_hash(request.form.get("new_passw"))
                if request.form.get("dosename1"):
                    users[query_user]["Prod1"] = request.form.get("dosename1")
                if request.form.get("dr1"):
                    users[query_user]["DR1"] = request.form.get("dr1")
                if request.form.get("site1"):
                    users[query_user]["Site1"] = request.form.get("site1")
                if request.form.get("dosename2"):
                    users[query_user]["Prod2"] = request.form.get("dosename2")
                if request.form.get("dr2"):
                    users[query_user]["DR2"] = request.form.get("dr2")
                if request.form.get("site2"):
                    users[query_user]["Site2"] = request.form.get("site2")
                if request.form.get("notes"):
                    users[query_user]["Notes"] = request.form.get("notes")
                success = f"User {query_user} has had their information updated!"
                updateUserDB(userDB, "Info", users, query_user)
            else:
                error = f"User {query_user} is not in this system!"

    return render_template('admin_update_user.html', error=error, success=success)


# for admins to delete a user from the system
@app.route('/admin-delete/', methods=['POST', 'GET'])
def delete_user():
    error = None
    success = None
    # if admin deletes themselves, make sure to pop session user as well so they go back to the login page
    if not session.get('user'):
        return redirect('/')

    if request.method == 'POST':
        query_user = request.form.get("query_user")
        # deleting an admin
        if request.form.get("deleteAdmin"):
            # You can not delete Admin jamahl29 under any circumstance
            if query_user == "jamahl29":
                error = f"You can not delete the head admin {query_user}!"
            # if the admin is not deleting themselves from the system
            elif query_user in administrators and query_user != session.get('user'):
                administrators.pop(query_user)
                success = f"Admin {query_user} was successfully deleted."
                deleteFromDB(adminDB, "Info", query_user)
            # the admin is deleting themself from the system
            elif query_user in administrators and query_user == session.get('user'):
                administrators.pop(query_user)
                session.pop('user')
                success = f"Admin {query_user} was successfully deleted."
                deleteFromDB(adminDB, "Info", query_user)
            else:
                error = f"Admin {query_user} is not in this system!"
        # else deleting normal user
        else:
            if query_user in users:
                users.pop(query_user)
                success = f"User {query_user} was successfully deleted."
                deleteFromDB(userDB, "Info", query_user)
            else:
                error = f"User {query_user} is not in this system!"

    return render_template('admin_delete_user.html', error=error, success=success)


# for admins to search for a user
@app.route('/admin-search/', methods=['POST', 'GET'])
def search_user():
    error = None
    # send error if user not found
    if not session.get('user'):
        return redirect('/')

    if request.method == 'POST':
        query_user = request.form.get("query_user")
        # searching an admin
        if request.form.get("searchAdmin"):
            if query_user in administrators:
                flash(f'Results found for admin {query_user}!')
                return redirect(f'/admin-search-results/{query_user}')
            else:
                error = f"Admin {query_user} Does not exist in this system!"
            
        # else searching regular users
        else:
            if query_user in users:
                flash(f'Results found for user {query_user}!')
                return redirect(f'/admin-search-results/{query_user}')
            else:
                error = f"User {query_user} does not exist in this system!"

    return render_template('admin_search_users.html', error=error)


# for admins to display search results in the system
@app.route('/admin-search-results/<username>', methods=['POST', 'GET'])
def search_user_results(username):
    # results = None
    is_admin = False

    # if user presses Go Back button, redirect back to admin-search
    if not session.get('user'):
        return redirect('/')
    
    if request.method == 'POST':
        if request.form.get("go back"):
            return redirect("/admin-search/")

    if username in users:
        results = users[username]
    else:
        results = administrators[username]
        is_admin = True

    return render_template('admin_display_search_results.html', user_info=results, username=username, is_admin=is_admin)


# register users' new QR code (User must have credentials first!)
@app.route('/generate-new-QR/<username>', methods=['POST', 'GET'])
def new_QR(username):
    # qr_img = None

    if not session.get('user'):
        return redirect('/')

    if request.method == 'POST':
        flash("New QR code was successfully generated!")
        # generate new string and store in the user's dictionary of information
        users[username]["QR"] = random_string()
        return redirect(f'/display-new-QR/{username}')

    # created a new userQR.png file with the relevant QR code
    createUserQR(users[username]["QR"])
    filename = users[username]["QR"]
    qr_img = f"/static/{filename}.png"

    return render_template('generate_qr.html', username=username, qr_img=qr_img)


# displays users' new QR code after registering new QR code
@app.route('/display-new-QR/<username>', methods=['POST', 'GET'])
def display_new_QR(username):
    # qr_img = None

    if not session.get('user'):
        return redirect('/')

    # display the newly generated qr code
    createUserQR(users[username]["QR"])
    filename = users[username]["QR"]
    qr_img = f"/static/{filename}.png"

    return render_template('display_new_qr.html', username=username, qr_img=qr_img)


# Users can send an email to the admin
@app.route('/send-issue/<username>', methods=['POST', 'GET'])
def user_send_email(username):
    success = None
    error = None

    if not session.get('user'):
        return redirect('/')

    if request.method == 'POST':
        # check that the user entered in all of the required fields
        if request.form.get("email") and request.form.get("msg"):
            first_name = users[username]["FN"]
            last_name = users[username]["LN"]
            email = request.form.get("email")
            msg = request.form.get("msg")
            email_message = EmailMessage()
            email_message['Subject'] = f'Query from Help Page from username \"{username}\"'
            email_message['From'] = email_address
            email_message['To'] = receiver_email
            email_message.set_content(f"First Name: {first_name} \nLast Name: {last_name} \nTheir Email Address: {email} \n\nMessage: \n{msg}")
            # using flask-mail to send the email to jrsvt23@gmail.com
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(email_address, email_pw)
                smtp.send_message(email_message)
            success = "Your email has been sent to the admins successfully! We will respond shortly."
        # send error about user not filling in all required fields
        else:
            error = "One or more of the mandatory fields are not filled!"

    return render_template('send_issue.html', username=username, error=error, success=success)


# Users can send an email to the admin
@app.route('/get-help/', methods=['POST', 'GET'])
def send_help_email():
    success = None
    error = None

    if request.method == 'POST':
        # check that the user entered in all of the required fields
        if request.form.get("fname") and request.form.get("lname") and request.form.get("email") and request.form.get("msg"):
            first_name = request.form.get("fname")
            last_name = request.form.get("lname")
            email = request.form.get("email")
            msg = request.form.get("msg")
            # username = ""

            # check if the user entered in their user (This is optional)
            if request.form.get("user"):
                username = request.form.get("user")
            else:
                username = "Not Applicable"
            
            email_message = EmailMessage()
            email_message['Subject'] = f'Message from Send Issue Page from username \"{username}\"'
            email_message['From'] = email_address
            email_message['To'] = receiver_email
            email_message.set_content(f"First Name: {first_name} \nLast Name: {last_name} \nTheir Email Address: {email} \n\nMessage: \n{msg}")

            # using flask-mail to send the email to jrsvt23@gmail.com
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(email_address, email_pw)
                
                smtp.send_message(email_message)

            success = "Your email has been sent to the admins successfully! We will respond shortly."

        # send error about user not filling in all required fields
        else:
            error = "One or more of the mandatory fields are not filled!"

    return render_template('get_help.html', success=success, error=error)


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    delete_pngs()
    session.pop('user') 
    return render_template('logout.html')


if __name__ == "__main__":
    app.run(host='localhost', port=3000, debug=True)
