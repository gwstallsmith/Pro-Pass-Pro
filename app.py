from flask import Flask, render_template, send_from_directory, request, make_response, redirect, url_for
import sqlite3
import string
import random

from crypto import *
from utils import *

app = Flask(__name__)

# Loads images
@app.route('/get_img/<filename>')
def get_img(filename):
    return send_from_directory('assets', filename)

@app.route('/', methods=['GET'])
def index_page():
    response = make_response(render_template('index.html', error = None))
    return response

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html', error = None)

@app.route('/check_credentials', methods=['GET', 'POST'])
def check_credentials():
    error = None
    if request.method == 'POST':
        input_username = request.form['username']
        input_password = request.form['password']
        
        with sqlite3.connect("db.sqlite3") as connection:

            cursor = connection.cursor()

            cursor.execute("SELECT * FROM Credentials WHERE Username = ? AND Password = ?", (input_username, hash_password(input_password)))
    
            result = cursor.fetchone()
            
        if result:
            # Simulate a successful login
            user = result
            # Store user information in a cookie
            response = make_response(render_template('index.html', user=user, logged_in=True))

            response.set_cookie('ID', str(user[0]))
            response.set_cookie('Username', str(user[1]))

            # Generate symmetric key with user passowrd on login
            generate_shared_secret(input_password)

            return response
        else:
            # Simulate an incorrect login
            error = "Invalid user credentials."
        
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    # Clear the cookies by creating a response and deleting the cookies
    response = make_response(redirect(url_for('index_page')))  # Redirect to home page
    response.set_cookie('ID', '', expires = 0)  # Clear 'ID' cookie
    response.set_cookie('Username', '', expires = 0)  # Clear 'Username' cookie
    return response


@app.route('/sign_up')
def sign_up_form():
    return render_template('sign_up.html')
        
@app.route('/sign_up', methods=['POST'])
def sign_up():
    sign_up_form()

    new_username = request.form['username']
    new_password = request.form['password']

    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM Credentials WHERE Username = ? AND Password = ?", (new_username, hash_password(new_password)))

        result = cursor.fetchone()

        # When the user signing up exists in db
        if result:
            # Simulate a successful login
            # Store user information in a cookie
            response = make_response(render_template('index.html', user=result, logged_in=True))

            response.set_cookie('ID', str(result[0]))
            response.set_cookie('Username', str(result[1]))
            generate_shared_secret(new_password)


        # Otherwise user does not exist
        # Need to sign them up
        else:
            # Input new user into database
            cursor.execute("SELECT MAX(ID) FROM Credentials")
            new_ID = cursor.fetchone()[0] + 1
            
            cursor.execute("INSERT INTO Credentials (ID, Username, Password, IsAdmin) VALUES (?, ?, ?, ?)", (new_ID, new_username, hash_password(new_password), False))

            user = cursor.execute("SELECT * FROM Credentials WHERE ID = ?", (new_ID,)).fetchone()

            response = make_response(render_template('index.html', user=result, logged_in=True))

            response.set_cookie('ID', str(user[0]))
            response.set_cookie('Username', str(user[1]))

            generate_shared_secret(new_password)

        
        return response
    

@app.route('/passwords', methods=['GET', 'POST'])
def display_info():
    # Check if 'ID' and 'Username' cookies are present

    if 'ID' in request.cookies and 'Username' in request.cookies:
        user_id = request.cookies.get('ID')

        with sqlite3.connect("db.sqlite3") as connection:
            cursor = connection.cursor()

            # Check if the user is an admin (you might have a column like 'IsAdmin' in your Credentials table)
            cursor.execute("SELECT * FROM Credentials WHERE ID = ?", (user_id,))
            user = cursor.fetchone()

            if user and user[3]:
                # User is an admin, display all users
                all_users = cursor.execute("SELECT * FROM Passwords ORDER BY ID").fetchall()
                return render_template('passwords.html', users = all_users)
            else:
                # User is not an admin, display single user
                user_data = cursor.execute("SELECT * FROM Passwords WHERE ID = ?", (user_id,)).fetchall()

                if not user_data:
                    return render_template('passwords.html')
                
            user_data_decrypt = []
            for row in user_data:
                try:
                    decrypted_values = [decrypt(value) for value in row[1:]]
                    user_data_decrypt.append(decrypted_values)

                except:
                    return render_template('login.html', error = "Shared secret expired.")

            return render_template('passwords.html', user = user_data_decrypt)
    else:
        # If cookies are not present, redirect to login page or handle the situation accordingly
        return redirect('/login')

# Function to add password or edit existing password
@app.route('/store_password', methods=['GET', 'POST'])
def store_passwords():
    error = None

    user_id = request.cookies.get('ID')
    site_name = request.form['siteName']
    url = request.form['url']
    new_password = request.form.get('newPassword')

    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()
            
        user_data = cursor.execute("SELECT SiteName, url FROM Passwords WHERE ID = ?", (user_id,)).fetchall()
        entry_exists = None

        try:
            for encrypted_data in user_data:
                if decrypt(encrypted_data[0]) == site_name and decrypt(encrypted_data[1]) == url:
                    entry_exists = cursor.execute("SELECT * FROM Passwords WHERE ID = ? AND SiteName = ? AND url == ?", (user_id, encrypted_data[0], encrypted_data[1])).fetchone()
        except:
            return render_template('login.html', error = "Shared secret expired.")
                
        # If an entry exists with the same site data we need to update, not store a new password
        if entry_exists:
            error = "Site and password already exist. Updating password."
            try:
                cursor.execute("UPDATE Passwords SET Password = ? WHERE ID = ? AND SiteName = ? AND url = ?", (encrypt(new_password), user_id, entry_exists[1], entry_exists[2]))
            except:
                return render_template('login.html', error = "Shared secret expired")

            user_data = cursor.execute("SELECT * FROM Passwords WHERE ID = ?", (user_id,)).fetchall()

            user_data_decrypt = []
            for row in user_data:
                try:
                    decrypted_values = [decrypt(value) for value in row[1:]]
                    user_data_decrypt.append(decrypted_values)

                except:
                    return render_template('login.html', error = "Shared secret expired.")
                
            print(user_data_decrypt)

            return render_template('passwords.html', user = user_data_decrypt, error=error)

        # If the entry is not found, we need to add a new password
        else:
            try:
                cursor.execute("INSERT INTO Passwords (ID, SiteName, url, Password) VALUES (?, ?, ?, ?)", (user_id, encrypt(site_name), encrypt(url), encrypt(new_password)))
            except:
                return render_template('login.html', error = "Shared secret expired.")
            
            user_data = cursor.execute("SELECT * FROM Passwords WHERE ID = ?", (user_id,)).fetchall()


            user_data_decrypt = []
            for row in user_data:
                try:
                    decrypted_values = [decrypt(value) for value in row[1:]]
                    user_data_decrypt.append(decrypted_values)

                except:
                    return render_template('login.html', error = "Shared secret expired.")

            return render_template('passwords.html', user = user_data_decrypt, error=error)


# Function allowing users to delete entries from the database
@app.route('/remove_password', methods=['GET', 'POST'])
def remove_password():
    error = None
    user_id = request.cookies.get('ID')
    site_name = request.form['siteNameRem']

    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()

        user_data = cursor.execute("SELECT SiteName FROM Passwords WHERE ID = ?", (user_id,)).fetchall()

        # Delete all passwords with the site name specified
        for encrypted_site_name in user_data:
            if decrypt(encrypted_site_name[0]) == site_name:
               cursor.execute("DELETE FROM Passwords WHERE ID = ? AND SiteName = ?", (user_id, encrypted_site_name[0]))

        user_data = cursor.execute("SELECT * FROM Passwords WHERE ID = ?", (user_id,)).fetchall()

        user_data_decrypt = []
        for row in user_data:
            try:
                decrypted_values = [decrypt(value) for value in row[1:]]
                user_data_decrypt.append(decrypted_values)
            except:
                return render_template('login.html', error = "Shared secret expired.")
            
        print(user_data_decrypt)

        return render_template('passwords.html', user = user_data_decrypt, error=error)
    


if __name__ == '__main__':
    app.run()