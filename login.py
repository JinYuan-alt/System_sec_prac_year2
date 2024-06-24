from flask import Flask, render_template,request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
import cryptography
from cryptography.fernet import Fernet
import re
#user bobmyskrm password bobby

bcrypt = Bcrypt()

app = Flask(__name__)
# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'
# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
# Password below must be changed to match root password specified at server installation
app.config['MYSQL_PASSWORD'] = 'ihatenyp1234'
app.config['MYSQL_DB'] = 'pythonlogin'
#DO NOTE THAT THE MYSQL SERVER INSTANCE IN THE LAB IS RUNNING ON PORT 3360.
#Please make necessary change to the above MYSQL_PORT config
app.config['MYSQL_PORT'] = 3306
# Intialize MySQL
mysql = MySQL(app)
@app.route('/login', methods=['GET', 'POST'])
def login():
 msg = ''
 # Check if "username" and "password" POST requests exist (user submitted form)
 if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
     # Create variables for easy access
     username = request.form['username']
     password = request.form['password']
     # Check if account exists using MySQL
     cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
     cursor.execute('SELECT * FROM accounts WHERE username = %s',(username,))#hash passwd will never match plaintext passwd
     account=cursor.fetchone() # Fetch one record and return result
     if account is not None:
         user_hashpwd = account['password']
         if account and bcrypt.check_password_hash(user_hashpwd, password):#hash passwd user gave than check
           # Create session data, we can access this data in other routes
           session['loggedin'] = True
           session['id'] = account['id']
           session['username'] = account['username']

           encrypted_email=account['email'].encode()
           file=open('symmetric.key','rb')
           key=file.read()
           file.close()
           f=Fernet(key)
           # Redirect to home page
           decrypted_email=f.decrypt(encrypted_email)
           return 'Logged in successfully! My email: ' + decrypted_email.decode()
         else:
           # Account doesn’t exist or username/password incorrect
             msg = 'Incorrect username/password!'
           # Show the login form with message (if any)
 return render_template('index.html',msg='')

@app.route('/MyWebApp/logout')
def logout():
# Remove session data, this will log the user out
 session.pop('loggedin', None)
 session.pop('id', None)
 session.pop('username', None)
# Redirect to login page
 return redirect(url_for('login'))

# http://localhost:5000/MyWebApp/register - this will be the registration page, we need to use both
#GET and POST requests
@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
# Output message if something goes wrong...
    msg = ''
# Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and'email' in request.form:
# Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        key = Fernet.generate_key()
        with open("symmetric.key","wb") as fo:
            fo.write(key)
        f = Fernet(key)
        email = email.encode()
        encrypted_email=f.encrypt(email)
        hashpwd=bcrypt.generate_password_hash(password)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, hashpwd, encrypted_email,))
        mysql.connection.commit()
        msg = 'You have successfully registered!'
    elif request.method == 'POST':
# Form is empty... (no POST data)
        msg = 'Please fill out the form!'
# Show registration form with message (if any)
    return render_template('register.html', msg=msg)

@app.route('/MyWebApp/home')
def home():
# Check if user is loggedin
   if 'loggedin' in session:
# User is loggedin show them the home page
     return render_template('home.html', username=session['username'])
# User is not loggedin redirect to login page
   return redirect(url_for('login'))

@app.route('/MyWebApp/profile')
def profile():
# Check if user is loggedin
   if 'loggedin' in session:
# We need all the account info for the user so we can display it on the profile page
      cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
      cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
      account = cursor.fetchone()
# Show the profile page with account info
      return render_template('profile.html', account=account)
# User is not loggedin redirect to login page
   return redirect(url_for('login'))

if __name__== '__main__':
    app.run()

# http://localhost:5000/login - this will be the login page, we need to use both GET and POST
#requests