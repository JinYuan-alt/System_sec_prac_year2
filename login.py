from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template,request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import uuid, datetime
import time
from PIL import Image
import os
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, AnyOf
from password_strength import PasswordPolicy
from password_strength import PasswordStats
from PIL.ExifTags import TAGS
from iptcinfo3 import IPTCInfo
from datetime import datetime, timedelta
from flask_dance.contrib.google import make_google_blueprint, google
import json



#user Karen password Kimster/Kimmy
#user Ted password Teddy (to present expiry date working)
#Bobmyskrm password Bobby
#Bivol password Soviet
#MoguM1 password MoguM1 email: MoguM1@gmail.com
#bah password Bahn10


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)



app.config['temp']=timedelta(days=1)
app.config['uploads'] = os.path.join(basedir, 'uploads')
app.config['sanitized']= os.path.join(basedir, 'static/sanitized')
app.secret_key = 'skip'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdjNgUqAAAAACaa3mZx9EOk2mx4ooaUmabkPhAb'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdjNgUqAAAAALNKNo64J122u0Yj0Bn96Z1ZZPeP'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'ihatenyp1234'
app.config['MYSQL_DB'] = 'pythonlogin2'
time_list=[]
#DO NOTE THAT THE MYSQL SERVER INSTANCE IN THE LAB IS RUNNING ON PORT 3360.
#Please make necessary change to the above MYSQL_PORT config
app.config['MYSQL_PORT'] = 3306
# Intialize MySQL
blueprint = make_google_blueprint(
    client_id="15998136336-hgnkta6j00istjbbrdl36hgefuep6t9u.apps.googleusercontent.com",
    client_secret="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",
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_to="google_login"
)
app.register_blueprint(blueprint, url_prefix="/login")

mysql = MySQL(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect()
recaptcha = RecaptchaField()
failed_attempts=[]
NonSan_filepath=[]
San_filepath=[]
Post_text=[]

policy = PasswordPolicy.from_names(
    length=1,       # Min length: 1 character
    uppercase=1,    # Min 1 uppercase letter
    numbers=1,       # Min 1 digit
    strength = 0.10
)


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired('A username is required!'),
    Length(min=1, max=30, message='Must be between 5 and 30 characters.')])
    password = PasswordField('password', validators=[InputRequired('Password is required!')])
    recaptcha = RecaptchaField()

class MySQLStorage:
    def __init__(self, connection, user_id):
        self.connection = connection
        self.user_id = user_id

    def get(self, google_id):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM oauth_tokens WHERE google_id = %s AND user_id = %s', (google_id, self.user_id))
        token = cursor.fetchone()
        if token:
            return {
                "access_token": token['access_token'],
                "refresh_token": token['refresh_token'],
                "token_type": token['token_type'],
                "expires_in": token['expires_in']
            }
        return None

    def set(self, google_id, token):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO oauth_tokens (google_id, access_token, refresh_token, token_type, expires_in, user_id) VALUES (%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE access_token = %s, refresh_token = %s, token_type = %s, expires_in = %s',
                       (google_id, token['access_token'], token.get('refresh_token'), token.get('token_type'), token.get('expires_in'), self.user_id,
                        token['access_token'], token.get('refresh_token'), token.get('token_type'), token.get('expires_in')))
        self.connection.commit()

    def delete(self, google_id):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('DELETE FROM oauth_tokens WHERE google_id = %s AND user_id = %s', (google_id, self.user_id))
        self.connection.commit()
@app.route("/")
def first():
    formL=LoginForm()
    if 'loggedin' not in session:
       myuuid = str(uuid.uuid4())
       session['temp'] = "temp" + myuuid
       clear_session()
    return render_template("index.html",msg='',form=formL)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    formL=LoginForm()
        # Google OAuth
    if google.authorized:
        try:
            resp = google.get("/oauth2/v2/userinfo")
            resp.raise_for_status()  # Raises HTTPError for bad responses
            google_info = resp.json()
            google_id = google_info["id"]
            email = google_info["email"]
            username = google_info.get("name", "Google User")
        except AssertionError:
            msg = 'Failed to retrieve user information from Google. Please try again.'
            return render_template('index.html', msg=msg, form=formL)
        except Exception as e:
            msg = f'An unexpected error occurred: {str(e)}'
            return render_template('index.html', msg=msg, form=formL)

        # Check if the user already exists in the `google` table
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM google WHERE google_id = %s', (google_id,))
        google_account = cursor.fetchone()

        if google_account:
            # Load related account data from `accounts` table
            cursor.execute('SELECT * FROM accounts1 WHERE email = %s', (email,))
            account = cursor.fetchone()
            if account:
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                session['email'] = account['email']
                session['google_id'] = google_account['google_id']
                session['role_id'] = account['role_id']
                return redirect(url_for('home'))
        else:
            return redirect(url_for('register'))

        if account is None:
            msg = 'Incorrect username/password!'
            return render_template('index.html', msg=msg, form=formL)
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'g-recaptcha-response' in request.form:
     # Create variables for easy access
      if request.form['g-recaptcha-response'] == '':
         return render_template('index.html', form=formL)
      username = request.form['username']
      password = request.form['password']
      if username == 'admin123' and password == 'admin123':
         session['username']= 'admin123'
         session['password']= 'admin123'
         session['loggedin'] = True
         session['id']= '10101010'
         return render_template('admin.html')
     # Check if account exists using MySQL
      cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
      cursor.execute('SELECT * FROM login_attempts WHERE username = %s', (username,))
      login_attempt = cursor.fetchone()
      cursor.execute('SELECT * FROM accounts WHERE username = %s',(username,))#hash passwd will never match plaintext passwd
      account=cursor.fetchone() # Fetch one record and return result
      if account is not None:
         user_hashpwd = account['password']
         if account and bcrypt.check_password_hash(user_hashpwd, password):#hash passwd user gave than check
           # Create session data, we can access this data in other routes
           session['loggedin'] = True
           session['id'] = account['id']
           session['username'] = account['username']
           cursor.execute('SELECT * FROM accounts WHERE username=%s',(username,))
           key=cursor.fetchone()
           C_key=key['symm_key']
           encrypted_email=account['email'].encode()
           f=Fernet(C_key)
           # Redirect to home page
           decrypted_email=f.decrypt(encrypted_email)
           print(decrypted_email)
           session.pop('temp', None)
           if login_attempt:
               if login_attempt['attempts'] >= 2:
                   # Check if the block period has passed
                   last_attempt = login_attempt['last_attempt']
                   block_until = last_attempt + timedelta(minutes=5)
                   print(block_until)
                   if datetime.now() < block_until:
                       return render_template('login.html', msg='Too many failed attempts. Try again later.', form=formL)
                   else:
                       # Reset the failed attempts after the block period
                       cursor.execute('DELETE FROM login_attempts WHERE username = %s', (username,))
                       mysql.connection.commit()
                       return expiry(username)
           else: return expiry(username)
         else:
           # Account doesn’t exist or username/password incorrect
           failed_attempts.append('failed')
           a = len(failed_attempts)
           if 'temp' in session:
             cursor.execute(
                   'UPDATE login_attempts SET attempts = %s, last_attempt = %s WHERE username = %s',
                   (a,datetime.now(), username))
             logging(session['temp'], password, username, a)
           else:
               cursor.execute('INSERT INTO login_attempts (username, attempts, last_attempt) VALUES (%s, %s, %s)',
                              (username, a, datetime.now()))
               logging(sesh=str(uuid.uuid4()), p=password, u=username, a=a)
           # Show the login form with message (if any)
      else:
         return render_template('register.html')
    return render_template('index.html',msg='',form=formL)

@app.route('/google_login')
def google_login():
    formL=LoginForm()
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get("/oauth2/v2/userinfo")
    google_info = resp.json()
    google_id = google_info["id"]
    email = google_info["email"]
    name = google_info.get("name", "No Name")
    picture = google_info.get("picture", None)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM google WHERE google_id = %s', (google_id,))
    google_account = cursor.fetchone()

    if google_account:
        session['loggedin'] = True
        session['id'] = google_account['id']
        session['username'] = google_account['username']
        return redirect(url_for('home'))
    else:
        msg = 'Google account not registered. Please sign up using Google.'
        return render_template('index.html', msg=msg, form=formL)
@app.route('/secure_login', methods=['GET', 'POST'])
def secure_login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Check if the user is blocked
        cursor.execute('SELECT * FROM login_attempts WHERE username = %s', (username,))
        login_attempt = cursor.fetchone()

        if login_attempt:
            if login_attempt['attempts'] >= 5:
                # Check if the block period has passed
                last_attempt = login_attempt['last_attempt']
                block_until = last_attempt + timedelta(minutes=5)
                if datetime.now() < block_until:
                    msg = 'Too many failed attempts. Try again later.'
                    return render_template('secure_login.html', msg=msg)
                else:
                    # Reset the failed attempts after the block period
                    cursor.execute('UPDATE login_attempts SET attempts = 0 WHERE username = %s', (username,))
                    mysql.connection.commit()

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account and bcrypt.check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            # Reset failed attempts on successful login
            cursor.execute('DELETE FROM login_attempts WHERE username = %s', (username,))
            mysql.connection.commit()
            return 'Secure login successful!'
        else:
            # Increment failed attempts
            if login_attempt:
                cursor.execute(
                    'UPDATE login_attempts SET attempts = attempts + 1, last_attempt = %s WHERE username = %s',
                    (datetime.now(), username))
            else:
                cursor.execute('INSERT INTO login_attempts (username, attempts, last_attempt) VALUES (%s, 1, %s)',
                               (username, datetime.now()))
            mysql.connection.commit()
            msg = 'Incorrect username/password!'
    return render_template('secure_login.html', msg=msg)
@app.route('/vulnerable_login', methods=['GET', 'POST'])
def vulnerable_login():
    msg = ''
    data = []
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # This query is vulnerable to SQL injection
        query = f"SELECT * FROM accounts WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        accounts = cursor.fetchall()

        if accounts:
            # Display all returned account details
            msg = 'Vulnerable login successful! Retrieved data:'
            data = accounts  # Capture the retrieved data
        else:
            msg = 'Incorrect username/password!'
    return render_template('vulnerable_login.html', msg=msg, data=data)

def logging(sesh,p,u,a):
    tries = "." + str(a)
    sesh_id = str(sesh)
    user = str(u)
    pasw = str(p)
    hashpwd = bcrypt.generate_password_hash(pasw)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("INSERT INTO tests VALUES(%s,%s,%s,NULL)", (sesh_id + tries, hashpwd, user))
    cursor.execute("INSERT INTO tests2 VALUES(%s,%s,%s,NULL)", (sesh_id + tries, hashpwd, user))
    mysql.connection.commit()

def display_log():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM tests")
    a = cursor.fetchall

@app.route('/logout/google')
def google_logout():
    token = blueprint.token["access_token"]
    resp = google.post(
        "https://accounts.google.com/o/oauth2/revoke",
        params={"token": token},
        headers={"content-type": "application/x-www-form-urlencoded"}
    )
    assert resp.ok, resp.text
    logout()  # Flask-Login's logout
    return redirect(url_for('login'))

@app.route('/clear-session')
def clear_session():
    session.clear()
    return 'Session cleared!'


@app.route('/MyWebApp/logout')
def logout():
# Remove session data, this will log the user out
  session.pop('loggedin', None)
  session.pop('id', None)
  session.pop('username', None)
  session.pop('email', None)
  session.pop('google_id', None)
  session.pop('role_id', None)
  clear_session()
    # Also log out from Google if logged in via Google
  if google.authorized:
        token = blueprint.token["access_token"]
        resp = google.post('https://accounts.google.com/o/oauth2/revoke',
                           params={'token': token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})
        assert resp.ok, resp.text
# Redirect to login page
  return redirect(url_for('login'))

# http://localhost:5000/MyWebApp/register - this will be the registration page, we need to use both
#GET and POST requests
@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
# Output message if something goes wrong...
    msg = ''
    if google.authorized:
        resp = google.get("/oauth2/v2/userinfo")
        resp.raise_for_status()
        assert resp.ok, resp.text
        google_info = resp.json()
        google_id = google_info["id"]
        email = google_info["email"]
        username = google_info.get("name", "Google User")
        picture = google_info.get("picture", None)

        # Check if the user already exists in the `google` table
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM google WHERE google_id = %s OR email = %s', (google_id, email))
        google_account = cursor.fetchone()

        if google_account:
            msg = 'Account already exists! Please log in.'
            return redirect(url_for('login'))

        # Insert Google user data into `google` table
        cursor.execute('INSERT INTO google (username, email, google_id, role_id) VALUES (%s, %s, %s, %s)',
                       (username, email, google_id, 1))
        mysql.connection.commit()

        # Insert related data into `accounts` table
        cursor.execute('INSERT INTO accounts1 (username, email, password) VALUES (%s, %s, NULL) ',
                       (username, email))
        mysql.connection.commit()

        session['loggedin'] = True
        session['id'] = cursor.lastrowid
        session['username'] = username
        session['email'] = email
        session['google_id'] = google_id
        session['role_id'] = 1

        return redirect(url_for('home'))
# Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and'email' in request.form:
# Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        key = Fernet.generate_key()
        checkpolicy = policy.test(password)
        stats = PasswordStats(password)
        if checkpolicy:
            # Create a detailed error message
            flash("Password does not meet the following criteria: " + ", ".join([str(rule) for rule in checkpolicy]))
            return render_template('register.html', msg='Password does not meet the required criteria.')
        if stats.strength() < 0.10:
            flash("Password not strong enough. It must have an entropy strength of at least 0.10.")
            return render_template('register.html', msg='Password does not meet the required criteria.')
        if password != confirm_password:
            msg = 'Passwords do not match!'
        if password != confirm_password:
            msg = 'Passwords do not match!'
        else:
         with open("symmetric.key","wb") as fo:
            fo.write(key)
         f = Fernet(key)
         email = email.encode()
         encrypted_email=f.encrypt(email)
         hashpwd=bcrypt.generate_password_hash(password)
         CT=time.localtime()
         yr=str(CT.tm_year)
         day=str(CT.tm_mday)
         month=str(CT.tm_mon)
         time_list=[yr,int(month)+1,day]
         if int(month)>=12:
            time_list[0]=int(yr)+1
            time_list[1]=1
         P_yr=str(time_list[0])
         P_month=str(time_list[1])
         P_day=str(time_list[2])
         P_sql=P_yr+"-"+P_month+"-"+P_day
         R_sql=yr+"-"+month+"-"+day
        #write some sql code to store this into database under user's username
         cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
         cursor.execute('SELECT * FROM accounts WHERE username=%s',(username,))
         check=cursor.fetchone()
         if check != None:
            msg='choose another username'
            return render_template('register.html',msg=msg)
         cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s, %s)', (username, hashpwd, encrypted_email, R_sql ,P_sql, key))
         mysql.connection.commit()
         msg = 'You have successfully registered!'
    elif request.method == 'POST':
# Form is empty... (no POST data)
        msg = 'Please fill out the form!'
# Show registration form with message (if any)
    return render_template('register.html', msg=msg)

@app.route('/MyWebApp/update', methods=['GET', 'POST'])
def update():
    msg=''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
      username= request.form['username']
      password = request.form['password']
      hashpwd = bcrypt.generate_password_hash(password)
      checkpolicy = policy.test(password)
      stats = PasswordStats(password)
      if checkpolicy:
          # Create a detailed error message
          flash("Password does not meet the following criteria: " + ", ".join([str(rule) for rule in checkpolicy]))
          return render_template('update.html', msg='Password does not meet the required criteria.')
      if stats.strength() < 0.10:
          flash("Password not strong enough. It must have an entropy strength of at least 0.10.")
          return render_template('update.html', msg='Password does not meet the required criteria.')
      else:
        CT = time.localtime()
        yr = str(CT.tm_year)
        day = str(CT.tm_mday)
        month = str(CT.tm_mon)
        time_list = [yr, int(month)+1, day]
        E_sql=yr+"-"+month+"-"+day
        if int(month) >= 12:
          time_list[0] = int(yr) + 1
          time_list[1] = 1
        P_yr = str(time_list[0])
        P_month = str(time_list[1])
        P_day = str(time_list[2])
        P_sql = P_yr + "-" + P_month + "-" + P_day
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username=%s',(username,))
        check = cursor.fetchone()
        ogP=check['password']
        if bcrypt.check_password_hash(ogP,password)==True:
          return redirect(url_for('update'))
        else: cursor.execute('UPDATE accounts SET username=%s, password=%s, password_register_date=%s, password_expiry_date=%s where username=%s', (username, hashpwd, E_sql, P_sql, username))
        cursor.execute('DELETE FROM tests2 WHERE username=%s', (username,))
        mysql.connection.commit()
      return render_template('home2.html')
    return render_template('update.html',msg='will refresh if password is same as past one')

def expiry(U_name):
   #this should retrieve the data from sql
   if request.method == 'POST' and 'username':
       # Create variables for easy access
       #U_name = request.form['username']
       CT = time.localtime()
       yr = str(CT.tm_year)
       day = str(CT.tm_mday)
       month = str(CT.tm_mon)
       if int(month)<10:
           month="0"+str(CT.tm_mon)
       if int(day)<10:
           day="0"+str(CT.tm_mday)
       date_sql = yr + "-" + month + "-" + day
       #date_sql = "2024-08-15"
       cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
       cursor.execute('SELECT * FROM accounts WHERE username = %s', (U_name,))
       accts = cursor.fetchone()
       expiration_date = accts["password_expiry_date"]
       expiration=expiration_date.strftime('%Y-%m-%d')
       print(expiration[0:10])
       e=expiration.split("-")
       print(e)
       e_yr=e[0]
       e_month=e[1]
       e_day=e[2]
       print(date_sql)
       if int(e_yr)<int(yr):
           return redirect(url_for('update'))
       if int(e_day)<int(day) and int(e_month)<=int(month):
           return redirect(url_for('update'))
       if int(e_yr)==int(yr) and int(e_day)==int(day) and int(e_month)==int(month):
           return redirect(url_for('update'))
       else:
           return home()


@app.route('/MyWebApp/admin', methods=['GET','POST'])
def admin_view():
    if 'loggedin' in session:
      if request.method == 'POST' and request.form['logs'] == 'logging':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM tests')
        logs=cursor.fetchall()
        return render_template('admin.html', logs=logs)
    return render_template('admin.html')

@app.route('/MyWebApp/home', methods=['GET', 'POST'])
def home():
# Check if user is loggedin
   if 'loggedin' in session:
       cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
       if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
           username=session['username']
           cursor.execute('SELECT COUNT(username) FROM tests2 WHERE username=%s ', (username,))
           count = cursor.fetchone()
           print(count['COUNT(username)'])
           real_count = count['COUNT(username)']
           if real_count >= 5:
              msg='your account is under risk of being hacked, update password now'
              return render_template('home2.html', username=session['username'], msg=msg)
# User is loggedin show them the home page
       return render_template('home2.html', username=session['username'])
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
      try:
          The_path=San_filepath[-1]
          txt = Post_text[-1]
      except IndexError:
          The_path=''
          txt = ''
# Show the profile page with account info
      return render_template('account.html', account=account, filename=The_path, txt=txt)
# User is not loggedin redirect to login page
   return redirect(url_for('login'))

@app.route('/MyWebApp/AdminProfile')
def Admin_profile():
# Check if user is loggedin
   if 'loggedin' in session:
      if session['username']=='admin123':
           account='administrator'
           return render_template('Adminprofile.html', account=account)
# We need all the account info for the user so we can display it on the profile page
      cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
      cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
      account = cursor.fetchone()
# Show the profile page with account info
      return render_template('Adminprofile.html', account=account)
# User is not loggedin redirect to login page
   return redirect(url_for('login'))

@app.route('/MyWebApp/post', methods=['GET','POST'])
def image():
    msg=''
    if request.method == "POST" and 'img' in request.files:
        try:
          image=request.files['img']
          txt=request.form['txt']
          #print(str(image.filename))
          image.save(os.path.join(app.config['uploads'], image.filename))
          img = Image.open('uploads/'+image.filename)
          icc_profile = img.info.get('icc_profile')
          NonSan_filepath.append('uploads/'+image.filename)
          output_path = os.path.join(app.config['sanitized'], image.filename)
          img.save(output_path, icc_profile=icc_profile)
          msg='/sanitized/'+image.filename
          San_filepath.append(msg)
          Post_text.append(txt)
        except FileNotFoundError:
            return render_template('post.html')
        return render_template('post.html', filename=msg)
    return render_template('post.html')

@app.route('/check_sanIMG', methods=['GET','POST'])
def check():
    if request.method == 'POST':
      file_path= 'static/sanitized/WIN_20240811_21_14_29_Pro.jpg'
      image=Image.open(file_path)
      exifdata = image.getexif()
      info=IPTCInfo(file_path)
      xmpdata = image.getxmp()
      print(xmpdata)
      print(info)
      ls = []
    # looping through all the tags present in exifdata
      for tagid in exifdata:
        # getting the tag name instead of tag id
        tagname = TAGS.get(tagid, tagid)

        # passing the tagid to get its respective value
        value = exifdata.get(tagid)

        # printing the final result
        print(f"{tagname:25}: {value}")
        ls.append(f"{tagname:25}: {value}")
      ls.append(xmpdata)
      ls.append(info)
      return render_template('check_sanIMG.html', check=ls)
    return render_template('check_sanIMG.html')

@app.route('/pre_sanIMG', methods=['GET','POST'])
def presanitize():
    if request.method == 'POST':
      file_path = 'uploads/WIN_20240811_21_14_29_Pro.jpg'
      image = Image.open(file_path)
      exifdata = image.getexif()
      info = IPTCInfo(file_path)
      xmpdata=image.getxmp()
    # looping through all the tags present in exifdata
      print(xmpdata)
      print(info)
      ls = []
      for tagid in exifdata:
        # getting the tag name instead of tag id
        tagname = TAGS.get(tagid, tagid)

        # passing the tagid to get its respective value
        value = exifdata.get(tagid)

        # printing the final result
        print(f"{tagname:25}: {value}")
        ls.append(f"{tagname:25}: {value}")
      ls.append(xmpdata)
      ls.append(info)
      return render_template('pre_sanIMG.html', presan=ls)
    return render_template('pre_sanIMG.html')

@app.route("/login/callback")
def callback():
    google.authorized_response()
    token = google.token
    session['google_token'] = (token['access_token'], '')
    return redirect(url_for('home'))




if __name__== '__main__':
    app.run(debug=True, ssl_context='adhoc')



# http://localhost:5000/login - this will be the login page, we need to use both GET and POST
#requests

