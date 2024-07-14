from flask import Flask, render_template,session,redirect,abort, request,flash,g,url_for,jsonify
from google_auth_oauthlib.flow import Flow
from flask_mail import Mail,Message
from datetime import datetime, time, date as dt_date
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, current_user,login_required
from flask_session import Session
from models import Users,db,Pets,Services,VetRoles,Vets,Admins,Appointments, Vitals
from forms import LoginForm,AddServiceForm,VetRoleForm,RegistrationForm,RegisterVetForm,AdminRegisterForm,VitalsForm
from random import *
from config import Config
from flask_paginate import Pagination, get_page_parameter
import pathlib,os
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt     
from googleapiclient.discovery import build 
from pathlib import Path
import io
import base64
import matplotlib
from flask import send_file
import pandas as pd
import numpy as np
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from bcrypt import hashpw, gensalt
import re
import string
import hashlib
import random

bcrypt = Bcrypt()
otp =randint(000000,999999)

app = Flask(__name__)
app.secret_key = 'myfishsucksmiamiaa'
login_manager = LoginManager()
login_manager.init_app(app)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///owners.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable Flask-SQLAlchemy event system to avoid unnecessary overhead

db.init_app(app)
migrate = Migrate(app, db)


# APP CONFIGURATIONS
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'iamhawiana@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.secret_key = "MyGoogleSAuth"
app.config['SESSION_FILE_DIR'] = os.path.join(app.root_path, "sessions")
app.config['SESSION_FILE_THRESHOLD'] = 1000
app.config.from_object(Config)
mail = Mail(app)

# Session(app)

# GOOGLE CONFIGURATIONS
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
#
def set_password(Password):
    return bcrypt.generate_password_hash(Password).decode('utf-8')
        
# SESSIONS MANAGER
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # The name of the login view

def generate_random_string(length):
    # Define the characters that will be used in the random string
    characters = string.ascii_letters + string.digits + string.punctuation
    # Use random.choices to select random characters from the defined set
    random_string = ''.join(random.choices(characters, k=length))
    return random_string

# Default credentials for login/register
DEFAULT_PROFILE_IMAGE = 'static/images/default.png'
DEFAULT_CONTACT = ""
DEFAULT_VET_PROFILE = 'static/images/profile-user.png'
DEFAULT_PET_PROFILE = 'static/images/pet-profile.png'
DEFAULT_RECOVERYMAIL = " "
DEFAULT_STATUS = "Pending"
DEFAULT_DURATION = " "
DEFAULT_TIME = " "
DEFAULT_ADDRESS = ""

Pass = generate_random_string(10)

def generate_unique_password(id):
    id = 10
    prefix = "Admin"
    suffix = "@petco"
    
    # Create a unique part using a hash of the user ID
    unique_part = hashlib.sha256(str(id).encode()).hexdigest()[:4]  # Take the first 4 characters of the hash
    
    # Combine prefix, unique part, and suffix to form the password
    default_password = f"{prefix}{unique_part}{suffix}"
    
    return default_password

def generate_unique_vetpassword(id):
    id = 12
    prefix = "Vet"
    suffix = "@petco"
    
    # Create a unique part using a hash of the user ID
    unique_part = hashlib.sha256(str(id).encode()).hexdigest()[:4]  # Take the first 4 characters of the hash
    
    # Combine prefix, unique part, and suffix to form the password
    default_password = f"{prefix}{unique_part}{suffix}"
    
    return default_password

@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith('admin_'):
        user_id = user_id.split('_')[1]
        return Admins.query.get(int(user_id))
    elif user_id.startswith('user_'):
        user_id = user_id.split('_')[1]
        return Users.query.get(int(user_id))
    elif user_id.startswith('vet_'):
        user_id = user_id.split('_')[1]
        return Vets.query.get(int(user_id))
    return None


# ROUTES 
@app.route("/")
def landing_page():
    # flash('Login successful!', 'success') 
    return render_template ("landing.html")

@app.route('/homee', methods=["GET","POST"])
def home():
    return render_template("home.html")



####################### AUTHENTICATION ##################################
# LOGIN USER
@app.route('/login', methods=["GET","POST"])
def login():
    form = LoginForm()
    
     # for new admin login
    expected_prefix = "Admin"
    expected_prefix_vet = "Vet"
   
    if form.validate_on_submit():
        Email = form.Email.data  # Retrieve email from the form
        print(Email)
        Password = form.Password.data
        
        if Admins.query.filter_by(Email=Email).first():
            user = Admins.query.filter_by(Email=Email).first()
        elif (Users.query.filter_by(Email=Email).first()):
            user = Users.query.filter_by(Email=Email).first()
        elif (Vets.query.filter_by(Email=Email).first()):
            user = Vets.query.filter_by(Email=Email).first()
        else:
            flash("Invalid user", "danger")
            
        print(user)
        default_password = user.Password 
        
        if user:
            if Password.startswith(expected_prefix) or Password.startswith(expected_prefix_vet):
                login_user(user) 
                return render_template("forms/reset-password.html")
            
            elif (user.check_password(form.Password.data)) :
                login_user(user) 
                otp_str = str(otp)
                session["otp"] = otp_str
                #session["role"] = current_user.role
                Email = form.Email.data
                EmailContent = render_template("emails/log-otp-email.html", otp=otp_str)
                msg = Message(subject="Welcome back!", sender='iamhawiana@gmail.com', recipients=[Email])
                msg.html = EmailContent

                mail.send(msg)  #sends the email 
            
                flash('Email has been sent your account', 'primary')
                return render_template ('login-verify.html', otp=otp) 
        
            else:
                flash ("Invalid password", "danger")
                
        else:
            flash("Email is invalid","danger")
        
    return render_template('forms/SignIn.html', form=form)  # Redirect to landing instead of render_template

@app.route("/loginchecker", methods=["POST","GET"])
def logchecker():
    otp = session.get("otp")
    #current_user.role = session.get("role")
    if request.method == "POST":
        code = request.form["user-otp"]
        if code == otp:
            if current_user.role == "vet":
                return redirect(url_for('vetHome'))
            elif (current_user.role == "admin"):
                return redirect(url_for("admin"))
            elif (current_user.role == "user"):
                return redirect(url_for("home"))
        else:
            flash("Otp does not match", "danger")
        


# REGISTER USER
@app.route('/register', methods=["GET","POST"])
def register():
    Regform = RegistrationForm()
    if Regform.validate_on_submit():
            DEFAULT_PROFILE_IMAGE = 'static/images/default.png'
            user = Users(Fullname=Regform.Fullname.data, Email=Regform.Email.data,Password=Regform.Password.data)
            user.Profile_pic = DEFAULT_PROFILE_IMAGE  # Assign default image path
            user.Contact =DEFAULT_CONTACT
            user.Address= DEFAULT_ADDRESS 

            db.session.add(user)
            db.session.commit()

            #Send email with mail credentials at the top
            otp_str = str(otp)
            Email = request.form['Email']
            EmailContent = render_template("emails/email.html", otp=otp_str)
            msg = Message(subject="Welcome to PetCo", sender='iamhawiana@gmail.com', recipients=[Email])
            msg.html = EmailContent

            mail.send(msg)   
            login_user(user)
            flash('Email has been sent your account', 'primary')
            return render_template ('verify.html', otp=otp) 


    return render_template("forms/SignUp.html", Regform = Regform)

@app.route('/auth-checker/<otp>', methods=["GET","POST"]) #verify to reset password for user
def checker(otp):
    if request.method == "POST":
        code = request.form["user-otp"]
        if code == str(otp):
            # flash("Account created", "success")
            return render_template("forms/reset-password.html") #reset-password.html
        else:
            return('invalid otp','danger')
    
    return ("error")

@app.route('/forgot-pass', methods=["GET","POST"])
def display():
    return render_template('forms/email-otp.html')


@app.route('/verify-otp')
def dis():
    return render_template('forms/otp.html')


# #FORGOT PASSWORD 
@app.route('/forgotPassword', methods=["GET","POST"])
def reset(): 
    if request.method == "POST":
        Email = session.get('reset_email')
        # Email = session.get('reset_email')
        Password = request.form['Password']
        New_Password = request.form['Confirm_Password']  
        
    user = Admins.query.filter_by(Email=Email).first()
    if not user:
        user = Users.query.filter_by(Email=Email).first()
    if not user:
        user = Vets.query.filter_by(Email=Email).first()
        
    if Password == New_Password:
        user.Password = bcrypt.generate_password_hash(Password).decode('utf-8')
        db.session.commit()
        flash("Password updated successfully!", "primary")
        return redirect(url_for("login")) #
                
    else:
        flash("Password not match")
        return redirect(url_for('login'))
 
                
    return render_template("forms/reset-password.html")

# RESET PASSWORD
@app.route('/resetPassword', methods=["GET","POST"])
def resetPassword(): 
    if request.method == "POST":
        print(current_user)
        if current_user.is_authenticated:
            Email = current_user.Email
            Password = request.form["Password"]
            New_Password = request.form['Confirm_Password'] 
    
        if Password == New_Password:
            current_user.Password = bcrypt.generate_password_hash(Password).decode('utf-8')
            db.session.commit()
            flash("Password updated successfully!", "primary")
    
            if current_user.role == 'admin':
                return redirect(url_for('admin'))
            elif current_user.role == 'user':
                return redirect(url_for('home'))
            elif current_user.role == 'vet':
                return redirect(url_for('vetHome'))    
        else:
            flash("Password not match")
            return redirect(url_for('login'))
    
                
    return render_template("forms/reset-password.html")


@app.route('/reset-email', methods=["GET","POST"]) #Sends email notification to reset password
def res_email():
    if request.method=="POST":
        Email = request.form['Email']
        session['reset_email'] = Email
        otp_str = str(otp)
        print(Email)
        EmailContent = render_template("emails/reset-email.html", otp=otp_str)
        msg = Message(subject="Reset Password Confirmation", sender='iamhawiana@gmail.com', recipients=[Email])
        msg.html = EmailContent
        print(otp)
        mail.send(msg)   
        flash('Email has been sent to your account', 'primary')
        return render_template('forms/otp.html')
   
    return render_template("forms/reset-pass.html")

@app.route('/confirm_password', methods=["GET","POST"])
def cdonf():
    if request.method == "POST":
        auth = request.form["user-otp"]
        flash("Password updated", "success")
    else:
        flash("Wrong otp", "danger")
    
    return render_template('forms/forgot-password.html')

@app.route('/forgot', methods=["GET","POST"])
def forgot():
    return render_template("forms/forgot-password.html")

@app.route("/auth", methods=["GET", "POST"])
def autho():
    return render_template("forms/SignIn.html")

@app.route("/logout")
def logout():
    # logout_user()
    session.clear()
    return redirect (url_for("login"))

def check_password(plain_password, Password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), Password)

def verify_password(input_password, Password):
    return bcrypt.check_password_hash(Password, input_password)

@app.route('/lock-session', methods=['GET', 'POST'])
def checkPass():
    Email = session.get('reset_email')
    if request.method == 'POST':
        password = request.form['Password']
        user_id = session.get('_user_id')
        if user_id:   
            user = Users.query.filter_by(id=user_id).first()
            if user and verify_password(password, user.Password):
                return redirect(url_for('home'))
        flash('Invalid password', 'danger')
    return render_template("forms/lock-sesh.html")



# EVERYTHING GOOGLE

###################### REGISTER WITH GOOGLE ###################################

# Initialize the OAuth 2.0 flow using client secrets file
flow = Flow.from_client_secrets_file(
    client_secrets_file,  # Path to the client_secret.json file
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/home"
)

#Dictionary of redentials retrieved from google
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'id_token': credentials.id_token}

@app.route('/google-checker/<otp>', methods=["GET","POST"])
def goog_checker(otp):
    if request.method == "POST":
        code = request.form["user-otp"]
        if code == str(otp):
            # flash("Account created", "success")
            return render_template("home.html") 
        else:
            flash('Invalid otp')
    
    return ("error")

# Google account lists display 
@app.route("/google_auth")
def authenticate():
    flow.redirect_uri = url_for('google_auth_callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session["state"] = state
    return redirect(authorization_url)

@app.route("/home")
def google_auth_callback():
    
    #flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(client_secrets_file, scopes=SCOPES)
    flow.redirect_uri = url_for('google_auth_callback', _external=True)
    authorization_response = request.url

    # Use authorisation code to request credentials from Google
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    # Use the credentials to obtain user information and save it to the session
    oauth2_client = build('oauth2','v2',credentials=credentials)
    user_info= oauth2_client.userinfo().get().execute()
    session['user'] = user_info
    print (user_info)

    Password = set_password("dummyinfo")
    user = Users(Fullname=user_info["name"], Email=user_info["email"], Password=Password)
    db.session.add(user)
    db.session.commit()

    # Return to main page
    return redirect(url_for("home"))


#################### LOGIN WITH GOOGLE ###########################

flow = Flow.from_client_secrets_file(
    client_secrets_file,  # Path to the client_secret.json file
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=["http://127.0.0.1:5000/callback"],
)

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'id_token': credentials.id_token}

@app.route("/authorize")
def logauthorize():
    # Intiiate login request
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', 
                                                      include_granted_scopes='true')
    return redirect(authorization_url)

## Used by Google OAuth
@app.route("/callback")
def callback():
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_response = request.url
    # Use authorisation code to request credentials from Google
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
   
    # Use the credentials to obtain user information and save it to the session
    oauth2_client = build('oauth2','v2',credentials=credentials)
    user_info= oauth2_client.userinfo().get().execute()
    session['user'] = user_info
   
    user = Users.query.filter_by(Email=user_info['email']).first()
    if user:
        #flash("Not registered in the database", "danger")

        # otp_str = str(otp)
        # Email = user_info['email']
        # EmailContent = render_template("emails/google-email.html", otp=otp_str)
        # msg = Message(subject="Welcome to PetCo", sender='PetCo', recipients=[Email])
        # msg.html = EmailContent

        # mail.send(msg)   
        login_user(user)
        # flash('OTP has been sent your account', 'primary')
        # return render_template ('google-otp.html', otp=otp) 
        return redirect(url_for('home'))
    else:
        flash("Account does not exist","danger")
        return redirect(url_for('register'))

    return render_template("landing.html")

############################################################################

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


@app.route('/userProfile', methods=['POST', 'GET'])
def uploadProfile():
    pets = Pets.query.filter_by(OwnerId=current_user.id).first()
    # Profile picture logic
    if request.method == 'POST':
        
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
         
        file = request.files['file']
        
        if file.filename == '':
            flash('No file was selected',"danger")
            return redirect(request.url)
        else: 
            print(file.filename) #Dogfinal.jpg
            file.filename = f"{current_user.id}_{file.filename}" # re-name the image to match id
            print(file.filename)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            print(f"Saving file to: {save_path}")  # Debug statement
            
            #Edit path to be stored in the database
            db_path = os.path.join('static', 'uploads', filename)
            image_path = db_path.replace('\\', '/')
            
            current_user.Profile_pic = image_path
            db.session.commit()
            # if (current_user.role == "user"):
            #         return render_template('userProfile.html',filename=filename)
            # elif(current_user.role == "admin"):
            #     return render_template('admin/adminProfile.html', filename=filename)
            # else:
            #     return render_template('vets/vetProfile', filename=filename)
            
        try:
            file.save(save_path)
            
            flash('Image has been successfully uploaded',"success")
              
                
        except Exception as e:
            flash(f"An error occurred while saving the file: {e}")
            print(f"Error: {e}")  # Debug statement
            
            
        else:

            return redirect(request.url)
    
    return render_template('userProfile.html', pets = pets)

@app.route('/uploads/<filename>')
def display_profile(filename):
    return redirect(url_for('static', filename='uploads/' +filename), code=301)

def is_valid_kenyan_phone_number(phone_number):
    # Regular expression to match Kenyan phone numbers
    # Valid format: 10 digits starting with 07, 01, 07x, or 01x
    pattern = r'^(07\d{8}|01\d{8}|254\d{9}|01\d{7})$'

    # Check if the phone number matches the pattern
    if re.match(pattern, phone_number):
        return True
    else:
        return False

@app.route('/updateProfile', methods=['POST', 'GET']) # view User profile
def updateProfile():
    user = Users.query.filter_by(id=current_user.id).first()

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('uploadProfile'))

    if request.method == "POST":
        Fullname = request.form["UpdateFullname"]
        Email = request.form["UpdateEmail"]
        Contact = request.form["UpdateContact"]
        Address = request.form["UpdateAddress"]

        # Update the user object with correct number data
        if is_valid_kenyan_phone_number(Contact):
            user.Fullname = Fullname
            user.Email = Email
            user.Contact = Contact
            user.Address = Address
            db.session.commit()
            flash('Details updated!', 'success')
        else:
            flash("Please input a valid number (07../01..)","danger")

    return redirect(url_for('uploadProfile'))


@app.route('/delete-profile-picture', methods=['POST']) #Delete pet owner profile picture
def delete_profile_picture():
    current_user.Profile_pic = None 
    db.session.commit()
    return redirect(url_for('uploadProfile'))



##################### PET MODULE ################################

@app.route('/addPet', methods=["POST","GET"]) #register new pets
@login_required
def addPet():
    
    if request.method == "POST":
        DEFAULT_PROFILE_IMAGE = 'static/images/pet-profile.png'
        PetName = request.form['PetName']
        Type = request.form['Type']
        Species = request.form['Species']
        DateOfBirth = request.form['DateOfBirth']
        Gender = request.form['Gender']
        
        pet = Pets(PetName=PetName,Type=Type,Species=Species,DateOfBirth=DateOfBirth,Gender=Gender,OwnerId=current_user.id, Profile_pic=DEFAULT_PROFILE_IMAGE)
        db.session.add(pet)
        db.session.commit()
        flash('New pet registered','success')
   
    return render_template ("petForms/addPet.html")


@app.route('/viewPet',  methods=["POST","GET"])    #view list of pets
def viewPet():
    user_pets = Pets.query.filter_by(OwnerId=current_user.id).all()
    if len(user_pets) == 0 :
        return render_template("petForms/viewPets/nopets.html")
    
    return render_template('petForms/viewPets/viewPets.html', user_pets=user_pets)

def get_day_suffix(day):
    if 11 <= day <= 13:
        return '<sup>th</sup>'
    elif day % 10 == 1:
        return '<sup>st</sup>'
    elif day % 10 == 2:
        return '<sup>nd</sup>'
    elif day % 10 == 3:
        return '<sup>rd</sup>'
    else:
        return '<sup>th</sup>'


@app.route('/view-pet-profile/<int:first_pet>')    # view edit pet profile
def view_pet_profile(first_pet):
   
    pet = Pets.query.filter_by(PetID=first_pet).first()
    # profile_pic = pet.Profile_pic
    print(pet)
    app = Appointments.query.filter_by(OwnerId = current_user.id, Status= "Approved", PetName = pet.PetName).all()
    
    if len(app) == 0 :
        app = Appointments.query.filter_by(OwnerId = current_user.id, PetName = pet.PetName).all()
        vitals = 0
        app = 0

    else:
        for apps in app:
            date = apps.Startdate
            print(date)
            date_obj = datetime.strptime(date, '%Y-%m-%d')
            day_of_week = date_obj.strftime('%A')
            
            # Get the day with the suffix
            day = date_obj.day
            suffix = get_day_suffix(day)
            formatted_day = f"{day}{suffix}"
            
            # Get the month and year
            month = date_obj.strftime('%B')
            year = date_obj.year
            
            # Format the complete date
            formatted_date = f"{day_of_week}, {formatted_day} {month} {year}"
            apps.Startdate = formatted_date
        
            vitals = Vitals.query.filter_by(AppointmentID = apps.id, PetID = pet.PetID).first()
    
    return render_template('petForms/viewProfile/petProfile.html',pet=pet, app = app, vitals=vitals)


@app.route('/petProfilePic/<int:pet>', methods=['POST', 'GET'])  # Upload pet profile picture
def uplProfile(pet):
    pet_obj = Pets.query.filter_by(PetID=pet).first()
    app = Appointments.query.filter_by(OwnerId=current_user.id, Status="Approved", PetName=pet_obj.PetName).all()
    for appoint in app:          
        vitals = Vitals.query.filter_by(AppointmentID=appoint.id, PetID=pet_obj.PetID).first()
    
  
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', "danger")
            return redirect(request.url)
        
        file = request.files['file']
        print(file)
        
        if file.filename == '':
            flash('No file was selected', "danger")
            return redirect(request.url)
        else:
            print(file.filename)  # Dogfinal.jpg
            file.filename = f"{pet}_{file.filename}"  # re-name the image to match petid
            print(file.filename)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            print(f"Saving file to: {save_path}")  # Debug statement
            
            db_path = os.path.join('static', 'uploads', filename)
            image_path = db_path.replace('\\', '/')

            pet_obj.Profile_pic = image_path
            db.session.commit()
            
            try:
                file.save(save_path)
                flash('Image has been successfully uploaded', "success")
            except Exception as e:
                flash(f"An error occurred while saving the file: {e}")
                print(f"Error: {e}")  # Debug statement
            
            app = Appointments.query.filter_by(OwnerId=current_user.id, Status="Approved", PetName=pet_obj.PetName).all()
    
            if len(app) == 0:
                app = Appointments.query.filter_by(OwnerId=current_user.id, PetName=pet_obj.PetName).all()
                vitals = 0
                app = 0
            else:
                for apps in app:
                    date = apps.Startdate
                    print(date)
                    date_obj = datetime.strptime(date, '%Y-%m-%d')
                    day_of_week = date_obj.strftime('%A')
                    day = date_obj.day
                    suffix = get_day_suffix(day)
                    formatted_day = f"{day}{suffix}"
                    month = date_obj.strftime('%B')
                    year = date_obj.year
                    formatted_date = f"{day_of_week}, {formatted_day} {month} {year}"
                    apps.Startdate = formatted_date
                    vitals = Vitals.query.filter_by(AppointmentID=apps.id, PetID=pet_obj.PetID).first()
            
            return render_template('petForms/viewProfile/petProfile.html', filename=filename, pet=pet_obj, vitals=vitals,app = app)
        else:
            flash('Allowed media types are - png, jpg, jpeg, gif')
            return redirect(request.url)
    
    return render_template('petForms/viewProfile/petProfile.html', pet=pet_obj, vitals = vitals,app = app)

@app.route('/delete-pet-picture/<int:pet>', methods=['POST'])  # Delete pet picture
def delete_pet_picture(pet):
    pet_obj = Pets.query.filter_by(PetID=pet).first()
    if pet_obj:
        pet_obj.Profile_pic = DEFAULT_PET_PROFILE
        db.session.commit()
    return redirect(url_for('uplProfile', pet=pet))

@app.route('/deletePet',methods=['GET','POST'])
def deletePet():
    petid = request.form.get('petid')
    print(petid)
    if not petid:
        return ("id not found")
    else:
        pet = Pets.query.filter_by(PetID = petid).first()
        db.session.delete(pet)
        db.session.commit()
        
        app = Appointments.query.filter_by(PetName = pet.PetName).all()
        for apps in app:
            db.session.delete(apps)
            db.session.commit() 
        
    return redirect(url_for('viewPet'))
    
@app.route('/updatePetProfile', methods=['POST', 'GET']) # view User profile
def updatePetProfile():

    id = request.form["id"]
    pet = Pets.query.filter_by(PetID = id).first()
    if request.method == "POST":
        Fullname = request.form["Fullname"]
        Type = request.form["Type"]
        Species = request.form["Species"]
        Gender = request.form["Gender"]
        DOB = request.form["DOB"]
        pet = Pets.query.filter_by(PetID = id).first()
        
        pet.PetName = Fullname
        pet.Type = Type
        pet.Species = Species
        pet.DateOfBirth = DOB
        pet.Gender = Gender
       
        db.session.commit()
        flash('Details updated',"success")
        
    
        return redirect(url_for('view_pet_profile',first_pet = pet.PetID))



#############################################################################333
@app.route("/deleteVet", methods=["POST"])
def deleteVet():
    vetid = request.form.get('vetid')
   
    if not vetid:
        return ("id not found")
    else:
        vet = Vets.query.filter_by(id = vetid).first()
       
        db.session.delete(vet)
        db.session.commit() 
        
    return redirect(url_for('viewVets') ) 
    
@app.route("/appointmentInfo")
def appointmentInfo():
    id = current_user.id
    print(id)
    
    today = dt_date.today()
    apps = Appointments.query.filter(
        Appointments.OwnerId == id,
        Appointments.Status == 'Approved',
        Appointments.Startdate > today.strftime('%Y-%m-%d')
    ).all()

    appointments = Appointments.query.filter_by(OwnerId=id, Status = 'Pending').all()
      
    return render_template("forms/appointments.html", appointments = appointments, apps=apps)

@app.route("/pastAppointments")
def pastAppointments():
    id = current_user.id
    print(id)
    today = dt_date.today()
    
    app = Appointments.query.filter(
        Appointments.OwnerId == id,
        Appointments.Status == 'Approved',
        Appointments.Startdate < today.strftime('%Y-%m-%d')
    ).all()

    return render_template("forms/pastApp.html", app=app)

@app.route("/pastVetApps/<int:page>", methods=['GET','POST'])
def pastVetApps(page=1):
    
    per_page = 5
    apps_pagination = Appointments.query.filter_by(Status = "Approved") \
                                    .paginate(page=page, per_page=per_page, error_out=False)
    
    app_details = []
    
    today = dt_date.today()
    
    for app in apps_pagination.items:
        if(app.Startdate< today.strftime('%Y-%m-%d')):
                user = Users.query.filter_by(id=app.OwnerId).first()
                app_details.append({
                    "id": app.id,
                    "servicename": app.ServiceName,
                    "petname": app.PetName,
                    "date": app.Startdate,
                    "time": app.Time,
                    "duration": app.Duration,
                    "owner": user.Fullname if user else "Unknown"
            })
            
    # Handle POST request for search functionality
    if request.method == "POST" and 'tag' in request.form:
        search_query = request.form['tag']
        print(f"Search query: {search_query}")

        # Perform search by pet name (case-insensitive)
        apps_search = Appointments.query.filter(Appointments.PetName.ilike(f"%{search_query}%"),  Appointments.Status == 'Approved', Appointments.Startdate < today.strftime('%Y-%m-%d'))
        
        # Paginate the search results
        app_details = apps_search.paginate(page=page, per_page=per_page, error_out=False)

        results = []
            
        for app in app_details.items:
            user = Users.query.filter_by(id=app.OwnerId).first()
            results.append({
            "id": app.id,
            "servicename": app.ServiceName,
            "petname": app.PetName,
            "date": app.Startdate,
            "time": app.Time,
            "duration": app.Duration,
            "owner": user.Fullname if user else "Unknown"
        })
            
        return render_template('vets/pastAppointments.html', app =results, pagination=app_details)

    return render_template("vets/pastAppointments.html", app = app_details,pagination=apps_pagination)

    # return render_template("vets/pastAppointments.html", app=app_details, pagination=apps_pagination)


@app.route("/appointments", methods=['GET','POST'])
def bookappointment():
    services = Services.query.all()
    pets = Pets.query.filter_by(OwnerId = current_user.id)
    
    if request.method == 'POST':
        ServiceName = request.form['ServiceName']
        PetName = request.form['PetName']
        OwnerId = current_user.id
        Date = request.form['StartDate']
        RelevantInfo = request.form['RelevantInfo']
      
        
        if 'Agree' not in request.form:
            flash("You must agree to the terms and conditions.", "danger")
            return render_template("forms/appointments.html", services=services, pets=pets)
        
            
        appointment_date = datetime.strptime(Date, '%Y-%m-%d')
        if appointment_date <= datetime.now():
            flash("The appointment date must be in the future.", "danger")
        else:
            appointment = Appointments(ServiceName = ServiceName, PetName = PetName, OwnerId = OwnerId,Startdate = Date, 
                    OtherInfo=RelevantInfo,Status = DEFAULT_STATUS, Time = DEFAULT_TIME,Duration = DEFAULT_DURATION)
           
            db.session.add(appointment)
            db.session.commit()
            flash("Appointment booked!","success")
          
  
    return render_template("forms/bookApp.html", services = services, pets=pets)

@app.route("/appointmentReject", methods=['GET','POST'])
def appointmentReject():
    if request.method == "POST":
        appid = request.form.get('appReject')
        message = request.form['Message']
        print(message)
        print(appid)
  
        if not appid:
            return ("id not found")
        else:
            appointment = Appointments.query.filter_by(id = appid).first()
            appointment.Status = 'Rejected'
            userid = appointment.OwnerId
            
            db.session.commit()
            
            user = Users.query.filter_by(id = userid).first()
            if user:
                email = user.Email
                EmailContent = render_template("emails/rejectedApp.html", reason = message, appid = appointment.id, petname = appointment.PetName)
                msg = Message(subject="Appointment Status", sender='iamhawiana@gmail.com', recipients=[email])
                msg.html = EmailContent
                mail.send(msg)   
                
            return redirect(url_for('vetHome'))
    

@app.route("/deleteAppointment", methods=['GET','POST'])
def deleteAppointment():
    appid = request.form.get('appid')
    print(appid)
    if not appid:
        return ("id not found")
    else:
        appointment = Appointments.query.filter_by(id = appid).first()
        db.session.delete(appointment)
        db.session.commit() 
   
        return redirect(url_for('appointmentInfo'))
    
   

######################## VET MODULE ############################

@app.route("/vetHome")
def vetHome():
    role = current_user.VetRole

    # Assuming Services and Appointments are your SQLAlchemy model classes
    serviceProvided = Services.query.filter_by(VetRole=role).first()
    
    if serviceProvided:
        identified_service = serviceProvided.ServiceName
       
        # Retrieve appointments for the identified service
        bookings = Appointments.query.filter_by(ServiceName=identified_service, Status='Pending').all()
      
        today = dt_date.today()
        app = Appointments.query.filter_by(Startdate = today).all()
    
        for book in bookings:
            if book.Status == 'Pending':
            # Process bookings into a list for rendering
                bookings_list = []
                for appointment in bookings:
                    bookings_list.append({
                        "id": appointment.id,
                        "name": appointment.PetName,
                        "date": appointment.Startdate,
                        "info": appointment.OtherInfo,
                        "status": appointment.Status
                    })
            
        if len(bookings) == 0:
            return render_template("vets/vetHome.html", bookings = [], app = app)
                     
    return render_template("vets/vetHome.html", bookings = bookings_list)

@app.route("/vetProfile",methods=['POST', 'GET'])
def vetProfile():
    # Profile picture logic
    if request.method == 'POST':
        
        if 'file' not in request.files:

            flash('No file part')
            return redirect(request.url)
         
        file = request.files['file']
        
        if file.filename == '':
            flash('No file was selected',"danger")
            return redirect(request.url)
        else: 
            print(file.filename) #Dogfinal.jpg
            file.filename = f"{current_user.id}_{file.filename}" # re-name the image to match id
            print(file.filename)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            print(f"Saving file to: {save_path}")  # Debug statement
            
            #Edit path to be stored in the database
            db_path = os.path.join('static', 'uploads', filename)
            image_path = db_path.replace('\\', '/')
            
            current_user.Profile_pic = image_path
            db.session.commit()
                
            try:
                file.save(save_path)
                
                flash('Image has been successfully uploaded',"success")
                
                    
            except Exception as e:
                flash(f"An error occurred while saving the file: {e}")
                print(f"Error: {e}")  # Debug statement
                
            
        else:
            flash('Allowed media types are - png, jpg, jpeg, gif')
            return redirect(request.url)
        
    
    return render_template("vets/vetProfile.html")

@app.route('/updateVet', methods=['POST', 'GET']) # view User profile
def updateVet():
    user = Vets.query.filter_by(id=current_user.id).first()

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('updateVet'))

    if request.method == "POST":
        Fullname = request.form["Fullname"]
        Email = request.form["Email"]
        Contact = request.form["Contact"]
        RecoveryEmail = request.form["RecoveryEmail"]
        License = user.License
        
        if is_valid_kenyan_phone_number(Contact) or " ":
            if Vets.query.filter_by(RecoveryEmail= RecoveryEmail):
                user.VetName = Fullname
                user.Email = Email
                user.Contact = Contact
                user.RecoveryEmail = RecoveryEmail
                user.License = License
            
                db.session.commit()
                flash('Details updated!', 'success')  
            else:
                flash('Email already exists')  
        else:
            flash("Invalid phone number","danger")
    else:
        flash("Form not receiving data", "danger")

    return render_template('vets/vetProfile.html', user=user)

@app.route('/updateLicense', methods=["POST"])
def updateLicense():
    vet = Vets.query.filter_by(id = current_user.id).first()
    print(vet.id)
    
    if request.method == "POST":
        file = request.files['license']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file and file.filename.endswith('.pdf'):
            filename = secure_filename(file.filename)
            save_path = os.path.join(Config.LICENSE_FOLDER, filename)
            print(f"Saving file to: {save_path}")  # Debug statement
        
            try:
                file.save(save_path)    
                vet.License = filename
                db.session.commit()
                flash("License updated!","success")
                        
            except Exception as e:
                    flash(f"An error occurred while saving the file: {e}")
                    print(f"Error: {e}")  # Debug statement
    else:
        flash("No new","danger")

    return render_template('vets/vetProfile.html', user=vet, license=license)
    

# @app.route('/', methods=['GET', 'POST'])
@app.route('/viewPets/<int:page>', methods=["GET", "POST"])
def viewPets(page=1):
    per_page = 5

    # Paginate the Pets query
    pets_pagination = Pets.query.paginate(page=page, per_page=per_page, error_out=False)
    pet_details = []

    # Fetch the owner for each pet in the current page
    for pet in pets_pagination.items:
        owner = Users.query.filter_by(id=pet.OwnerId).first()
        pet_details.append({
            "id": pet.PetID,
            "name": pet.PetName,
            "type": pet.Type,
            "species": pet.Species,
            "gender": pet.Gender,
            "ownerFullname": owner.Fullname if owner else "Unknown"
        })
    
    # Handle POST request for search functionality
    if request.method == "POST" and 'tag' in request.form:
        search_query = request.form['tag']
        print(f"Search query: {search_query}")

        # Perform search by pet name (case-insensitive)
        pets_search = Pets.query.filter(Pets.PetName.ilike(f"%{search_query}%"))

        # Paginate the search results
        pet_details = pets_search.paginate(page=page, per_page=per_page, error_out=False)

        results = []
        print(f"Matching pets: {pet_details.items}")
        for pet in pet_details.items:
           # petname = Pets.query.filter_by(id=pet.OwnerId).first()
            results.append({
                "id": pet.PetID,
                "name": pet.PetName,
                "type": pet.Type,
                "species": pet.Species,
                "gender": pet.Gender,
                "ownerFullname": owner.Fullname if owner else "Unknown"
            })

        return render_template('vets/viewPets.html', pet_details=results, pagination=pet_details)

    return render_template("vets/viewPets.html", pet_details=pet_details, pagination=pets_pagination)


@app.route('/appointmentApproval', methods=["GET","POST"])
def appStatus():
    
    if request.method == "POST":
        appid = request.form.get('appid')
        Time = request.form['Time']
        duration = request.form['Duration']
        status ="Approved"
        
        try:
            selected_time = datetime.strptime(Time, '%H:%M').time()
            start_time = time(hour=7)  # 7 AM
            end_time = time(hour=18)  # 6 PM

            if start_time <= selected_time < end_time:
                # Time is within the allowed range, proceed with updating appointment
                appointment = Appointments.query.filter_by(id=appid).first()
                if appointment:
                    appointment.Status = status
                    appointment.Time = selected_time.strftime('%H:%M')  # Assign parsed time
                    appointment.Duration = duration
                    
                    db.session.commit()
                    userid = appointment.OwnerId
                    user = Users.query.filter_by(id = userid).first()
                    if user:
                        email = user.Email
                    
                        EmailContent = render_template("emails/approvedApp.html", petname = appointment.PetName, servicename = appointment.ServiceName)
                        msg = Message(subject="Appointment Status", sender='iamhawiana@gmail.com', recipients=[email])
                        msg.html = EmailContent

                        mail.send(msg)   
            
            else:
                flash('Select working hours only', 'danger')
            
                
        except ValueError:
            return "Invalid time format"
            
    
    return redirect(url_for('vetHome'))


@app.route('/approvedAppointments/<int:page>', methods=["GET", "POST"])
def viewApproved(page=1):
    per_page = 5

    apps_pagination = Appointments.query.filter_by(Status = "Approved") \
                                    .paginate(page=page, per_page=per_page, error_out=False)
    
    # Fetch the approved appointments
   
    upp_details = []
    today = dt_date.today()
    for app in apps_pagination.items:
        if app.Startdate > today.strftime('%Y-%m-%d'):
            user = Users.query.filter_by(id=app.OwnerId).first()
            upp_details.append({
                "id": app.id,
                "servicename": app.ServiceName,
                "petname": app.PetName,
                "date": app.Startdate,
                "time": app.Time,
                "duration": app.Duration,
                "owner": user.Fullname if user else "Unknown"
            })
        
            
   # Handle POST request for search functionality
    if request.method == "POST" and 'tag' in request.form:
        search_query = request.form['tag']
        print(f"Search query: {search_query}")

        # Perform search by pet name (case-insensitive)
        apps_search = Appointments.query.filter(Appointments.PetName.ilike(f"%{search_query}%"),  Appointments.Status == 'Approved',
            Appointments.Startdate > today.strftime('%Y-%m-%d'))
        

        # Paginate the search results
        app_details = apps_search.paginate(page=page, per_page=per_page, error_out=False)

        results = []
            
        for app in app_details.items:
            user = Users.query.filter_by(id=app.OwnerId).first()
            results.append({
            "id": app.id,
            "servicename": app.ServiceName,
            "petname": app.PetName,
            "date": app.Startdate,
            "time": app.Time,
            "duration": app.Duration,
            "owner": user.Fullname if user else "Unknown"
        })
            
    
        return render_template('vets/approvedAppointments.html', upp_details=results, pagination=app_details)

    return render_template("vets/approvedAppointments.html", upp_details = upp_details,pagination=apps_pagination)


@app.route('/calendar')
def approvedCalendar():
    approved_apps = Appointments.query.filter_by(Status="Approved").all()

    appointments = []
    for app in approved_apps:
        appointments.append({
            'id': app.id,
            'title': f'{app.ServiceName} - {app.PetName}',
            'start': app.Startdate,  # Assuming Startdate is in ISO format (YYYY-MM-DD)
            'time': app.Time,         # Assuming Time is in HH:MM format
            'duration': app.Duration  # Assuming Duration is in minutes
        })

    return jsonify(appointments)

@app.route('/userCalendar')
def userCalendar():
    return render_template('forms/userCalendar.html')

@app.route('/appCalendar')
def Calendar():
    apps = Appointments.query.filter_by(OwnerId=current_user.id, Status = "Approved").all()

    userAppointments = []
    for app in apps:
        # Format each appointment as required by FullCalendar
        userAppointments.append({
            'id': app.id,
            'title': f'{app.PetName} -{app.ServiceName}',
            'start': app.Startdate,  # Assuming Startdate is in ISO format (YYYY-MM-DD)
            'time': app.Time,         # Assuming Time is in HH:MM format
            'duration': app.Duration
        })

    return jsonify(userAppointments)
    
    
@app.route('/tryP')
def trysis():
    return render_template('forms/calendartry.html')

@app.route('/getAppID', methods=['POST','GET'])
def appID():
    if request.method == "POST":
        appid = request.form['appid']
        print(appid)
        session['appid'] = appid
    return redirect(url_for('petVitals'))

@app.route('/viewVitals', methods=['POST','GET'])
def viewVitals():
    if request.method == "POST":
        appid = request.form['appid']
        selectedApp = Appointments.query.filter_by(id = appid).first() # Get appID
        appname = selectedApp.ServiceName
        date = selectedApp.Startdate
        ownerID = selectedApp.OwnerId # Get owner ID
        petname = selectedApp.PetName # Get pet name
        
        pet = Pets.query.filter_by(PetName = petname).first()
        vitals = Vitals.query.filter_by(AppointmentID = appid, PetID = pet.PetID).first()
        print(appid)
        session['appid'] = appid
    return render_template('petForms/viewVitals.html', vitals = vitals, appname = appname, petname = petname, date = date)


@app.route('/petVitals', methods=['POST','GET'])
def petVitals():
    appid = session.get("appid")
    print(appid)
    selectedApp = Appointments.query.filter_by(id = appid).first() # Get appID
    appname = selectedApp.ServiceName
    ownerID = selectedApp.OwnerId # Get owner ID
    petname = selectedApp.PetName # Get pet name
    
    # Filter to find the pet
    pet = Pets.query.filter_by(PetName = petname, OwnerId = ownerID).first()
    print(selectedApp)
    vitals = Vitals.query.filter_by(AppointmentID = selectedApp.id, PetID = pet.PetID).first()
    form = VitalsForm()
    
    if form.validate_on_submit():  
        vitals = Vitals(AppointmentID = appid, PetID = pet.PetID, Weight = form.Weight.data, Heartrate = form.Heartrate.data, Temperature = form.Temperature.data, Mobility = form.Mobility.data, Behaviour = form.Behaviour.data)
        db.session.add(vitals)
        db.session.commit()
        flash('Vitals updated', "success")
                
        petDetails = Vitals.query.filter_by(AppointmentID = appid, PetID = pet.PetID).first()
        
    else:
        return render_template('vets/petVitals.html', form=form, petname = petname, appname = appname, vitals=vitals)
    
    return redirect(url_for('petVitals'))


######################### ADMIN OPERATIONS ############################
admin_pass = generate_random_string(7)

@app.route("/addAdmin", methods=['POST', 'GET'])
def addAdmin():
    form = AdminRegisterForm()
    default_password = generate_unique_password(10)
    Hash = set_password(default_password)
    if form.validate_on_submit():
        admin = Admins(Firstname=form.Firstname.data, Lastname=form.Lastname.data, Email = form.Email.data,Password = Hash,Contact= DEFAULT_CONTACT,RecoveryEmail = DEFAULT_RECOVERYMAIL,Profile_pic= DEFAULT_PROFILE_IMAGE)
        db.session.add(admin)
        db.session.commit()
        
        EmailContent = render_template("emails/registervet.html", key=default_password)
        msg = Message(subject="Welcome Admin!", sender='iamhawiana@gmail.com', recipients=[form.Email.data])
        msg.html = EmailContent

        mail.send(msg)   
        flash("Email sent to vet","primary")
            #return render_template ('vet-verify.html', otp=key) 
    else:
        flash('Invalid data', 'danger')
        
    return render_template('soft-ui-dashboard-main/pages/addAdmin.html', form = form)

def verify_password(input_password, Password):
    return bcrypt.check_password_hash(Password, input_password)


@app.route('/authadmin/<otp>', methods=["GET","POST"])
def newAdmin(otp):
    name = current_user.Firstname
    if request.method == "POST":
        code = request.form["user-input"]
        if code == str(otp):
            return render_template("/soft-ui-dashboard-main/pages/dashboard.html", name = name) 
        else:
            return('Invalid key','danger')
    
    return render_template("admin/verify-admin.html")


# @app.route('/', methods=['GET', 'POST'])
@app.route('/viewVets/<int:page>', methods=["GET", "POST"])
def viewVets(page=1):
    per_page = 10

    # Paginate the Pets query
    vets_pagination = Vets.query.paginate(page=page, per_page=per_page, error_out=False)
    vet_details = []

    # Fetch the owner for each pet in the current page
    for vet in vets_pagination.items:
        vet_details.append({
            "id": vet.id,
            "role": vet.VetRole,
            "name": vet.VetName,
            "email": vet.Email
        })
    
    # Handle POST request for search functionality
    if request.method == "POST" and 'tag' in request.form:
        search_query = request.form['tag']
        print(f"Search query: {search_query}")

        # Perform search by pet name (case-insensitive)
        vets_search = Vets.query.filter(Vets.VetName.ilike(f"%{search_query}%"))

        # Paginate the search results
        vet_details = vets_search.paginate(page=page, per_page=per_page, error_out=False)

        results = []
        print(f"Matching vets: {vet_details.items}")
        for vet in vet_details.items:
           # petname = Pets.query.filter_by(id=pet.OwnerId).first()
            results.append({
                "id": vet.id,
                "role": vet.VetRole,
                "name": vet.VetName,
                "email": vet.Email,
            })

        return render_template('soft-ui-dashboard-main/pages/viewVets.html', pet_details=results, pagination=vet_details)

    return render_template("soft-ui-dashboard-main/pages/viewVets.html", pet_details=vet_details, pagination=vets_pagination)


# @app.route('/', methods=['GET', 'POST'])
@app.route('/viewAllAppointments/<int:page>', methods=["GET", "POST"])
def viewAllAppointments(page=1):
    per_page = 5

    # Paginate the Pets query
    app_pagination = Appointments.query.paginate(page=page, per_page=per_page, error_out=False)
    app_details = []

    # Fetch the owner for each pet in the current page
    for apps in app_pagination.items:
        owner = Users.query.filter_by(id=apps.OwnerId).first()
        app_details.append({
            "id": apps.id,
            "servicename": apps.ServiceName,
            "petname": apps.PetName,
            "owner": owner.Fullname if owner else "Unknown",
            "date" :apps.Startdate,
            "status":apps.Status
        })
    
        
    # Handle POST request for search functionality
    if request.method == "POST" and 'tag' in request.form:
        search_query = request.form['tag']
        print(f"Search query: {search_query}")

        # Perform search by pet name (case-insensitive)
        app_search = Appointments.query.filter(Appointments.PetName.ilike(f"%{search_query}%"))

        # Paginate the search results
        app_details = app_search.paginate(page=page, per_page=per_page, error_out=False)

        results = []
        print(f"Matching vets: {app_details.items}")
        for apps in app_details.items:
            owner = Users.query.filter_by(id=apps.OwnerId).first()
            results.append({
            "id": apps.id,
            "servicename": apps.ServiceName,
            "petname": apps.PetName,
            "owner": owner.Fullname if owner else "Unknown",
            "date" :apps.Startdate   
        })
    

        return render_template('soft-ui-dashboard-main/pages/viewAllAppointments.html', app_details=results, pagination=app_details)

    return render_template("soft-ui-dashboard-main/pages/viewAllAppointments.html", app_details=app_details, pagination=app_pagination)


@app.route("/adminHome")
def admin():
    # Query the database to get data
    vets = Vets.query.all()
    users = Users.query.all()
    pets = Pets.query.all()
    
    pet_count = len(pets)
    vet_count =(len(vets))
    owner_count = len(users)
    
    approved_appointments = Appointments.query.filter_by(Status='Approved').all()
    app_count = len(approved_appointments)

        
    types = [pet.Type for pet in pets]
    type_counts = {t: types.count(t) for t in set(types)}
    total_pets = len(types)  # Total number of pets

    # Calculate percentages
    percentages = {t: (count / total_pets) * 100 for t, count in type_counts.items()}

    # Matplotlib code to generate pie chart
    fig, ax = plt.subplots(figsize=(6, 4), subplot_kw=dict(aspect="equal"))

    labels = list(type_counts.keys())
    values = list(type_counts.values())

    wedges, texts, autotexts = ax.pie(values, autopct='%1.1f%%', wedgeprops=dict(width=0.6), startangle=-40)

    bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.75)
    kw = dict(arrowprops=dict(arrowstyle="-"),
              bbox=bbox_props, zorder=0, va="center")

    for i, p in enumerate(wedges):
        ang = (p.theta2 - p.theta1)/2. + p.theta1
        y = np.sin(np.deg2rad(ang))
        x = np.cos(np.deg2rad(ang))
        horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
        connectionstyle = f"angle,angleA=0,angleB={ang}"
        kw["arrowprops"].update({"connectionstyle": connectionstyle})
        ax.annotate(labels[i], xy=(x, y), xytext=(1.35*np.sign(x), 1.4*y),
                    horizontalalignment=horizontalalignment, **kw)

    # ax.set_title("Distribution of Pet Types")

    # Save the plot to a temporary file
    plot_file = '/static/images/plot.png'  # Adjust the path as needed
    plt.savefig('.' + plot_file)

    approved_appointments = Appointments.query.filter_by(Status='Approved').all()

    # Extract service names and any other relevant data for plotting
    service_names = [appointment.ServiceName for appointment in approved_appointments]
    appointment_dates = [datetime.strptime(appointment.Startdate, '%Y-%m-%d').date() for appointment in approved_appointments]
    
    # Prepare data for plotting
    unique_services = list(set(service_names))
    service_counts = [service_names.count(service) for service in unique_services]

    # Plotting with Matplotlib
    plt.figure(figsize=(6, 4)) #x, y
    plt.plot(unique_services, service_counts, marker='o', linestyle='-', color='b')
    # plt.title('Service Distribution of Approved Appointments')
    plt.xlabel('Service Name')
    plt.ylabel('Number of Appointments')
    plt.xticks(rotation=10)
    plt.grid(True)
    plt.tight_layout()

    # Save the plot to a file or display it directly in Flask
    plot_path = 'static/images/service_distribution.png'
    plt.savefig(plot_path)  # Save the plot to a file
    plt.close()

    #Upcoming appointments list
    today = dt_date.today()
    upcoming_appointments = Appointments.query.filter(Appointments.Status=='Approved', Appointments.Startdate > today.strftime('%Y-%m-%d')).all()
    
   # Total cost of services approved
    apps = Appointments.query.filter_by(Status = "Approved").all()
    total_cost = 0
    for app in apps:
        service = app.ServiceName
        
        serv = Services.query.filter_by(ServiceName = service).all()
        
        for service in serv:
            total_cost += service.Cost 
            

    return render_template('soft-ui-dashboard-main/pages/dashboard.html',vets=vets, plot_file=plot_file, pet_count = pet_count, total_cost = total_cost,
                           app_count = app_count, owner_count = owner_count, vet_count= vet_count, approved_appointments = upcoming_appointments, plot_path=plot_path)


@app.route("/adminProfile", methods=['POST', 'GET'])
def adminProfile():
    return render_template("admin/adminProfile.html")

@app.route('/updateAdmin', methods=['POST', 'GET']) # view User profile
def updateAdmin():
    user = Admins.query.filter_by(id=current_user.id).first()

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('uploadProfile'))

    if request.method == "POST":
        Firstname = request.form["Firstname"]
        Lastname = request.form["Lastname"]
        Email = request.form["Email"]
        RecoveryEmail = request.form["RecoveryEmail"]
        Contact = request.form["Contact"]
        
        if is_valid_kenyan_phone_number(Contact) or " ":
            user.Firstname = Firstname
            user.Lastname = Lastname
            user.Email = Email
            user.RecoveryEmail = RecoveryEmail
            user.Contact = Contact

            db.session.commit()
            flash('Details updated!', 'success')    
        else:
            flash("Invalid phone number","danger")
    else:
        flash("Form not receiving data", "danger")

    return redirect(url_for('adminProfile'))


@app.route("/addServices", methods=['POST', 'GET'])
def addServices():
    AddService = AddServiceForm()
    roles = VetRoles.query.all() #get all the services
    
    # Create a list of tuples (id, role name) for SelectField choices
    AddService.VetRole.choices = [(str(role.VetRoleID), role.VetRoleName) for role in roles]
    
    role_id = AddService.VetRole.data
    role = VetRoles.query.get(role_id)
    if AddService.validate_on_submit():
        service = Services(ServiceName=AddService.ServiceName.data, VetRole=role.VetRoleName,Description=AddService.Description.data,Cost=AddService.Cost.data )
        print(service)
       
        db.session.add(service)
        db.session.commit()
        flash("Service added successfully", "success")
        
    return render_template('soft-ui-dashboard-main/pages/addServices.html',roles=roles, AddService = AddService)
    


@app.route("/addVetRole", methods=['POST', 'GET'])
def addVetRole():
    AddVRole = VetRoleForm()
    print(AddVRole.VetRoleName.data) #check if the form is receiving data
    print(AddVRole.Description.data)
    if AddVRole.validate_on_submit():
        vetrole = VetRoles(VetRoleName=AddVRole.VetRoleName.data, Description=AddVRole.Description.data )
        db.session.add(vetrole)
        db.session.commit()
        flash("Vet role added", "success")
    # else:
    #     flash('Form not validating', 'success')
        
    return render_template('soft-ui-dashboard-main/pages/addVetRole.html', AddVRole = AddVRole)

@app.route('/download_csv', methods=['POST'])
def download_csv():
    format = request.form['format']

    # Fetch data from Appointments table
    appointments = Appointments.query.all()
    data = [{'ID': appointment.id,
             'Service': appointment.ServiceName,
             'Pet name': appointment.PetName,
             'OwnerID': appointment.OwnerId,
             'Date': appointment.Startdate}  # Format date as needed
            for appointment in appointments]

    # Convert data to pandas DataFrame
    df = pd.DataFrame(data)
    
      # Check and convert Date column to datetime if it's not already
    if 'Date' in df.columns and isinstance(df['Date'][0], str):
        df['Date'] = pd.to_datetime(df['Date'])  # Convert string to datetime if necessary


    # Prepare the file based on selected format
    if format == 'csv':
        buffer =  io.BytesIO()
        df.to_csv(buffer, index=False)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name='Appointments.csv', mimetype='text/csv')
    elif format == 'excel':
        buffer = io.BytesIO()
        df.to_excel(buffer, index=False)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name='Appointments.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/downloadVets', methods=['POST'])
def downloadVets():
    format = request.form['format']

    # Fetch data from Appointments table
    vets = Vets.query.all()
    data = [{'ID': vet.id,
             'Service': vet.VetRole,
             'Vet name': vet.VetName,
             'Email': vet.Email,
             'Date': vet.Gender}  # Format date as needed
            for vet in vets]

    # Convert data to pandas DataFrame
    df = pd.DataFrame(data)
    

    # Prepare the file based on selected format
    if format == 'csv':
        buffer =  io.BytesIO()
        df.to_csv(buffer, index=False)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name='Vets.csv', mimetype='text/csv')
    elif format == 'excel':
        buffer = io.BytesIO()
        df.to_excel(buffer, index=False)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name='Vets.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')



@app.route("/addVet", methods=["POST", "GET"])
def addVet():
    RegisterVet = RegisterVetForm()
    roles = VetRoles.query.all() #get all the services
    
    # Create a list of tuples (id, role name) for SelectField choices
    RegisterVet.VetRole.choices = [(str(role.VetRoleID), role.VetRoleName) for role in roles]
    role_id = RegisterVet.VetRole.data
    role = VetRoles.query.get(role_id)
    DEFAULT_PROFILE_IMAGE = 'static/images/default.png'
        
    if RegisterVet.validate_on_submit():
        file = request.files['license']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
    
        if file and file.filename.endswith('.pdf'):
            filename = secure_filename(file.filename)
            save_path = os.path.join(Config.LICENSE_FOLDER, filename)
            print(f"Saving file to: {save_path}")  # Debug statement
                
            try:
                file.save(save_path)
                
                #flash('Image has been successfully uploaded')
                # image_url = url_for('uploaded_file', filename=filename)
            except Exception as e:
                flash(f"An error occurred while saving the file: {e}")
                print(f"Error: {e}")  # Debug statement
       
            Password = generate_unique_vetpassword(12)
            HashedP = set_password(Password)
            vet = Vets(VetRole = role.VetRoleName, VetName = RegisterVet.VetName.data, Email=RegisterVet.Email.data, Gender=RegisterVet.Gender.data, Password= HashedP,Contact= DEFAULT_CONTACT,RecoveryEmail = DEFAULT_RECOVERYMAIL,License=filename,Profile_pic=DEFAULT_PROFILE_IMAGE)
           
            db.session.add(vet)
            db.session.commit()
            
            EmailContent = render_template("emails/registervet.html", key=Password)
            msg = Message(subject="Karibu Daktari!", sender='iamhawiana@gmail.com', recipients=[RegisterVet.Email.data])
            msg.html = EmailContent

            mail.send(msg)   
            flash("Email sent to vet","primary")
            #return render_template ('vet-verify.html', otp=key) 
            
        else:
            flash("Please upload the license", "danger")
  
    # if RegisterVet.validate_on_submit():
            
    return render_template('soft-ui-dashboard-main/pages/addVet.html', RegisterVet = RegisterVet, roles=roles)
        # else:
        #     flash('Invalid file type. Please upload a PDF.', 'danger')
        #     return redirect(request.url)
        

@app.route("/viewServices")
def viewServices():
    services = Services.query.all()
    return render_template("soft-ui-dashboard-main/pages/viewServices.html", services=services)


@app.route("/displayServices")
def displayServices():
    services = Services.query.all()
    return render_template("Services.html", services=services)



@app.route("/appointmentLists")
def appointmentlists():
    
    appointments = Appointments.query.filter_by(OwnerId=current_user.id).all()
    if len(appointments) == 0:
        return ("No appointment")
    
    return render_template("appLists.html", appointments = appointments)

with app.app_context():
    db.create_all()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

if __name__ == "__main__":
    app.run(debug=True)
