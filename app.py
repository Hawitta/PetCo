from flask import Flask, render_template,session,redirect,abort, request,flash,g,url_for
from google_auth_oauthlib.flow import Flow
from flask_mail import Mail,Message
from flask_login import LoginManager, login_user, logout_user, current_user,login_required
from flask_session import Session
from models import Users,RegistrationForm,db,LoginForm,PetRegistrationForm,Pets
from random import *
from config import Config
import pathlib,os
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt     
from googleapiclient.discovery import build 
from pathlib import Path
from io import BytesIO
import base64
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from bcrypt import hashpw, gensalt
import re

bcrypt = Bcrypt()
otp =randint(000000,999999)

app = Flask(__name__)
app.secret_key = 'myfishsucksmiamiaa'
login_manager = LoginManager()
login_manager.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///owners.db"

db.init_app(app)

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


@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

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
    Logform = LoginForm()
    if Logform.validate_on_submit():
        user = Users.query.filter_by(Email=Logform.Email.data).first()
        login_user(user) 
        otp_str = str(otp)
        Email = Logform.Email.data
        EmailContent = render_template("emails/log-otp-email.html", otp=otp_str)
        msg = Message(subject="Welcome back!", sender='iamhawiana@gmail.com', recipients=[Email])
        msg.html = EmailContent

        mail.send(msg)   
        login_user(user)
        flash('Email has been sent your account', 'primary')
        return render_template ('login-verify.html', otp=otp) 
        
        #return render_template('home.html')  # Redirect to landing instead of render_template

    return render_template("forms/SignIn.html", Logform=Logform)

@app.route('/login-check/<otp>', methods=["GET","POST"])
def logchecker(otp):
    if request.method == "POST":
        code = request.form["user-otp"]
        if code == str(otp):
            # flash("Account created", "success")
            return render_template("home.html") #reset-password.html
        else:
            flash ('invalid otp','danger')


# REGISTER USER
@app.route('/register', methods=["GET","POST"])
def register():
    Regform = RegistrationForm()
    if Regform.validate_on_submit():
            DEFAULT_PROFILE_IMAGE = 'static/images/default.png'
            DEFAULT_CONTACT = ''
            DEFAULT_ADDRESS = ''
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

@app.route('/auth-checker/<otp>', methods=["GET","POST"])
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


#FORGOT PASSWORD AND RESET
@app.route('/reset', methods=["GET","POST"])
def reset(): 
    if request.method == "POST":
        Email = current_user.Email
        # Email = session.get('reset_email')
        Password = request.form['New_Password']
        New_Password = request.form['Confirm_Password']  
        user = Users.query.filter_by(Email=Email).first()
        #user = Users.query.filter_by(Email=self.Email.data).first()
        if Password == New_Password:
            user.Password = bcrypt.generate_password_hash(Password).decode('utf-8')
            db.session.commit()
            flash("Password updated successfully!", "primary")
            return redirect(url_for("homee")) #
                
        else:
            flash("Password not match")
            return redirect(url_for('login'))
    else:
            flash("Not validating",'danger')
                
    return render_template("forms/reset-password.html")


@app.route('/reset-email', methods=["GET","POST"])
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

@app.route('/conf_password', methods=["GET","POST"])
def cdonf():
    if request.method == "POST":
        auth = request.form["user-otp"]
        print(auth)
    return render_template('forms/forgot-password.html')

@app.route('/forgot', methods=["GET","POST"])
def forgot():
    return render_template("forms/forgot-password.html")

@app.route('/verify', methods=["GET","POST"])
def tryi():
    return render_template("verify.html")

@app.route("/auth", methods=["GET", "POST"])
def autho():
    return render_template("forms/SignIn.html")

@app.route("/logout")
def logout():
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

    user = Users(Fullname=user_info["name"], Email=user_info["email"], Password="dummyinfo")
    db.session.add(user)
    db.session.commit()

    # Return to main page
    return render_template("home.html")


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

    if Users.query.filter_by(Email=user_info['email']).first():
        #flash("Not registered in the database", "danger")

        otp_str = str(otp)
        Email = user_info['email']
        EmailContent = render_template("emails/google-email.html", otp=otp_str)
        msg = Message(subject="Welcome to PetCo", sender='PetCo', recipients=[Email])
        msg.html = EmailContent

        mail.send(msg)   

        # flash('OTP has been sent your account', 'primary')
        # return render_template ('google-otp.html', otp=otp) 
        return render_template('home.html')
    else:
        flash("Account does not exist","danger")
        return redirect(url_for('register'))

    return render_template("landing.html")

############################################################################



@app.route('/reg-reset',methods=["GET","POST"]) #reset password after user registration
def newreset():
    if current_user.is_authenticated:
        if request.method == "POST":
            p1 = request.form['New_Password']
            p2 = request.form['Confirm_Password']  
            if p1 == p2:
                current_user.Password = current_user.set_password(p1)
                db.session.commit()
                return redirect(url_for('login'))
            else:
                flash("Password not match")
            # return "Password reset successfully"
        else:
            flash("Not validating",'danger')
    else:
        return redirect(url_for('login'))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


@app.route('/userProfile', methods=['POST', 'GET'])
def uploadProfile():
    
    # Profile picture logic
    if request.method == 'POST':
        
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
         
        file = request.files['file']
        
        if file.filename == '':
            flash('No file was selected')
            return redirect(request.url)
        else: 
            print(file.filename) #Dogfinal.jpg
            file.filename = f"{current_user.id}_{file.filename}" # re-name the image to match petid
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
            
                flash('Image has been successfully uploaded')
               # image_url = url_for('uploaded_file', filename=filename)
            except Exception as e:
                flash(f"An error occurred while saving the file: {e}")
                print(f"Error: {e}")  # Debug statement
            
            return render_template('userProfile.html',filename=filename)
        else:
            flash('Allowed media types are - png, jpg, jpeg, gif')
            return redirect(request.url)
    
    return render_template('userProfile.html')

@app.route('/uploads/<filename>')
def display_profile(filename):
    return redirect(url_for('static', filename='uploads/' +filename), code=301)

def is_valid_kenyan_phone_number(phone_number):
    # Regular expression to match Kenyan phone numbers
    # Valid format: 10 digits starting with 07, 01, 07x, or 01x
    pattern = r'^(07\d{8}|01\d{8}|+254\d{7}|01\d{7})$'

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


# @app.route('/pet-list')
# def display_pet_list():
#     user = current_user.id
#     pets = Pets.query.filter_by(OwnerId=user).all()
#     if len(pets) == 1:
#         "you have one pet"
#     return render_template ("userProfile.html", pets = pets)


@app.route('/delete-profile-picture', methods=['POST']) #Delete pet owner profile picture
def delete_profile_picture():
    current_user.Profile_pic = None 
    db.session.commit()
    return redirect(url_for('uploadProfile'))


@app.route('/bookAppointment', methods=['POST', 'GET'])  #Book appointment
def book_appointment():
    user = current_user.id
    pets = Pets.query.filter_by(OwnerId=user).all()
    
    if len(pets) == 0:
        flash("You have no pets registered", "danger")
    # if request.method == 'POST':
    #     selected_pet = request.form['pet']
    #     # Process the selected pet here
    #     return f'Selected pet: {selected_pet}'

    return render_template('forms/appointments.html',  pets=pets)


##################### PET MODULE ################################

@app.route('/addPet', methods=["POST","GET"]) #register new pets
@login_required
def addPet():
    
    if request.method == "POST":
        DEFAULT_PROFILE_IMAGE = 'static/images/pet-profile.png'
        PetName = request.form['PetName']
        Type = request.form['Type']
        Species = request.form['Species']
        Age = request.form['Age']
        Gender = request.form['Gender']
        
        pet = Pets(PetName=PetName,Type=Type,Species=Species,Age=Age,Gender=Gender,OwnerId=current_user.id, Profile_pic=DEFAULT_PROFILE_IMAGE)
        db.session.add(pet)
        db.session.commit()
        flash('New pet registered','success')
   
    return render_template ("petForms/addPet.html")


@app.route('/viewPet',  methods=["POST","GET"])    #view list of pets
def viewPet():
    user_pets = Pets.query.filter_by(OwnerId=current_user.id).all()
    return render_template('petForms/viewPets/viewPets.html', user_pets=user_pets)

@app.route('/view-pet-profile/<int:first_pet>')    # view edit pet profile
def view_pet_profile(first_pet):
    pet = Pets.query.filter_by(PetID=first_pet).first()
    # profile_pic = pet.Profile_pic
    print(pet)
    print(current_user)
    return render_template('petForms/viewProfile/petProfile.html',pet=pet)


@app.route('/petProfilePic/<pet>', methods=['POST', 'GET'])   #upload pet profile picture
def uplProfile(pet):
    pet = Pets.query.filter_by(PetID=pet).first()
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
         
        file = request.files['file']
        print(file)
        
        if file.filename == '':
            flash('No file was selected')
            return redirect(request.url)
        else:
            print(file.filename) #Dogfinal.jpg
            file.filename = f"{pet.PetID}_{file.filename}" # re-name the image to match petid
            print(file.filename)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            print(f"Saving file to: {save_path}")  # Debug statement
            
            db_path = os.path.join('static', 'uploads', filename)
            image_path = db_path.replace('\\', '/')

            pet.Profile_pic = image_path
            db.session.commit()
            
            try:
                file.save(save_path)
            
                flash('Image has been successfully uploaded')
               # image_url = url_for('uploaded_file', filename=filename)
            except Exception as e:
                flash(f"An error occurred while saving the file: {e}")
                print(f"Error: {e}")  # Debug statement
            
            return render_template('petForms/viewProfile/petProfile.html',filename=filename, pet=pet)
        else:
            flash('Allowed media types are - png, jpg, jpeg, gif')
            return redirect(request.url)
    
    return render_template('petForms/viewProfile/petProfile.html')

@app.route('/delete-pet-picture/<int:pet>', methods=['POST'])  #Delete pet picture
def delete_pet_picture(pet):
    pet.Profile_pic = None 
    db.session.commit()
    return redirect(url_for('uploadPetPic'))



######################## VET MODULE ############################




























######################### ADMIN OPERATIONS ############################
@app.route("/adminHome")
def admin():
    fig, ax = plt.subplots(figsize=(4, 3))
    fruits = ['apple', 'blueberry', 'cherry', 'orange']
    counts = [40, 100, 30, 55]
    bar_labels = ['red', 'blue', '_red', 'orange']
    bar_colors = ['tab:red', 'tab:blue', 'tab:red', 'tab:orange']

    ax.bar(fruits, counts, label=bar_labels, color=bar_colors)
    ax.set_ylabel('Fruit supply')
    ax.set_title('Fruit supply by kind and color')
    ax.legend(title='Fruit color')

    # Save bar chart to a temporary file
    bar_img = BytesIO()
    plt.savefig(bar_img, format='png', dpi=100)
    bar_img.seek(0)
    bar_plot_url = base64.b64encode(bar_img.getvalue()).decode()
    plt.close()

    # Create the pie chart
    labels = 'Birds', 'Cats', 'Dogs', 'Guinea Pig'
    sizes = [15, 30, 45, 10]

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%')
    # ax.set_title('Pie chart')
    
    # Save pie chart to a temporary file
    pie_img = BytesIO()
    plt.savefig(pie_img, format='png', dpi=100)
    pie_img.seek(0)
    pie_plot_url = base64.b64encode(pie_img.getvalue()).decode()
    plt.close()

    return render_template('soft-ui-dashboard-main/pages/dashboard.html', bar_plot_url=bar_plot_url, pie_plot_url=pie_plot_url)

@app.route("/addServices")
def addServices():
    return render_template('soft-ui-dashboard-main/pages/addServices.html')


@app.route("/addVet")
def addVet():
    return render_template('soft-ui-dashboard-main/pages/addServices.html')


@app.route("/services")
def displayServices():
    return render_template('services.html')

with app.app_context():
    db.create_all()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

if __name__ == "__main__":
    app.run(debug=True)
