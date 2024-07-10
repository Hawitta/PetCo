from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, Form, validators,IntegerField,RadioField,SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, NumberRange
import re

db = SQLAlchemy()
bcrypt = Bcrypt()

DEFAULT_PROFILE_IMAGE = 'static/images/profile-user.png'

DEFAULT_PROFILE_PET = 'static/images/pet-profile.png'
DEFAULT_CONTACT = ""
DEFAULT_ADDRESS = ""
DEFAULT_VET_PROFILE = 'static/images/profile-user.png'
DEFAULT_RECOVERYMAIL = " "
DEFAULT_STATUS = "Pending"
DEFAULT_DURATION = " "
DEFAULT_TIME = " "

class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    Fullname = db.Column(db.String(250), nullable=False)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Contact = db.Column(db.String(15), unique=True, nullable=True, default=DEFAULT_CONTACT)
    Address = db.Column(db.String(250), unique=False, nullable=True, default=DEFAULT_ADDRESS)
    Password = db.Column(db.String(250), nullable=False)
    Profile_pic = db.Column(db.String(250), nullable=False, default=DEFAULT_PROFILE_IMAGE)
    role = db.Column(db.String(50), nullable=False, default='user')
 
    def get_id(self):
        return f'user_{self.id}'
    # def __init__(self, Fullname, Email, Password,Contact=None, Address=None ):
    #     self.Fullname = Fullname
    #     self.Email = Email
    #     self.Contact = Contact
    #     self.Address = Address
    #     self.Password = self.set_password(Password)
        
    def check_password(self, Password):
        return bcrypt.check_password_hash(self.Password, Password)

    def set_password(self, Password):
        return bcrypt.generate_password_hash(Password).decode('utf-8')
    

class Pets(UserMixin, db.Model):
    __tablename__ = 'pets'
    PetID = db.Column(db.Integer, primary_key=True)
    PetName = db.Column(db.String(250), nullable=False)
    Type = db.Column(db.String(250), nullable=False)
    Species = db.Column(db.String(250), nullable=False)
    DateOfBirth = db.Column(db.String(250), nullable=False)
    Gender = db.Column(db.String(250), nullable=False)
    OwnerId = db.Column(db.Integer, db.ForeignKey('users.id'))
    Profile_pic = db.Column(db.String(250), nullable=False, default=DEFAULT_PROFILE_PET)

class VetRoles(UserMixin, db.Model):
    __tablename__ = 'vetroles'
    VetRoleID = db.Column(db.Integer, primary_key=True)
    VetRoleName = db.Column(db.String(250), nullable=False, unique=True)
    Description = db.Column(db.String(250), unique=True, nullable=False)
    
class Services(UserMixin, db.Model):
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    ServiceName = db.Column(db.String(60), nullable=False)
    VetRole = db.Column(db.String(250),db.ForeignKey('vetroles.VetRoleName'),nullable=False)
    Description = db.Column(db.String(250), unique=True, nullable=False)
    Cost = db.Column(db.Integer, nullable=False)

class Vets(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    VetRole = db.Column(db.String(250), db.ForeignKey('services.VetRole'), nullable=False)
    VetName = db.Column(db.String(250), nullable=False)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Password = db.Column(db.String(250), nullable=False)
    Gender = db.Column(db.String(250), nullable=False)
    Contact = db.Column(db.String(15), nullable=True, default=DEFAULT_CONTACT)
    RecoveryEmail = db.Column(db.String(250), nullable=True, default=DEFAULT_RECOVERYMAIL)
    License = db.Column(db.String(250), nullable=False)
    Profile_pic = db.Column(db.String(250), nullable=False, default=DEFAULT_VET_PROFILE)
    role = db.Column(db.String(50), nullable=False, default='vet')
    
    def get_id(self):
        return f'vet_{self.id}'
    
    def check_password(self, Password):
        return bcrypt.check_password_hash(self.Password, Password)

    def set_password(self, Password):
        return bcrypt.generate_password_hash(Password).decode('utf-8')
    

class Admins(UserMixin, db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    Firstname = db.Column(db.String(250), nullable=False)
    Lastname = db.Column(db.String(250), nullable=False)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Password = db.Column(db.String(250), nullable=False)
    Contact = db.Column(db.String(15), nullable=True, default=DEFAULT_CONTACT)
    RecoveryEmail = db.Column(db.String(250), nullable=True, default=DEFAULT_RECOVERYMAIL)
    Profile_pic = db.Column(db.String(250), nullable=False, default=DEFAULT_PROFILE_IMAGE)
    role = db.Column(db.String(50), nullable=False, default='admin')
    
    def get_id(self):
        return f'admin_{self.id}'
    
    def check_password(self, Password):
        return bcrypt.check_password_hash(self.Password, Password)

    def set_password(self, Password):
        return bcrypt.generate_password_hash(Password).decode('utf-8')
    
class Appointments(UserMixin, db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    ServiceName = db.Column(db.String(250), db.ForeignKey('services.ServiceName',onupdate="CASCADE", ondelete="CASCADE"),nullable=False)
    PetName = db.Column(db.String(250), db.ForeignKey('pets.PetName', onupdate="CASCADE", ondelete="CASCADE"),nullable=False)
    OwnerId = db.Column(db.String(250), db.ForeignKey('pets.OwnerId',onupdate="CASCADE", ondelete="CASCADE"), nullable=False)
    Startdate = db.Column(db.String(250), nullable=False)
    OtherInfo = db.Column(db.String(250), nullable=False)
    Status = db.Column(db.String(30), nullable=True, default=DEFAULT_STATUS)
    Time = db.Column(db.String(20), nullable=True, default=DEFAULT_TIME)
    Duration = db.Column(db.String(100), nullable=False, default=DEFAULT_DURATION)

    
class Vitals(UserMixin, db.Model):
    __tablename__ = 'vitals'
    id = db.Column(db.Integer, primary_key=True)
    AppointmentID = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=False)
    PetID = db.Column(db.Integer, db.ForeignKey('pets.PetID'),nullable=False)
    Weight = db.Column(db.Integer, nullable=False)
    Heartrate = db.Column(db.Integer, nullable=False)
    Temperature = db.Column(db.Integer, nullable=False)
    Mobility = db.Column(db.String(30), nullable=True)
    Behaviour = db.Column(db.String(20), nullable=True)

