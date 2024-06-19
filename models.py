from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, Form, validators,IntegerField,RadioField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, NumberRange
import re

db = SQLAlchemy()
bcrypt = Bcrypt()

DEFAULT_PROFILE_IMAGE = 'static/images/profile-user.png'

DEFAULT_PROFILE_PET = 'static/images/pet-profile.png'
DEFAULT_CONTACT = ""
DEFAULT_ADDRESS = ""

class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    Fullname = db.Column(db.String(250), nullable=False)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Contact = db.Column(db.String(15), unique=True, nullable=True, default=DEFAULT_CONTACT)
    Address = db.Column(db.String(250), unique=True, nullable=True, default=DEFAULT_ADDRESS)
    Password = db.Column(db.String(250), nullable=False)
    Profile_pic = db.Column(db.String(250), nullable=False, default=DEFAULT_PROFILE_IMAGE)

    # def __init__(self, Fullname, Email, Password):
    #     self.Fullname = Fullname
    #     self.Email = Email
    #     self.Contact = DEFAULT_CONTACT
    #     self.Address = DEFAULT_ADDRESS
    #     self.Password = self.set_password(Password)
    
    

    def check_password(self, Password):
        return bcrypt.check_password_hash(self.Password, Password)

    def set_password(self, Password):
        return bcrypt.generate_password_hash(Password).decode('utf-8')
    

class Pets(UserMixin, db.Model):
    PetID = db.Column(db.Integer, primary_key=True)
    PetName = db.Column(db.String(250), nullable=False)
    Type = db.Column(db.String(250), nullable=False)
    Species = db.Column(db.String(250), nullable=False)
    Age = db.Column(db.Integer, nullable=False)
    Gender = db.Column(db.String(250), nullable=False)
    OwnerId = db.Column(db.Integer, db.ForeignKey('users.id'))
    Profile_pic = db.Column(db.String(250), nullable=False, default=DEFAULT_PROFILE_PET)


class Services(UserMixin, db.Model):
    ServiceId = db.Column(db.Integer, primary_key=True)
    ServiceName = db.Column(db.String(60), nullable=False)
    Description = db.Column(db.String(250), unique=True, nullable=False)
    Cost = db.Column(db.Integer, nullable=False)


class Vets(UserMixin, db.Model):
    VetId = db.Column(db.Integer, primary_key=True)
    VetName = db.Column(db.String(250), nullable=False)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Password = db.Column(db.String(250), nullable=False)

    def __init__(self, Fullname, Email, Password):
        self.Fullname = Fullname
        self.Email = Email
        self.Password = self.set_password(Password)

    def check_password(self, Password):
        return bcrypt.check_password_hash(self.Password, Password)

    def set_password(self, Password):
        return bcrypt.generate_password_hash(Password).decode('utf-8')

class RegistrationForm(FlaskForm):
    Fullname = StringField('Fullname', validators=[DataRequired()])
    Email = StringField('Email', [Email()])
    Password = PasswordField('Password', validators=[Length(min=6)])
    Confirm_Password = PasswordField('Confirm_Password', validators=[DataRequired()])
    Submit = SubmitField('Create_Account')

    def validate_Email(self, field):
        if Users.query.filter_by(Email=field.data).first():
            raise ValidationError('Email already exists')

    def validate_Password(self, field):
        if field.data != self.Confirm_Password.data: 
            raise ValidationError('Passwords must match')
        else:
            if not re.search(r"[A-Z]", field.data):
                raise ValidationError('Password must contain at least one uppercase letter.')
            else:
                if not re.search(r"[0-9]", field.data):
                    raise ValidationError('Password must contain at least one number.')

class LoginForm(FlaskForm):
    Email = StringField('Email')
    Password = PasswordField('Password')
    Submit = SubmitField('Login')

    def validate_Email(self, field):
        if not Users.query.filter_by(Email=field.data).first():
            raise ValidationError('Invalid email')

    def validate_Password(self, field):
        user = Users.query.filter_by(Email=self.Email.data).first()
        if not user or not user.check_password(field.data):
            raise ValidationError('Invalid password')

class PetRegistrationForm(FlaskForm):
    PetName = StringField('PetName', validators=[DataRequired()])
    Type = StringField('Type', validators=[DataRequired()])
    Species = StringField('Species', validators=[Length(min=6)])
    Age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=0, max=30)])
    Gender = RadioField('Gender', choices=[('male', 'Male'), ('female', 'Female')], validators=[DataRequired()])
    
    def validate_petname(self, field):
        if Pets.query.filter_by(PetName = field.data).first():
            raise ValidationError('Pet already exists')

