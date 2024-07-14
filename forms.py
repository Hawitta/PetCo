from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from models import Pets,Users,Vets,Admins
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, Form, validators,IntegerField,RadioField,SelectField,FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, NumberRange
import re

db = SQLAlchemy()
bcrypt = Bcrypt()

DEFAULT_PROFILE_IMAGE = 'static/images/profile-user.png'

DEFAULT_PROFILE_PET = 'static/images/pet-profile.png'
DEFAULT_CONTACT = ""
DEFAULT_ADDRESS = ""
DEFAULT_VET_PROFILE = 'static/images/profile-user.png'


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
            if not re.search(r"[A-Z]", field.data) and not re.search(r"[0-9]", field.data) :
                raise ValidationError('Password must contain at least one uppercase letter.')
            else:
                if not re.search(r"[0-9]", field.data):
                    raise ValidationError('Password must contain at least one number.')

class LoginForm(FlaskForm):
    Email = StringField('Email')
    Password = PasswordField('Password')
    Submit = SubmitField('Login')

    # def validate_Email(self, field):
    #     if not Users.query.filter_by(Email=field.data).first():
    #         raise ValidationError('Invalid email')

    # def check_password(self, Password):
    #     return bcrypt.check_password_hash(self.Password, Password)

    # def validate_Password(self, field):
    #     user = Users.query.filter_by(Email=self.Email.data).first()
    #     if not user.check_password(field.data):
    #         raise ValidationError('Invalid password')

class PetRegistrationForm(FlaskForm):
    PetName = StringField('PetName', validators=[DataRequired()])
    Type = StringField('Type', validators=[DataRequired()])
    Species = StringField('Species', validators=[Length(min=6)])
    Age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=0, max=30)])
    Gender = RadioField('Gender', choices=[('male', 'Male'), ('female', 'Female')], validators=[DataRequired()])
    
    def validate_petname(self, field):
        if Pets.query.filter_by(PetName = field.data).first():
            raise ValidationError('Pet already exists')

class AddServiceForm(FlaskForm):
    ServiceName = StringField('ServiceName', validators=[DataRequired()])
    VetRole = SelectField('VetRole', validators=[DataRequired()])
    Description = StringField('Description', validators=[DataRequired()])
    Cost = IntegerField('Cost', validators=[DataRequired()])
    Submit = SubmitField('AddService')

class VetRoleForm(FlaskForm):
    VetRoleName = StringField('VetRole', validators=[DataRequired()])
    Description = StringField('Description', validators=[DataRequired()])
    Submit = SubmitField('AddRole')

class RegisterVetForm(FlaskForm):
    VetRole = SelectField('VetRole', validators=[DataRequired()], choices=[])
    VetName = StringField('VetName', validators=[DataRequired()])
    Email = StringField('Email', validators=[DataRequired(), Email()])
    Gender = RadioField('Gender', choices=[('male', 'Male'), ('female', 'Female')], validators=[DataRequired()])
    License = StringField('license')
    Submit = SubmitField('RegisterVet')
    
    def validate_Email(self, field):
        if Vets.query.filter_by(Email=field.data).first():
            raise ValidationError('Email already exists')


class AdminRegisterForm(FlaskForm):
    Firstname = StringField('Firstname', validators=[DataRequired()])
    Lastname = StringField('Lastname', validators=[DataRequired()])
    Email = StringField('Email', [Email()])
    Submit = SubmitField('AddAdmin')

    def validate_Email(self, field):
        if Admins.query.filter_by(Email=field.data).first():
            raise ValidationError('Email already exists')

    def validate_Password(self, field):
        if field.data != self.Confirm_Password.data: 
            raise ValidationError('Passwords must match')
        else:
            if not re.search(r"[A-Z]", field.data) and not re.search(r"[0-9]", field.data) :
                raise ValidationError('Password must contain at least one uppercase letter.')
            else:
                if not re.search(r"[0-9]", field.data):
                    raise ValidationError('Password must contain at least one number.')


class VitalsForm(FlaskForm):
    Weight = IntegerField('Weight', validators=[DataRequired(), NumberRange(min=0, max=30)])
    Heartrate = IntegerField('Heartrate', validators=[DataRequired(), NumberRange(min=0, max=100)])
    Temperature = IntegerField('Temperature', validators=[DataRequired(), NumberRange(min=0, max=100)])
    Mobility = StringField('Mobility', validators=[DataRequired()])
    Behaviour = StringField('Behaviour', validators=[DataRequired()])
