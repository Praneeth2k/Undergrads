from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField ,IntegerField, SubmitField,RadioField
from wtforms.validators import InputRequired, Email, Length, EqualTo 
from flask_wtf.file import FileField,FileRequired



class RegisterForm(FlaskForm):

    types = RadioField('What Are You : ', choices = [('1','Single User'),('2','Community')])
    name = StringField('Name', validators=[InputRequired(), Length(min=4, max=40)])
    mobile = StringField('Mobile', validators=[InputRequired(), Length(min=10, max=10)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    address= StringField('Address',validators=[InputRequired()])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=25)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(),Length(min=8, max=25),EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):

    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=25)])
    remember = BooleanField('Remember me')
    submit = SubmitField('Sign In')


