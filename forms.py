from flask_wtf import FlaskForm 
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, DataRequired, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class UpdateForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    retypePassword = PasswordField('Retype Password', validators=[InputRequired(), Length(min=8, max=80)])
    image = FileField('Update Profile Picture', validators=[FileAllowed(['png','jpg','jpeg'])])
    submit = SubmitField('Submit')
    
class PostQuestionForm(FlaskForm):
    question_title = StringField('Title', validators=[InputRequired(), Length(min=4, max=100)])
    question = TextAreaField('Question', render_kw={"rows": 3}, validators=[InputRequired(), Length(max=1000)])
    submit = SubmitField('Submit')

class SearchForm(FlaskForm):
    submit = SubmitField('Next')

class AnswerForm(FlaskForm):
    answer = TextAreaField(render_kw={"rows": 3}, validators=[InputRequired(),Length(max=1000)])
    submit = SubmitField('Submit')

