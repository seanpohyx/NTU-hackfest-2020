from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, DataRequired, EqualTo
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

import os
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(12).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://ravcmlsuuogjpn:e8f5ba9ff258e4170cd8a982ff3ac9981727cd3c9030ba73cb4048d6b67c7622@ec2-174-129-24-148.compute-1.amazonaws.com:5432/dbpis23j1nf4ag'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class Question(UserMixin, db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    modCode = db.Column(db.String(15))
    question = db.Column(db.String(100))
    datetime = db.Column(db.Integer)
    authorId = db.Column(db.Integer)
    vote = db.Column(db.Integer)
    description = db.Column(db.String(1000))
    children = relationship("Answer")

class Answer(UserMixin, db.Model):
    __tablename__ = 'answers'
    id = db.Column(db.Integer, primary_key=True)
    questionId = db.Column(db.Integer, ForeignKey('question.id'))
    datetime = db.Column(db.Integer)
    authorId = db.Column(db.Integer)
    vote = db.Column(db.Integer)
    answer = db.Column(db.String(1000))
    parent_id = db.Column(db.Integer, ForeignKey('questions.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

class PostQuestionForm(FlaskForm):
    question_title = StringField('Title', validators=[InputRequired(), Length(min=4, max=50)])
    question = TextAreaField('Question', render_kw={"rows": 3}, validators=[InputRequired(), Length(max=50)])
    module_code = StringField('Module Code', validators=[InputRequired(), Length(min=4, max=15)])
    submit = SubmitField('Post Question')

class SearchForm(FlaskForm):
    submit = SubmitField('Search')

