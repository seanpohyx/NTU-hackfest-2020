from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
import time
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
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    questions = db.relationship('Question', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.id}','{self.username}', '{self.email}', '{self.image_file}')"


class Question(UserMixin, db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    modCode = db.Column(db.String(15), nullable=False)
    question = db.Column(db.String(100), nullable=False)
    datetime = db.Column(db.DateTime, nullable=False)
    authorId = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    authorName = db.Column(db.String(15), nullable=False)
    vote = db.Column(db.Integer)
    description = db.Column(db.String(1000), nullable=False)
    answers = db.relationship('Answer', backref='answer_author', lazy=True)

    def __repr__(self):
        return f"Question('{self.question}, {self.id}, {self.authorId}, {self.authorName}')"

class Answer(UserMixin, db.Model):
    __tablename__ = 'answers'
    id = db.Column(db.Integer, primary_key=True)
    questionId = db.Column(db.Integer, ForeignKey('questions.id'))
    datetime = db.Column(db.DateTime, nullable=False)
    authorId = db.Column(db.Integer)
    authorName = db.Column(db.String(15), nullable=False)
    vote = db.Column(db.Integer)
    answer = db.Column(db.String(1000))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))