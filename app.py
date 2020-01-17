from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import User, LoginForm, RegisterForm, UpdateForm, SearchForm, PostQuestionForm, Question, Answer, app, db
from modules import modulesDict
from datetime import datetime

@app.route('/', methods=['GET', 'POST'])
def index():
    form = SearchForm()

    if form.validate_on_submit():
        module = request.form.get('modulesSelect').upper()

        if ((module in modulesDict) is False):
            flash("please enter the right module", "error")
        elif module is "":
            flash("please choose your module", "error")
        else:
            return redirect(url_for('ask', module=module))

    return render_template('index.html', title="Index", form=form, modules=modulesDict)

@app.route('/ask/<string:module>', methods=['GET', 'POST'])
def ask(module):

    if ((module.upper() in modulesDict) is False):
            return redirect(url_for('index'))
            #incorrect module

    form = SearchForm()

    if form.validate_on_submit():
        question = request.form.get('question')
        print(question)

    return render_template('ask.html', title="Index", form=form, module=module.upper())

@app.route("/livesearch", methods=['GET', 'POST'])
def livesearch():
    hint = list()
    search = "%{}%".format(request.form.get("text"))
    module = request.form.get("module")
    result = Question.query.filter_by(modCode=module).filter(Question.question.like(search)).all()

    for i in result:
        hint.append(i.question)
    
    return jsonify(hint)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form, title="login")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('dashboard'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form, title="signup")

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/postQuestion', methods=['GET', 'POST'])
@login_required
def postQuestion():
    form = PostQuestionForm()
    if form.validate_on_submit():
        new_question = Question(modCode=form.module_code.data, question=form.question_title.data, datetime=datetime.now(), 
                                authorId=current_user.get_id(), vote=0, description=form.question.data)
        db.session.add(new_question)
        db.session.commit()

        flash('Your question has been created!', 'success')
        return redirect(url_for('your_questions'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('postQuestion.html', form=form, title="New Question")

@app.route('/your_questions')
@login_required
def your_questions():
    page = request.args.get('page', 1, type=int)
    questions = Question.query.filter_by(authorId=current_user.get_id()).order_by(Question.datetime.desc()).paginate(page=page, per_page=5)
    return render_template('your_questions.html', name=current_user.username, questions = questions)


@app.route('/question/<int:question_id>')
def question(question_id):
    question = Question.query.get_or_404(question_id)
    return render_template('question.html', title=question.question, question = question)

@app.route('/question/<int:question_id>/update', methods=['GET', 'POST'])
@login_required
def update_question(question_id):
    question = Question.query.get_or_404(question_id)
    return render_template('question.html', title=question.question, question = question)

@app.route('/user/<string:username>')
@login_required
def user_questions(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    questions = Question.query.filter_by(author=user)\
                .order_by(Question.datetime.desc())\
                .paginate(page=page, per_page=5)
    return render_template('user_questions.html', user=user, questions = questions)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateForm()

    if form.validate_on_submit():
        if form.password.data == form.retypePassword.data:
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            user = User.query.filter_by(id=current_user.id).first()
            user.password = hashed_password
            user.username = form.username.data
            print(user.username)
            print(form.username.data)
            user.email = form.email.data
            db.session.commit()
            flash('successful update')
            return redirect(url_for('dashboard'))
        else:
            error('incorrect password')

    form.username.data = current_user.username
    form.email.data = current_user.email

    return render_template('profile.html', name=current_user.username, form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
