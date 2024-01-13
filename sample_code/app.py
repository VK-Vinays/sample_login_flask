from flask import Flask, render_template, url_for, redirect, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

import pandas as pd

app = Flask(__name__)
#db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.get_user.get('id')


class User():
    def get_user():
        data = {'id': [1, 2],
            'name': ['vinay', 'nani'],
            'password': ['abc@1234', 'xyz@1234']}
        return data

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.get_user().get('name')
        if username in existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class SummaryForm(FlaskForm):
    submit = StringField('Submit')

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/submit_form', methods=['POST'])
def submit_form():
    form = LoginForm()
    username = request.form.get('username')
    password = request.form.get('password')
    if username in User.get_user().get('name'):
        return render_template('dashboard.html')
    else:
        return render_template('login.html', form = form, error='Invalid credentials')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_name = form.username.data
        user = User.get_user()
        if user_name in user.get('name'):
            return redirect(url_for('submit_form'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/calculate_total', methods=['POST'])
def calculate_total():
    form = SummaryForm()
    data = request.get_json()
    total = sum(item['productPrice'] for item in data)
    return render_template('summary.html',total_value = total, form=form)

if __name__ == "__main__":
    app.run(debug=True)
