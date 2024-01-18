from flask import Flask, render_template, url_for, redirect, request, jsonify
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from database import Database

import pandas as pd

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'thisisasecretkey'



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db_obj = Database()


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = get_user(username).get('user_name')
        if username == existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
            

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class ProductForm(FlaskForm):
    productname = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "productname "})
    productvalue = FloatField(validators=[
                             InputRequired(), Length(min=1, max=5)], render_kw={"placeholder": "productvalue "})
    submit = SubmitField('Total')


class SummaryForm(FlaskForm):
    logout = SubmitField('Logout')

@app.route('/summary', methods=['GET', 'POST'])
def summary():
    form = SummaryForm()
    total = 0
    if form.validate_on_submit():
        product_values = request.form.getlist('productvalue')
        for value in product_values:
            total += float(value)
    return render_template('summary.html', total_value = total, form=form)



@login_manager.user_loader
def load_user(user_name):
    return get_user(user_name).get('user_name')


def get_user(user_name):
    query = '''
            select * from login_users where user_name = ?;
            '''
    try:
        result = db_obj.get_result(query=query, params=[user_name])
        return {'user_name':result[0][1], 'password': result[0][-1]}
    except:
        return {}

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/submit_form', methods=['POST'])
def submit_form():
    form = LoginForm()
    form2 = ProductForm()
    username = request.form.get('username')
    password = request.form.get('password')
    user_details = get_user(username)
    if username  == user_details.get('user_name') and \
        password == user_details.get('password'):
        return render_template('prod_dashboard.html', form = form2)
    else:
        return render_template('register.html', form = form, error='Invalid credentials')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_name = form.username.data
        password = form.password.data
        user_details = get_user(user_name)
        if user_name  == user_details.get('user_name') and \
            password == user_details.get('password'):
            return redirect(url_for('submit_form'))
        else:
            return redirect(url_for('register'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('prod_dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_name = form.username.data
        password = form.password.data
        user_details = get_user(user_name)
        if user_name  == user_details.get('user_name'):
            return redirect(url_for('login'))
        else:
            insert_query = """
                            insert into login_users (user_name, passcode) values
                            ('{}','{}')
                           """.format(user_name, password)
            try:
                result = db_obj.get_result(query=insert_query)
                if result == 'Success':
                    return redirect(url_for('login'))
            except:
                raise ValidationError(
                'Issue while updating Database')
        return render_template('login.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)
