from flask import Flask, render_template_string, redirect, url_for, session, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
Talisman(app, content_security_policy=None)
limiter = Limiter(get_remote_address, app=app,
                  default_limits=["10 per minute"])


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[
        InputRequired(), Length(min=3, max=150),
        Regexp(r'^[A-Za-z0-9_]+$',
               message="Only letters, numbers, and underscores allowed")
    ])
    password = PasswordField("Password", validators=[
        InputRequired(), Length(min=8, message="Password must be at least 8 characters")
    ])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Login")


@app.route('/')
def home():
    if 'username' in session:
        return f"<h1>Welcome, {session['username']}!</h1><a href='/logout'>Logout</a>"
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            return "Username already taken", 400
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template_string("""
        <h2>Register</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.username.label }} {{ form.username }}<br>
            {{ form.password.label }} {{ form.password }}<br>
            {{ form.submit }}
        </form>
    """, form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session.clear()
            session['username'] = user.username
            return redirect(url_for('home'))
        return "Invalid credentials", 401
    return render_template_string("""
        <h2>Login</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.username.label }} {{ form.username }}<br>
            {{ form.password.label }} {{ form.password }}<br>
            {{ form.submit }}
        </form>
    """, form=form)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.before_first_request
def init_db():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=False)
