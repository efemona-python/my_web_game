import os
import re
from sqlalchemy.exc import IntegrityError
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import LoginForm, RegisterForm, CreatePostForm, CommentForm,ResetPasswordForm
from flask_gravatar import Gravatar

app = Flask(__name__)
# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config["SECRET_KEY"] = "MYSECRETEKEY"
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

##CONNECT TO DB
uri = os.getenv("DATABASE_URL", 'sqlite:///data.db')  # or other relevant config var
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
# rest of connection code using the connection string `uri`
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))


class Subscriber(db.Model):
    __tablename__ = "subscribers"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)


# db.drop_all()
db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if request.method == "POST":
        new_subscriber = Subscriber(email=request.form.get('email'))
        db.session.add(new_subscriber)
        try:
            db.session.commit()
            flash(message="thank you for subscribing.", category="subscription")
        except IntegrityError as e:
            db.session.rollback()
            flash(message="this email already subscribed", category="subscription")
        return redirect(request.referrer)

    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_user = register_form.register_user(db, User)
        login_user(new_user)
        return redirect(url_for("home"))

    return render_template("register.html", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user, error = login_form.check_user(User)
        if error:
            flash(message=error, category="login")
        else:
            login_user(user)
            flash(message='You were successfully logged in', category="login")
            return redirect(request.referrer)
    return render_template("login.html", form=login_form)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    reset_password_form = ResetPasswordForm()
    if reset_password_form.validate_on_submit():
        user, error = reset_password_form.check_email_exist(User)
        if error:
            flash(message=error, category="reset_password")
        else:
            # send email with confirmation url
            flash(message='Instructions have been sent to your email', category="reset_password")
            return redirect(request.referrer)
    return render_template("reset_password.html", form=reset_password_form)



if __name__ == "__main__":
    app.run(debug=True)
