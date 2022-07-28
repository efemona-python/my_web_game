from datetime import datetime
from flask_ckeditor import CKEditorField
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, URL, Email, Length, InputRequired, ValidationError
from wtforms.widgets import PasswordInput


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# CREATE REGISTER FORM
class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', widget=PasswordInput(hide_value=False),
                             validators=[DataRequired(), Length(min=8, max=32)])
    confirm = PasswordField(label='repeat password',
                            widget=PasswordInput(hide_value=False),
                            validators=[DataRequired(), Length(min=8, max=32)])
    terms = BooleanField(label="I accept the terms of use", validators=[DataRequired()])
    submit = SubmitField(label="Register")

    def validate_password(self, password):
        if password.data != self.confirm.data:
            raise ValidationError('Password mismatch')

    def validate_email(self, user):
        email = user.query.filter_by(email=self.email.data).first()
        if email:
            raise ValidationError('email address already registered')
        return True

    def register_user(self, db, user):
        dictionary = {'name': self.name.data,
                      'email': self.email.data,
                      'password': generate_password_hash(self.password.data,
                                                         method='pbkdf2:sha256',
                                                         salt_length=8)
                      }

        new_user = user(dictionary)
        db.session.add(new_user)
        db.session.commit()
        return new_user


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField(label='password',
                             widget=PasswordInput(hide_value=False),
                             validators=[DataRequired(), Length(min=8, max=32, message="password must be between 8 and 32 Character long")])
    remember = BooleanField('remember me')
    submit = SubmitField("Let Me In!")

    def check_user(self, user_db,):
        error = None
        user = user_db.query.filter_by(email=self.email.data).first()
        if not user:
            error = "your email is incorrect or doesn't exit."
        else:
            if not check_password_hash(user.password, self.password.data):
                error = "Invalid password"
        return user, error


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


class SubscribeForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    submit = SubmitField("Subscribe")

    def check_email_exist(self, subscribers):
        email = subscribers.query.filter_by(email=self.email.data).first()
        if email:
            raise ValidationError('email address already subscribed')
        return True

    def confirm_email_validity(self):
        # send email has generated url
        # use smtplib
        # TODO implement emailing for confirmation of subscription
        pass


class ResetPasswordForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    submit = SubmitField("Reset password")

    def check_email_exist(self, subscribers):
        email = subscribers.query.filter_by(email=self.email.data).first()
        if not email:
            raise ValidationError('email address does not exist')
        return True
