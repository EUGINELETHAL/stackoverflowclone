import os

from flask_bcrypt import Bcrypt
from flask import current_app
from datetime import datetime, timedelta
import jwt
from app import db


class User(db.Model):
    """This is a model that defines every user"""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(256), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    questions = db.relationship('Question', backref='poster', lazy='dynamic')
    answers = db.relationship('Answer', backref='commenter', lazy='dynamic')

    def __init__(self, email, password, admin=False):
        """Initialize a user """
        self.email = email
        self.password = Bcrypt().generate_password_hash(password).decode('utf-8')
        self.admin = admin

    def is_password_valid(self, password):
        """Compare password with the harsh to check validity"""
        return Bcrypt().check_password_hash(self.password, password)

    def generate_token(self, user_id):
        """Generate an access token required to log in user"""
        try:
            # create a payload to be used in generating token

            payload = {
                'exp': datetime.utcnow() + timedelta(minutes=60),
                'iat': datetime.utcnow(),
                'sub': user_id
            }

            # generate a jwt encoded string
            jwt_string = jwt.encode(
                payload,
                os.environ['SECRET'],
                algorithm='HS256'
            )
            return jwt_string
        except Exception as e:
            # import pdb; pdb.set_trace()
            return str(e)

    @staticmethod
    def decode_token(token):
        """A method to decode access token from header"""
        try:
            # decode the token using the SECRET
            payload = jwt.decode(token, os.environ['SECRET'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            # if the token is expired, return an error string
            return "Expired token. Please login to get a new token"
        except jwt.InvalidTokenError:
            # the token is invalid, return an error string
            return "Invalid token. Please register or login"

    def save(self):
        """Save a user to the database"""
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return '<User {}>'.format(self.email)


class Question(db.Model):
    """This is a model that holds all orders"""

    __tablename__ = 'questions'

    # define the columns of the table, starting with its primary key
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    date_modified = db.Column(
        db.DateTime, default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp())
    answers = db.relationship('Answer', backref='answer-on-question', lazy='dynamic')    


    def __init__(self, name, created_by):
        """Initialize the bucketlist with a name and its creator."""
        self.name = name
        self.created_by = created_by

    def save(self):
        """Save a question  to the database"""
        db.session.add(self)
        db.session.commit()


class Answer(db.Model):
    """This is a model that holds all answers"""

    __tablename__ = 'answers'

    # define the columns of the table, starting with its primary key
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    date_modified = db.Column(
        db.DateTime, default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp())
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'))


    def __init__(self, name, created_by):
        """Initialize the answer  with a body  and its author."""
        self.name = name
        self.created_by = created_by

    def save(self):
        """Save an answer  to the database"""
        db.session.add(self)
        db.session.commit()



