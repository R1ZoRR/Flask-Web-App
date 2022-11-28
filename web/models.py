import datetime
from app import db, manager
from flask_login import UserMixin


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, nullable=False)
    text = db.Column(db.String(1024), nullable=False)
    created_at = db.Column(db.Date)

    def __init__(self, from_id, text, tags):
        self.from_id = from_id
        self.text = text.strip()
        self.tags = [Tag(text=tag.strip()) for tag in tags.split(',')]
        self.created_at = datetime.datetime.now()


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(32), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    message = db.relationship('Message', backref=db.backref('tags', lazy=True))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    role = db.Column(db.Integer, nullable=False, unique=False)

class User_passwords(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(1024), nullable=False)

class User_roles(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(128), nullable=False, unique=True)

class Data(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.LargeBinary, nullable=False)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)