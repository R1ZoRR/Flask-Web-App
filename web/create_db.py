import base64
import time
from app import *
from models import *
import os

time.sleep(10)

#Creating data for database
with app.app_context():
    db.drop_all()
    db.create_all()

    #creating roles
    data = ("user", "moderator", "admin")
    for row in data:
        role = row
        db.session.add(User_roles(role=role))
    try:
        db.session.commit()
    except exc.IntegrityError:
        db.session.rollback()

    #creating admin account
    hash_pwd = generate_password_hash("root")
    db.session.add(User(login="root", role=3))
    db.session.add(User_passwords(password=hash_pwd))
    try:
        db.session.commit()
    except exc.IntegrityError:
        db.session.rollback()

    with open(os.environ['KIT_IMG'], 'rb') as f:
        data = f.read()
        data = base64.b64encode(data)
        f.close()
        db.session.add(Data(image=data))
    try:
        db.session.commit()
    except exc.IntegrityError:
        db.session.rollback()
