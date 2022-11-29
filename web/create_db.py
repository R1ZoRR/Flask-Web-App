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

    # open kit.img for user pictures
    with open(os.environ['KIT_IMG'], 'rb') as f:
        data = f.read()
        data = base64.b64encode(data)
        # creating some account (login, password, role_id)
        user_gen = [["root", "root_pass", 3], ["mod", "mod_pass", 2], ["just_user", "just_password", 1]]
        for i in range(0, len(user_gen)):
            db.session.add(User(login=user_gen[i][0], role=user_gen[i][2]))
            hash_pwd = generate_password_hash(user_gen[i][1])
            db.session.add(User_passwords(password=hash_pwd, user_id=i+1))
            db.session.add(Data(image=data, user_id=i+1, filename="kit.png"))
            try:
                db.session.commit()
            except exc.IntegrityError:
                db.session.rollback()
        f.close()




