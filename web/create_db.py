import time
from app import db, app

time.sleep(10)

with app.app_context():
    db.drop_all()
    db.create_all()
