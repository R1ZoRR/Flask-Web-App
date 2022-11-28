from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from config import BaseConfig
import base64


app = Flask(__name__)
app.config.from_object(BaseConfig)
app.secret_key = BaseConfig.return_key(BaseConfig)
db = SQLAlchemy(app)
manager = LoginManager(app)

from models import *

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/redirect_login', methods=['POST'])
def redirect_login():
    return redirect(url_for('login_page'))

@app.route('/redirect_register', methods=['POST'])
def redirect_register():
    return redirect(url_for('register'))

@app.route('/main', methods=['GET'])
@login_required
def main():
    text = "SELECT user_roles.id AS user_roles_id, user_roles.role AS user_roles_role  " \
           "FROM user_roles WHERE user_roles.id = " + str(current_user.role)
    sql_query = db.session.execute(text).all()
    user_role = sql_query
    if user_role[0][1] == "admin" or user_role[0][1] == "moderator":
        messages = Message.query.all()
    elif user_role[0][1] == "user":
        messages = Message.query.filter_by(from_id=current_user.id)
    else:
        return redirect(url_for('logout'))
    img = db.session.query(Data).first()
    img = img.image.decode("UTF-8")
    return render_template('main.html', messages=messages, image=img)

@app.route('/add_message', methods=['POST'])
@login_required
def add_message():
    from_id = current_user.id
    text = request.form['text']
    tag = request.form['tag']

    db.session.add(Message(from_id, text, tag))
    db.session.commit()

    return redirect(url_for('main'))


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if not current_user.is_authenticated:
        login = request.form.get('login')
        password = request.form.get('password')

        if login and password:
            user = User.query.filter_by(login=login).first()
            hash_pwd = User_passwords.query.filter_by(id=user.id).first()
            if user and check_password_hash(hash_pwd.password, password):
                login_user(user)
                return redirect(url_for('main'))
            else:
                flash('Login or password is not correct')
        else:
            flash('Please fill login and password fields')

        return render_template('login.html')
    return redirect(url_for('main'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Please, fill all fields!')
        elif password != password2:
            flash('Passwords are not equal!')
        else:
            hash_pwd = generate_password_hash(password)
            db.session.add(User(login=login, role=1))
            try:
                db.session.commit()
            except exc.IntegrityError:
                db.session.rollback()
            u_id = User.query.filter_by(login=login).first().id
            db.session.add(User_passwords(password=hash_pwd, user_id=u_id))
            try:
                db.session.commit()
                return redirect(url_for('login_page'))
            except exc.IntegrityError:
                db.session.rollback()
                flash('Login is already taken')


    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page'))

    return response


if __name__ == '__main__':
    app.run(debug=True)
