from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from users.forms import RegisterForm
from users.forms import LoginForm
from users.models import User
from sqlalchemy.exc import IntegrityError

users_bp = Blueprint("users", __name__, template_folder="templates")


@users_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        print(form.errors)
        if form.password.data == form.confirm_password.data:
            user = User(
                username=form.username.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data, method='sha256')
            )
            db.session.add(user)
            try:
                db.session.commit()
                flash("successfully registered")
            except IntegrityError as err:
                db.session.roolback()
                if "UNIQUE constraint failed: user.username" in str(err):
                    flash("error, username already exists (%s)" % form.username.data)
                else:
                    flash("unknown error adding user")
        else:
            flash("Passwords don't match")
    return render_template("register.html", form=form, title="Register")


@users_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data,
        user = User.query.filter_by(username=username).first()
        if User or not check_password_hash(user.password, form.password.data):
            flash('Please check your login details')
            return redirect(url_for('users.login'))
        login_user(user)
        return redirect(url_for('users.profile'))
    return render_template("login.html", form=form, title="Login")


@users_bp.route('/profile')
@login_required
def profile():
    return render_template("profile.html", title="Profile")


@users_bp.route('/python')
@login_required
def python():
    return render_template("python.html", title="Python")


@users_bp.route('/github')
@login_required
def github():
    return render_template("github.html", title="Github")


@users_bp.route('/java')
@login_required
def java():
    return render_template("java.html", title="JavaScript")


@users_bp.route('/compiler')
@login_required
def compiler():
    return render_template("compiler.html", title="Compiler")


@users_bp.route('/admin')
@login_required
def admin():
    return render_template("admin.html", title="Admin")


@users_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('you have benn logged out')
    return render_template(url_for('users.login'))




