from sqlalchemy.exc import IntegrityError

from flask import Flask, flash
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = 'users.login'


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'mine'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    register_extensions(app)
    register_blueprints(app)
    setup_database(app)

    return app


def register_extensions(app):
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    from users.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


def register_blueprints(app):
    from users.users import users_bp
    app.register_blueprint(users_bp)

    from users.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


def setup_database(app):
    with app.app_context():
        from users.models import User
        from users.models import RolesUsers
        from users.models import Role
        db.create_all()
        db.session.commit()

        # TODO setup admin
        role = Role()
        role.name = "Admin"
        role.description = "This is Admin"
        db.session.add(role)
        try:
            db.session.commit()
        except IntegrityError as err:
            db.session.roolback()
            if "UNIQUE constraint" in str(err):
                flash('error, admin already exists')
            else:
                flash("unknown error")
        # TODO find admin user
        user = User.query.filter_by(email="techademy@admin.com").first()
        if user is not None:
            if not user.has_role("Admin"):
                role = Role.query.filter_by(name="Admin").first()
                user.roles.append(role)
                try:
                    db.session.commit()
                except IntegrityError as err:
                    db.session.roolback()
                    if "UNIQUE constraint" in str(err):
                        flash('Admin relationship')
                    else:
                        flash('error with relationship')
                flash('Added role admin')
            else:
                flash('Admin is already admin')


if __name__ == "__main__":
    app = create_app()
    app.run()