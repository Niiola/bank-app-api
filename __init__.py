from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
# from os import path
# from .models import User
# from .auth import Auth_bp
# from views import view_bp
from . import config
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from flask_jwt_extended import (JWTManager)


app = Flask(__name__, instance_relative_config=False)
db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)
ma = Marshmallow(app)
migrate = Migrate()
login_manager = LoginManager()
# app = Flask(__name__, instance_relative_config=False)
# jwt = JWTManager(app)
DB_NAME = "mydb.db"


def create_app():
    app.config.from_object(config.Config)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    app.config['SWLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = 'qawsgyenhfuioxn'
    # db = SQLAlchemy(app)
    migrate.init_app(app, db)
    db.init_app(app)
    login_manager.init_app(app)

    # from . import auth
    # from . import views

    with app.app_context():
        from .views import views
        from .auth import auth
        app.register_blueprint(auth)
        app.register_blueprint(views)

        # app.register_blueprint(views, url_prefix='/')
        # app.register_blueprint(auth, url_prefix='/')
        # from .models import User
        db.create_all(app=app)
        # from .models import User
        # create_database(app)
        # db.session.commit()
        print("created database")

        return app
