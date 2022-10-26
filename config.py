#flask app configuration
import imp
from msilib import type_string
from os import environ,path


class Config:
    #set flask configuration from environment variables
    FLASK_APP = "wsgi.py"
    FLASK_DEBUG = "development"
    SECRET_KEY = "QWERTYU"
    TESTING = True
    DEBUG = True

    #static assets
    STATIC_FOLDER = "static"
    TEMPLATES_FOLDER = "templates"

    #flask-SQLAlchemy
    SQLALCHEMY_DATABASE_URI =(
        "sqlite:///mydb.db"
    )
    SQLALCHEMY_ECHO=False
    SQLALCHEMY_TRACK_MODIFICATION = "False"


