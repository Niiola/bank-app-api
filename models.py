"""Database models."""
from . import db, ma
# from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
# from sqlalchemy.orm import relationship, sessionmaker
# db = SQLAlchemy()


class User(UserMixin, db.Model):
    """User account model."""
    __tablename__ = "user"
    accountNumber = db.Column(db.String(10), unique=True)
    user = db.Column(db.Boolean)
    # admin = db.Column(db.Boolean)
    User_Id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Fname = db.Column(db.String(100), nullable=False, unique=False)
    Lname = db.Column(db.String(100), nullable=False, unique=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    # pin = db.Column(db.String(4))
    pin = db.Column(db.String(10), unique=False)
    AccountBalance = db.Column(db.Integer())
    password = db.Column(
        db.String(200), primary_key=False, unique=False, nullable=False
    )
    # age = db.Column(db.String(), nullable=True)
    # PIC_data = db.Column(db.LargeBinary, nullable=True)
    # PIC_rendered_data = db.Column(db.Text, nullable=True)  
    # # Data to render the pic in browser
    # text = db.Column(db.Text)
    # created_on = db.Column(db.DateTime, index=False, unique=False, nullable=True)
    # last_login = db.Column(db.DateTime, index=False, unique=False, nullable=True)

    # transfer = db.relationship('Transfer', backref='Transfers')
    # transfer = db.relationship('Transfer', backref='Transfers')

    transfer = db.relationship('Transfer', backref='Transfers')
    # image = db.relationship('image', uselist=False, backref='user')

    def set_password(self, password):
        """Create hashed password."""
        self.password = generate_password_hash(password, method="sha256")

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f"{self.accountNumber} {self.Fname}"


class USchema(ma.Schema):
    class Meta:
        fields = ('accountNumber', 'User_Id', 'Fname', 'Lname',
                  'email', 'pin', 'AccountBalance', 'password')


# class Admin(UserMixin, db.Model):
    # __tablename__ = "Admin"
    # id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    # username = db.Column(db.String(100), unique=True, nullable=False)
    # email = db.Column(db.String(40), unique=True, nullable=False)


class Transfer(db.Model):
    # __tablename__ = "transfer"
    TransferId = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    # BankName = db.Column(db.String(100), nullable=False)
    SendersAccount = db.Column(db.String(10), nullable=False)
    RecieversAccount = db.Column(db.String(10), nullable=False)
    # user = relationship('User', backref='Transfers')
    User_Id = db.Column(db.Integer, db.ForeignKey('user.User_Id'))

    def __repr__(self):
        return f"{self.SendersAccount}"


# class IMG(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     img = db.Column(db.Text, unique=True, nullable=False)
#     name = db.Column(db.Text, nullable=False)
#     elemtype = db.Column(db.Text, nullable=False)
#     User_id = db.Column(db.Integer, db.ForeignKey('user.User_Id'))


class Admin(UserMixin, db.Model):
    __tablename__ = "admin"
    admin = db.Column(db.Boolean)
    # user = db.Column(db.Boolean)
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Fname = db.Column(db.String(100), nullable=False, unique=False)
    Lname = db.Column(db.String(100), nullable=False, unique=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(
        db.String(200), primary_key=False, unique=False, nullable=False
    )
    # age = db.Column(db.String(), nullable=True)

    def set_password(self, password):
        """Create hashed password."""
        self.password = generate_password_hash(password, method="sha256")

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f"{self.Fname} {self.Fname}"
