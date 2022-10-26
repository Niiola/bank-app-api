from asyncio.windows_events import NULL
from os import access
from flask import Blueprint, redirect, flash, request, url_for, jsonify
from werkzeug.utils import secure_filename
# from .forms import LoginForm, SignupForm
# from .__init__ import db
import jwt
from flask_sqlalchemy import SQLAlchemy
from .models import Admin, User, USchema
# from .__init__ import jwt
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
from flask_jwt_extended import (create_access_token,
                                jwt_required, get_jwt_identity, JWTManager)
from functools import wraps


db = SQLAlchemy()
secretKey = "qwwwwwwwwwwwwwwwwwwwwwwwddddddddddddddddddddddd1"
auth = Blueprint(
    "auth", __name__, template_folder="templates", static_folder="static"
)

schema = USchema()
schemas = USchema(many=True)


def test_decode_auth_token(self):
    user = User(email="test@test.com",
                password='test'
                )
    db.session.add(user)
    db.session.commit()
    auth_token = user.encode_auth_token(user.id)
    self.assertTrue(isinstance(auth_token, bytes))
    self.assertTrue(User.decode_auth_token(auth_token) == 1)


@staticmethod
def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
      
        headers = request.headers
        bearer = headers.get('Authorization')
        token = bearer

        if not token:
            return jsonify({'message': 'token is missing'}), 401
       

        try:
            token = bearer.split()[1]
            data = jwt.decode(token, secretKey, algorithms='HS256')
        except:
            return jsonify({"message": "token is invalid"}), 401
        current_user = Admin.query.filter_by(email=data['email']).first()
            # UserCurrent_user = User.query.filter_by(email=data['email']).first()
            # UserCurrent_user = db.session.query(User).filter_by(
                                # email=data["email"]).first()
        return f(current_user, *args, **kwargs)

    return decorated
    

def Usertoken_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # data = request.get_json()
        token = None
        headers = request.headers
        bearer = headers.get('Authorization')
        token = bearer

        if not token:
            return jsonify({'description': 'token is missing'}), 401
        try:
            token = bearer.split()[1]
            data = jwt.decode(token, secretKey, algorithms='HS256')
            # current_user = Admin.query.filter_by(email=data['email']).first()
            # UserCurrent_user = User.query.filter_by(accountNumber=data['accountNumber']).first()
            UserCurrent_user = db.session.query(User).filter_by(
                                email=data["email"]).first()

        except:
            return jsonify({"description": "token is invalid"}), 401
        return f(UserCurrent_user, *args, **kwargs)

    return decorated


# @auth.route("/signupAdmin", methods=['PUT'])
# def admin():
#     if request.method == 'PUT':
#         data = request.get_json()
#         email = data["email"]
#         admin = User.query.filter_by(email=email).first()
#         if not admin:
#             return jsonify({"message": "no user found"})


@auth.route("/signup", methods=["GET", "POST"])
@token_required
def signup(current_user):
    if request.method == 'POST':
        data = request.get_json()
        email = data["email"]
        first_name = data["firstName"]
        last_name = data["lastName"]
        password1 = data["password1"]
        password2 = data["password2"]
        pin = data["pin"]
        if not current_user.admin:
            return jsonify({'description': "cannot perform that function"}), 400
        existing_user = User.query.filter_by(email=email).first()
        if existing_user is None:
            if len(first_name and last_name and email and password1 and password2 and pin) < 1:
                return jsonify({"status": "ERROR",
                            "description": "Information not provided"}), 400
            elif len(first_name) < 2:
                return jsonify({"status": "ERROR",
                            "description": "First name must be greater then 1 character"}), 400
                # return jsonify('First name must be greater than 1 character.'), 400
            elif password1 != password2:
                return jsonify({"status": "ERROR",
                            "description": "Password don\'t match"}), 400
                # return jsonify('Passwords don\'t match.'), 400
            elif len(password1) < 5:
                return jsonify({"status": "ERROR",
                            "description": "Password must be at least 7 characters"}), 400
                # return jsonify('Password must be at least 7 characters.'), 400
            elif len(pin) < 4:
                return jsonify({"status": "ERROR",
                            "description": "Pin is too short"}), 400
         
                # return jsonify('pin is too short'), 400
            # get_user = User.query.filter_by(email=email).first()
            # get_user.accountNumber = AccountNumber(get_user.user_id)
            user = User(
                Fname=first_name, email=email, Lname=last_name,
                AccountBalance=0, pin=pin)
            user.set_password(password1)
            # user.admin = False
            # user.set_password(pin)
            db.session.add(user)
            db.session.commit()
            # Create new user
            # get_user = User.query.filter_by(email=email).first()
            get_user = db.session.query(User).filter_by(email=email).first()
            print(len(AccountNumber(get_user.User_Id)))
            get_user.accountNumber = AccountNumber(get_user.User_Id)
            get_user.user = True
            # get_user.admin = False
            db.session.flush()
            db.session.commit()
            print(User.query.all())
            print(User.query.count())
            # print(get_user)
            # return jsonify("user created"), 200
            return jsonify({"status": "SUCCESS",
                            "description": "User Created"}), 200
        # return jsonify("A user already exists with that email address."), 400
        return jsonify({"status": "ERROR",
                            "description": "A user already exists with that email address."}), 400


@auth.route("/adminsignup", methods=["POST"])
def admin_signup():
    if request.method == 'POST':
        data = request.get_json()
        email = data["email"]
        first_name = data["firstName"]
        last_name = data["lastName"]
        password1 = data["password1"]
        password2 = data["password2"]
        existing_user = Admin.query.filter_by(email=email).first()
        if existing_user is None:
            if len(first_name) < 2:
                return jsonify('First name must be greater than 1 character.'), 400
            elif password1 != password2:
                return jsonify('Passwords don\'t match.'), 400
            elif len(password1) < 5:
                return jsonify('Password must be at least 7 characters.'), 400
            user = Admin(
                Fname=first_name, email=email, Lname=last_name)
            user.set_password(password1)
            db.session.add(user)
            db.session.commit()
            get_user = db.session.query(Admin).filter_by(email=email).first()
            get_user.admin = True
            # get_user.user = False
            db.session.commit()
            return jsonify("user created"), 200
        return jsonify("A user already exists with that email address."), 400


# @auth.route("/allUsers", methods=["GET"])
# def getUsers():
#     if request.method == "GET":
#         allUsers = User.query.all()
#         result = {}
#         for user in allUsers:
#             print(user)
#             result[user.email] = user.Transfers

#         return result


@auth.route("/AllAdminUsers", methods=["GET"])
@token_required
def AlldminUser(current_user):
    if request.method == "GET":
        if not current_user.admin:
            return jsonify({'message': "cannot perform that function"})
        allUsers = Admin.query.all()
        result = []
        for user in allUsers:
            output = {}
            output['admin'] = user.admin
            output['email'] = user.email
            output['firstname'] = user.Fname

            result.append(output)
            # print(user)
            # result[user.email] = user.Transfers

        return result


@auth.route("/allusers", methods=["GET"])
@token_required
def alluser(current_user):
    if request.method == "GET":
        if not current_user.admin:
            return jsonify({'message': "cannot perform that function"})
        allUsers = User.query.all()
        result = schemas.dump(allUsers)
        # result = []
        # for user in allUsers:
        #     output = {}
        #     output['user'] = user.user
        #     # output['admin'] = user.admin
        #     output['email'] = user.email
        #     output['accountnumber'] = user.accountNumber

        #     result.append(output)
            # print(user)
            # result[user.email] = user.Transfers

        return result


def AccountNumber(user_id):
    number = str(user_id)
    if len(number) < 10:
        for i in range(0, 10-len(number)):
            number = "0"+number
        return number


@auth.route("/Userlogin", methods=["POST"])
def Userlogin():
    """
    Log-in page for registered users.

    GET requests serve Log-in page.
    POST requests validate and redirect user to dashboard.
    """
    if request.method == "POST":
        data = request.get_json()
        account_number = data["accountNumber"]
        password = data["password"]
        # email = data['email']

        user = db.session.query(User).filter_by(
                accountNumber=account_number).first()
        if user:
            if check_password_hash(user.password, password):
                return token(user)
            else:
                return jsonify({"description": "password incorrect"}), 400
        return jsonify({"status": "ERROR",
                            "description": "this account number doesn't exist",
                            "data": "0"}), 400


@auth.route("/Adminlogin", methods=["POST"])
def Adminlogin():
    if request.method == "POST":
        data = request.get_json()
        password = data["password"]
        email = data['email']

        user = db.session.query(Admin).filter_by(
                email=email).first()
        if user:
            if check_password_hash(user.password, password):
                return token(user)
            else:
                return jsonify("password incorrect")
        return jsonify({"status": "ERROR",
                            "description": "this email doesn't exist",
                            "data": "0"}), 400


# @auth.route("/token", methods=["POST"])
# def token2():
#     email = request.json.get("email", None)
#     password = request.json.get("password", None)
#     if email != 'test' or password != 'test':
#         return jsonify({'message': 'bad username or password'}), 401

#     access_token = create_access_token(email)
#     return jsonify(access_token)
 

def token(user):
    token = jwt.encode({
        'email': user.email,
        'name': f"{user.Fname} {user.Lname}",
        'exp': datetime.utcnow() + timedelta(minutes=30)},
        secretKey, algorithm='HS256')   

    return jsonify({"status": "SUCCESS",
                    "description": "login successful",
                    "data": token}), 200

# def token(user):
#     token = jwt.encode({
#         'email': user.email,
#         'name': f"{user.Fname} {user.Lname}",
#         'exp': datetime.utcnow() + timedelta(minutes=30)},
#         secretKey, algorithm='HS256')

#     return jsonify({"data": token}), 200

# def refreshtoken(user):
#     access_token = token()
#     return jsonify({"access_token": access_token})


# @auth.route("/upload", methods=['POST'])
# def upload():
#     pic = request.files["pic"]
#     if not pic:
#         return jsonify("no picture uploaded"), 400
#     filename = secure_filename(pic.filename)
#     elemtype = pic.elemtype
#     img = IMG(img=pic.read(), name=filename, elemtype=elemtype)
#     db.session.add(img)
#     db.session.commit()

#     return "img uploaded", 200


# @auth.route("/<int:id>")
# def get_img(id):
#     img = IMG.query.filter_by(id=id).first()
#     if not img:
#         return "img not found", 404
#     return Response(img.img, elemtype=img.elemmtype)


# @login_manager.user_loader
# def load_user(user_id):
#     """Check if user is logged-in on every page load."""
#     if user_id is not None:
#         return User.query.get(user_id)
#     return None


# @login_manager.unauthorized_handler
# def unauthorized():
#     """Redirect unauthorized users to Login page."""
#     flash("You must be logged in to view that page.")
#     return redirect(url_for("Auth_bp.login"))
