# from asyncio.windows_events import NULL
from flask import Blueprint, request, jsonify
# from .auth import AccountNumber
from .__init__ import db
# from flask_sqlalchemy import SQLAlchemy

from .auth import token_required, Usertoken_required
# from .__init__ import db
# from . import __init__
from .models import User, Transfer
from werkzeug.security import check_password_hash
from datetime import datetime as dt


# db = SQLAlchemy()

views = Blueprint(
    "view", __name__, template_folder="templates",
    static_folder="static"
)


@views.route("/transfer", methods=['GET', 'POST'])
@Usertoken_required
def transfer(UserCurrent_user):
    if request.method == 'POST':
        data = request.get_json()

        # Bankname = data["Banktype"]
        senderAccount = data["senderAccount"]
        recieverAccount = data["recieverAccount"]
        Pin = data["pin"]
        Amount = data["amount"]
        if len(senderAccount and recieverAccount and Pin and Amount) < 1:
            return jsonify({'description': "Information not provided"}), 400
        elif UserCurrent_user.accountNumber != senderAccount:
            return jsonify({'description': "cannot perform that function"}), 400
        # sender = User.query.filter_by(accountNumber=senderAccount).first()
        # reciever = User.query.filter_by(accountNumber=recieverAccount).first()
        sender = db.session.query(User).filter_by(
            accountNumber=senderAccount).first()
        reciever = db.session.query(User).filter_by(
            accountNumber=recieverAccount).first()
        # get_user = db.session.query(User).filter_by(email=email).first()
        if sender and reciever is not None:
            if len(senderAccount) and len(recieverAccount) < 10:
                return jsonify({"description": 'account number is not complete'}), 400
            elif Pin != sender.pin:
                return jsonify({"description":'Pin is incorrect'}), 400
            elif senderAccount == recieverAccount:
                return jsonify({
                    "status": "FAILED",
                    "description": "The senders and recievers account should not be the same!!"
                    }), 400
            elif sender.AccountBalance < int(Amount):
                return jsonify({"description": "insufficient balance"}), 400
            # elif len(Bankname) < 2:
            #     return jsonify("name is too short"), 400

            sender.AccountBalance -= int(Amount)
            reciever.AccountBalance += int(Amount)
            db.session.commit()

            # user = User.query.filter_by(accountNumber=senderAccount).first()
            transfer_ = Transfer(
                # BankName=Bankname, 
                SendersAccount=senderAccount,
                RecieversAccount=recieverAccount,
                User_Id=sender.User_Id)
            db.session.add(transfer_)
            db.session.commit()
            # print(transfer_.Transfers)

            sender.Transfers = (transfer_)
            # db.session.add(transfer_)
            # sender.Transfers = transfer_
            db.session.commit()
            # print(sender.AccountBalance)
            # print(reciever.AccountBalance)
            # return jsonify("Transfer successful"), 200
            return jsonify({"status": "success",
                        "description": "Transfer successful",
                        "data":{"Balance" : f"{sender.AccountBalance}"}}), 200

        return jsonify({"description":"account does not exist"}), 400


@views.route("/TransactionHistory", methods=["GET"])
@Usertoken_required
def Transactions(UserCurrent_user):
    if request.method == "GET":
        # data = request.get_json()
        # accountnumber = data["accountnumber"]
        accountnumber = UserCurrent_user.accountNumber
        # if not UserCurrent_user.user:
        # if UserCurrent_user.accountNumber != accountnumber:
        if not UserCurrent_user.accountNumber:
            return jsonify({'message': "cannot perform that function"})
        user = db.session.query(User).filter_by(
            accountNumber=accountnumber).first()
        history = []
        date = dt.now()
        # for item in range(0,3):
        # item = 0
        # while item < len(user.transfer):
        # print(user.transfer)
        # while item in range(0,len(user.transfer)):
        for i in range(0, len(user.transfer)):
            details = {"From": user.transfer[i].SendersAccount,
                        "TO": user.transfer[i].RecieversAccount,
                        "Date": date}
            # item = item+1
            history.append(details)
        # print(history)
        # print(details)
        # if user.transfer:
        if history:
            return jsonify(history), 200
        else:
            return jsonify("no transaction history"),400
    return jsonify({"status": "failed",
                             "description": "Account number is Invalid"}), 400


@views.route("/deposit", methods=['GET', 'POST'])
@token_required
def deposit(current_user):
    if request.method == 'POST':
        data = request.get_json()
        Accountnumber = data["accountNumber"]
        Amount = data["amount"]
        if not current_user.admin:
            return jsonify({'message': "cannot perform that function"})
        user = db.session.query(User).filter_by(
            accountNumber=Accountnumber).first()
        if user is None:
            return jsonify({"status": "failed",
                        "description": "invalid account number"}), 400
        user.AccountBalance += int(Amount)
        db.session.commit()
        return jsonify({"status": "success",
                        "description": "deposit successful",
                        "balance": user.AccountBalance}), 200


@views.route("/profile", methods=['GET', 'POST'])
@Usertoken_required
def profile(UserCurrent_user):
    if request.method == "POST":
        data = request.get_json()
        email = data["email"]
        oldPassword = data["oldPassword"]
        newPassword = data["newPassword"]
        confirmPassword = data["confirmPassword"]
        newPin = data["newPin"]
        oldPin = data["oldPin"]
        if UserCurrent_user.email != email:
            return jsonify({'message': "cannot perform that function"})
        user = db.session.query(User).filter_by(email=email).first()
        # update = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, oldPassword):
                if newPassword != confirmPassword:
                    return jsonify({"status": "failed",
                                    "description": "Password does not match"}), 400
                elif len(newPin) < 4:
                    return jsonify({"status": "failed",
                                    "description": "Pin is too short"}), 400
                elif user.pin != oldPin:
                    return jsonify({"status": "failed",
                                    "description": "old pin incorrect"})
                elif newPin == user.pin:
                    return jsonify({"status": "failed",
                                    "description": "pin is thesame input a new pin to update your pin"}), 400
                # print(update.pin)
        user.pin = newPin
        user.set_password(newPassword)
        db.session.commit()
        return jsonify({"status": "success",
                        "description": "profile updated",
                        "update": user.pin,
                        "pass update": user.password}), 200
        # return jsonify({"status": "failed",
        #                 "description": "Email does not exist"}), 400
