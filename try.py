def AccountNumber(user_id):
    number = str(user_id)
    if len(number) < 10:
        for i in range(0, 10-len(number)):
            number = "0"+number
    return number


AccountNumber(5)

# x=2
# y=3
# if x and y > 1:
#     print("yes")