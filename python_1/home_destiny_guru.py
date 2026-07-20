print("Welcome to Home Destiny Guru")

# Hardcoding these values to represent the user's credentials
correct_username = "Sabi"
correct_password = "Sabi123"
user_wants_to_try_again = 1

user_name = input("Please enter the  Username : ")
pass_word = input("Thank you" + user_name + "Please enter the Password : ")



while user_name != correct_username or pass_word != correct_password:
     print("Incorrect username or Password ")

     user_name = input("Please enter the New Username : ")
     pass_word = input("Thank you" + user_name + "Please enter the New Password : ")
print("Successfully login Welcome",user_name)


while user_wants_to_try_again:
    at_home = int(input("Where are you? Press 1 for Home, 0 for Work: "))
    raining = int(input("Is it Raining ? Press 1 for yes and 0 for no :"))

    if raining and at_home:
            print("Stay Home")
    elif raining and not at_home:
            print("Stay at Work")
    elif at_home:
        print("Go to Work")
    elif not at_home:
            print("Go Home")
    print("Thank you")
    user_response = input("Do you want to try again. Please type y/n: ")
    
    while user_response != "y" and user_response != "n":

        user_response = input("Hey, please enter a y or n. Nothing else!")

    
    if user_response == "y":
        user_wants_to_try_again = 1
    else:
          user_wants_to_try_again = 0
    

print("Bye!!!!")


#Ask the user for their username
# user_name = input("Please enter the New Username : ")
# pass_word = input("Thank you" + user_name + "Please enter the New Password : ")

# if user_name == correct_username  and pass_word == correct_password :
#     print("username and Password match")
# else:
#     print("Don't match")



    # user_response = input("Do you want to use this again?: Press y/n :")
    

    # While user_response != "y" and user_response != "n"
    # if user_response == "y":
    #                 user_wants_to_try_again = 1
    # else:
    #                 user_wants_to_try_again = 0





# user_location_as_string = input("Where are you ? Press 1 for Home, Press 2 for Work :")
# user_location_as_int = int(user_location_as_string )
# print(user_location_as_int)

# raining = input("is it raining? Press 1 for yes, 0 for No")


# location = input("Where are you ? Home or Work :")
# raining = input("is it raining?  yes or No :")


# if raining and location == "Home"
#    print 











