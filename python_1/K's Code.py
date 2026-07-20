print( "Welcome to Home Destiny Guru" )

# Hardcoding these values to represent the user's credentials
correct_username = "kay"
correct_password = "kaypinky"
computer_weather = 76
# assume user wants to try for the first time
user_wants_to_try_again = 1

# Ask the user for their username
user_name = input("Please enter your username: ")
password = input( "Thank you. Also please type in your password: " )

while user_name != correct_username or password != correct_password:
    # Ask the user again for their username
    print( "At least one credential is incorrect. Please renter: " )
    user_name = input("Please enter your username: ")
    password = input( "Thank you. Also please type in your password: " )

print( "Welcome", user_name )

# Try again
while user_wants_to_try_again:
    at_home = int( input("Where are you? Press 1 for Home. 0 for Work: ") )
    raining = int( input( "Is it raining? Press 1 for Yes and 0 for no.: ") )

    if raining and at_home:
        print("Stay home")
    elif raining and not at_home:
        print("Stay at work")
    elif at_home:
        print("Go to work")
    elif not at_home:
        print("Go Home")

    print("Thank you for using this application")

    user_response = input("Do you want to try again. Please type y/n")

    while user_response != "y" and user_response != "n":
        user_response = input("Hey, please enter a y or n. Nothing else!")
   

print("Bye!!!!")





