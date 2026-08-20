print("WELCOME TO SMART DEAL ALRET PRICE TRACKER")
# Hardcoding these values to represent the user's credentials
# correct_username = "Sabi"
# correct_password = "Sabi123"
# user_wants_to_try_again = 1

# user_name = input("Please enter the  Username : ")
# pass_word = input("Thank you " + user_name + " Please enter the Password : ")

# print(user_name,pass_word )

# first_time_setup()

def _first_time_setup():
# Create a new username/password the first time the program runs.
    print("               No account found. Let's create one.               ")
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()
    print("Account created successfully!\n")

#  if username is None: 
#         _first_time_setup()

def authenticate():

    if username is None:
            _first_time_setup()
            username, password_hash = _load_credentials()
    
    for attempt in range(1, MAX_ATTEMPTS + 1):
            entered_user = input("Username: ").strip()
            entered_pass = input("Password: ").strip()
    
            if entered_user == username and _hash_password(entered_pass) == password_hash:
                print(f"\nWelcome back, {username}!\n")
                return True
    
            remaining = MAX_ATTEMPTS - attempt
            if remaining > 0:
                print(f"Incorrect username or password. {remaining} attempt(s) left.\n")
            else:
                print("\nToo many failed attempts. Exiting.")
    return False





def main():
    print_welcome()
 
    if not auth.authenticate():
        sys.exit(1)
 
    products = storage.load_products()
    products = refresh_all_products(products)
 
    while True:
        display_products(products)
        choice = show_menu()
 
        if choice == "1":
            view_or_update_product(products)
            products = storage.load_products()
        elif choice == "2":
            add_new_product()
            products = storage.load_products()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Please choose 1, 2, or 3.\n")
 
 
if __name__ == "__main__":
    main()
 