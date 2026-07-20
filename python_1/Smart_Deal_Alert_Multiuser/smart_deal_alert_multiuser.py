"""
Smart Deal Alert — Multi-User Edition (JSON file, no hardcoded passwords)
----------------------------------------------------------------------------
Usernames, passwords, AND each user's own tracked products are all saved
in one JSON file: users_data.json

Structure of that file looks like this:
{
  "john": {
    "password": "1234",
    "products": [ {"id": 1, "name": "Laptop", "target_price": 700, "last_price": 750} ]
  },
  "asha": {
    "password": "5678",
    "products": [ ... ]
  }
}

Because each user's products live inside their own entry, when "john" logs
in he only ever sees his own products — never asha's.

Run this in VS Code: open the file, then click Run (or type
    python smart_deal_alert_multiuser.py
in the terminal).
"""

import json
import os

DATA_FILE = "users_data.json"

# ---------------------------------------------------------
# These two globals hold everything while the program runs.
# all_users  -> the WHOLE file's contents (every user)
# tracked_products -> just the CURRENTLY LOGGED-IN user's product list
# ---------------------------------------------------------
all_users = {}
tracked_products = []


# ---------------------------------------------------------
# 1. LOADING AND SAVING (JSON file = our simple "database")
# ---------------------------------------------------------

def load_all_users():
    """
    Load every user's data from the JSON file into the all_users dictionary.
    If the file doesn't exist yet (first run), create it with two sample
    accounts so there's something to log in with.
    """
    global all_users

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            all_users = json.load(file)
    else:
        all_users = {
            "john": {
                "password": "1234",
                "products": [
                    {"id": 1, "name": "Laptop", "target_price": 700, "last_price": 750}
                ]
            },
            "asha": {
                "password": "5678",
                "products": [
                    {"id": 1, "name": "Headphones", "target_price": 50, "last_price": 60}
                ]
            }
        }
        save_all_users()  # create the file right away with these samples


def save_all_users():
    """Save the entire all_users dictionary back to the JSON file."""
    with open(DATA_FILE, "w") as file:
        json.dump(all_users, file, indent=2)


# ---------------------------------------------------------
# 2. LOGIN / REGISTER
# ---------------------------------------------------------

def register_user():
    """Let someone create a brand new username and password."""
    print("\n===== REGISTER A NEW ACCOUNT =====")
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()

    if not username or not password:
        print("⚠️  Username and password can't be empty.")
        return
    if username in all_users:
        print("⚠️  That username is already taken. Try logging in instead.")
        return

    all_users[username] = {"password": password, "products": []}
    save_all_users()
    print(f"✅ Account created for '{username}'. You can now log in.")


def login():
    """
    Ask for username and password, up to 3 tries.
    Returns the username if correct, or None if all 3 tries fail.
    """
    attempts = 3
    while attempts > 0:
        print("\n===== LOGIN =====")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

        if username in all_users and all_users[username]["password"] == password:
            print(f"\n✅ Login successful. Welcome, {username}!")
            return username

        attempts -= 1
        print(f"❌ Wrong username or password. Attempts left: {attempts}")

    print("\n🚫 Too many failed attempts.")
    return None


# ---------------------------------------------------------
# 3. HELPER FUNCTIONS (work on the CURRENT user's tracked_products)
# ---------------------------------------------------------

def get_positive_number(prompt):
    """Keep asking until the user types a positive number."""
    while True:
        try:
            value = float(input(prompt))
            if value <= 0:
                print("⚠️  Please enter a number greater than zero.")
                continue
            return value
        except ValueError:
            print("⚠️  That's not a valid number. Try again.")


def next_id():
    """Work out the next id number for a new product for this user."""
    if not tracked_products:
        return 1
    return max(product["id"] for product in tracked_products) + 1


def find_product_by_id(product_id):
    """Look through tracked_products and return the one with this id, or None."""
    for product in tracked_products:
        if product["id"] == product_id:
            return product
    return None


def notify_if_deal(product):
    """
    Compare last_price to target_price.
    Print a buy alert if the price is good, otherwise say it's too expensive.
    """
    if product["last_price"] <= product["target_price"]:
        print(f"🎉 DEAL ALERT! '{product['name']}' is now {product['last_price']} "
              f"— that's at or below your target of {product['target_price']}. Buy now!")
        return True
    else:
        difference = product["last_price"] - product["target_price"]
        print(f"⏳ '{product['name']}' is still too expensive. "
              f"It's {difference} above your target price of {product['target_price']}.")
        return False


# ---------------------------------------------------------
# 4. MAIN FEATURES
# ---------------------------------------------------------

def startup_price_check():
    """Ask for a fresh price for every product THIS user is tracking."""
    if not tracked_products:
        print("\n📭 You aren't tracking any products yet.")
        return

    print("\n🔄 Let's check the latest price for each product you're tracking.")
    for product in tracked_products:
        print(f"\nProduct: {product['name']} (target price: {product['target_price']})")
        new_price = get_positive_number("Enter the current price you found: ")
        product["last_price"] = new_price
        notify_if_deal(product)

    save_all_users()


def show_tracked_products():
    """Print every product THIS user is tracking."""
    if not tracked_products:
        print("\n📭 You aren't tracking any products yet.")
        return

    print("\n===== YOUR TRACKED PRODUCTS =====")
    for product in tracked_products:
        print(f"[{product['id']}] {product['name']} — "
              f"target: {product['target_price']}, last price: {product['last_price']}")


def add_product():
    """Ask for a new product name, target price, and current price."""
    name = input("\nEnter the product name: ").strip()
    if not name:
        print("⚠️  Product name can't be empty.")
        return

    target_price = get_positive_number("Enter your target price: ")
    current_price = get_positive_number("Enter the current price you found: ")

    new_product = {
        "id": next_id(),
        "name": name,
        "target_price": target_price,
        "last_price": current_price
    }
    tracked_products.append(new_product)
    save_all_users()

    print(f"\n✅ '{name}' added to your tracked products.")
    notify_if_deal(new_product)


def view_or_update_product():
    """Let the user pick one of THEIR products and enter a fresh price for it."""
    show_tracked_products()
    if not tracked_products:
        return

    try:
        product_id = int(input("\nEnter the id of the product to check: "))
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    product = find_product_by_id(product_id)
    if product is None:
        print("⚠️  No product with that id was found.")
        return

    new_price = get_positive_number(f"Enter the current price of '{product['name']}': ")
    product["last_price"] = new_price
    save_all_users()
    notify_if_deal(product)


def delete_product():
    """Let the user pick one of THEIR products by id and remove it."""
    show_tracked_products()
    if not tracked_products:
        return

    try:
        product_id = int(input("\nEnter the id of the product to delete: "))
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    product = find_product_by_id(product_id)
    if product is None:
        print("⚠️  No product with that id was found.")
        return

    # Keep every product EXCEPT the one whose id matches product_id
    tracked_products[:] = [p for p in tracked_products if p["id"] != product_id]
    save_all_users()

    print(f"🗑️  '{product['name']}' has been removed from your tracked products.")


# ---------------------------------------------------------
# 5. USER DASHBOARD (everything a logged-in user can do)
# ---------------------------------------------------------

def run_dashboard(username):
    """
    Point tracked_products at THIS user's product list, run the startup
    check, then show the menu loop until they choose to log out.
    """
    global tracked_products
    tracked_products = all_users[username]["products"]

    startup_price_check()

    while True:
        show_tracked_products()

        print(f"\n===== MAIN MENU ({username}) =====")
        print("1. View/update an existing tracked product")
        print("2. Add a new product to track")
        print("3. Delete a tracked product")
        print("4. Log out")

        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            view_or_update_product()
        elif choice == "2":
            add_product()
        elif choice == "3":
            delete_product()
        elif choice == "4":
            print(f"\n👋 Logging out. Bye, {username}!")
            break
        else:
            print("⚠️  Invalid choice. Please enter 1, 2, 3, or 4.")


# ---------------------------------------------------------
# 6. MAIN PROGRAM (welcome screen: login / register / exit)
# ---------------------------------------------------------

def main():
    print("========================================")
    print("      📦 SMART DEAL ALERT — MULTI-USER 📦")
    print("========================================")

    load_all_users()

    while True:
        print("\n===== WELCOME =====")
        print("1. Log in")
        print("2. Register a new account")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ").strip()

        if choice == "1":
            username = login()
            if username is not None:
                run_dashboard(username)
        elif choice == "2":
            register_user()
        elif choice == "3":
            print("\n👋 Goodbye!")
            break
        else:
            print("⚠️  Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
