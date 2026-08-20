"""
Smart Deal Alert — Final Version
------------------------------------
Built directly from this pseudocode:

    START
    Display Welcome Message
    Load user data from JSON file
    WHILE True
        Display Menu (Login / Register / Exit)
        ...
    END WHILE
    END

Each function below has a comment showing which pseudocode line(s) it
implements, so you can trace the algorithm straight into the code.

Data is stored in users_data.json:
{
  "john": {"password": "1234", "products": [ {...}, {...} ]},
  "asha": {"password": "5678", "products": [ ... ]}
}

Run in VS Code: open this file, click Run, or type
    python smart_deal_alert_final.py
in the terminal.
"""

import json
import os

DATA_FILE = "users_data.json"

all_users = {}          # holds EVERY user's data, loaded from the JSON file
tracked_products = []   # holds ONLY the currently logged-in user's products


# ---------------------------------------------------------
# LOAD / SAVE — pseudocode: "Load user data from JSON file"
# ---------------------------------------------------------

def load_all_users():
    global all_users
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            all_users = json.load(file)
    else:
        # First run — create two sample accounts so there's something to log in with
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
        save_all_users()


def save_all_users():
    with open(DATA_FILE, "w") as file:
        json.dump(all_users, file, indent=2)


# ---------------------------------------------------------
# Small reusable helpers
# ---------------------------------------------------------

def get_positive_number(prompt):
    """Keep asking until the user types a valid number greater than zero."""
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
    if not tracked_products:
        return 1
    return max(product["id"] for product in tracked_products) + 1


def find_product_by_id(product_id):
    for product in tracked_products:
        if product["id"] == product_id:
            return product
    return None


def check_deal(product):
    """Pseudocode: 'IF current price <= target price -> Deal Alert ELSE Still Too Expensive'."""
    if product["last_price"] <= product["target_price"]:
        print(f"🎉 Deal Alert! Buy Now — '{product['name']}' is {product['last_price']} "
              f"(target was {product['target_price']}).")
        return True
    else:
        difference = product["last_price"] - product["target_price"]
        print(f"⏳ Still Too Expensive — '{product['name']}' is {difference} above your target.")
        return False


# ---------------------------------------------------------
# LOGIN / REGISTER — pseudocode: "IF choice == Login ... ELIF Register"
# ---------------------------------------------------------

def login():
    """
    Pseudocode: 'Ask for username / Ask for password / IF correct... ELSE Invalid Login'.
    Extended with a 3-attempt limit: if all 3 tries fail, give up and return
    to the main Menu instead of asking forever.
    """
    attempts = 3
    while attempts > 0:
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

        if username in all_users and all_users[username]["password"] == password:
            print(f"\n✅ Login successful. Welcome, {username}!")
            return username

        attempts -= 1
        print(f"❌ Invalid Login. Attempts left: {attempts}")

    print("\n🚫 Too many failed attempts. Returning to the main menu.")
    return None


def register():
    """Pseudocode: 'Ask username / Ask password / Save new account'."""
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()

    if not username or not password:
        print("⚠️  Username and password can't be empty.")
        return
    if username in all_users:
        # Not in the original pseudocode, but stops you from accidentally
        # overwriting an existing account with the same name.
        print("⚠️  That username is already taken.")
        return

    all_users[username] = {"password": password, "products": []}
    save_all_users()
    print(f"✅ Account created for '{username}'. You can now log in.")


# ---------------------------------------------------------
# STARTUP PRICE CHECK — pseudocode: "IF products exist -> FOR each product..."
# ---------------------------------------------------------

def check_all_products_on_login():
    if not tracked_products:
        print("\n📭 You aren't tracking any products yet.")
        return

    print("\n🔄 Checking the latest price for each of your tracked products...")
    for product in tracked_products:
        print(f"\nProduct: {product['name']} (target: {product['target_price']})")
        product["last_price"] = get_positive_number("Enter the latest price: ")
        check_deal(product)

    save_all_users()


# ---------------------------------------------------------
# DASHBOARD FEATURES — pseudocode: View/Update, Add, Delete
# ---------------------------------------------------------

def show_products_table():
    """Pseudocode: 'Display products in table'."""
    if not tracked_products:
        print("\n📭 You aren't tracking any products yet.")
    else:

        print("\n===== YOUR TRACKED PRODUCTS =====")
        print(f"{'ID':<4}{'Name':<20}{'Target':<12}{'Last Price':<12}")
        for product in tracked_products:
            print(f"{product['id']:<4}{product['name']:<20}"
                f"{product['target_price']:<12}{product['last_price']:<12}")


def view_or_update_product():
    """
    Pseudocode: 'Display products in table / Ask Product ID / Show selected
    product / Ask latest price / Update price / Compare / Display result'.
    """
    show_products_table()
    if not tracked_products:
        return

    try:
        product_id = int(input("\nEnter the Product ID: "))
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    product = find_product_by_id(product_id)
    if product is None:
        print("⚠️  No product with that ID was found.")
        return

    # "Show selected product"
    print(f"\nSelected product: {product['name']}")
    print(f"  Target price : {product['target_price']}")
    print(f"  Last price   : {product['last_price']}")

    product["last_price"] = get_positive_number("Enter the latest price: ")
    save_all_users()
    check_deal(product)


def add_product():
    """Pseudocode: 'Ask product name / Ask target price / Ask current price / Save product / Check Deal Alert'."""
    name = input("\nEnter the product name: ").strip()
    if not name:
        print("⚠️  Product name can't be empty.")
        return

    target_price = get_positive_number("Enter your target price: ")
    current_price = get_positive_number("Enter the current price: ")

    new_product = {
        "id": next_id(),
        "name": name,
        "target_price": target_price,
        "last_price": current_price
    }
    tracked_products.append(new_product)
    save_all_users()

    print(f"\n✅ '{name}' added to your tracked products.")
    check_deal(new_product)


def delete_product():
    """Pseudocode: 'Display products / Ask Product ID / Delete product'."""
    show_products_table()
    if not tracked_products:
        return

    try:
        product_id = int(input("\nEnter the Product ID to delete: "))
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    product = find_product_by_id(product_id)
    if product is None:
        print("⚠️  No product with that ID was found.")
        return

    tracked_products[:] = [p for p in tracked_products if p["id"] != product_id]
    save_all_users()
    print(f"🗑️  '{product['name']}' has been deleted.")


# ---------------------------------------------------------
# DASHBOARD MENU — pseudocode: "WHILE True: Display Dashboard Menu..."
# ---------------------------------------------------------

def run_dashboard(username):
    global tracked_products
    tracked_products = all_users[username]["products"]  # "Load logged-in user's products"

    check_all_products_on_login()

    while True:
        # show_products_table()

        print(f"\n===== DASHBOARD MENU ({username}) =====")
        print("1. View / Update Product")
        print("2. Add Product")
        print("3. Delete Product")
        print("4. Logout")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            view_or_update_product()
        elif choice == "2":
            add_product()
        elif choice == "3":
            delete_product()
        elif choice == "4":
            print(f"\n👋 Logging out. Bye, {username}!")
            break  # "Return to Welcome Menu"
        else:
            print("⚠️  Invalid Choice.")


# ---------------------------------------------------------
# MAIN PROGRAM — pseudocode: "START ... WHILE True: Display Menu..."
# ---------------------------------------------------------

def main():
    print("========================================")
    print("        📦 SMART DEAL ALERT 📦")
    print("========================================")

    load_all_users()

    while True:
        print("\n===== MENU =====")
        print("1. Login")
        print("2. Register")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            username = login()
            if username is not None:
                run_dashboard(username)
        elif choice == "2":
            register()
        elif choice == "3":
            print("\n👋 Goodbye!")
            break
        else:
            print("⚠️  Invalid Choice.")


if __name__ == "__main__":
    main()
