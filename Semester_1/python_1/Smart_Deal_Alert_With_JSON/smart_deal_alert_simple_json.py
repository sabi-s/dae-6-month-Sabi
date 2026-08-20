"""
Smart Deal Alert — Simple Beginner Edition (with JSON file + delete option)
------------------------------------------------------------------------------
No external API. Prices are entered by hand (simulating a real price check).
But now the tracked products list is saved to a JSON file, so it survives
closing and reopening the program. You can also delete a product you no
longer want to track.

Run this in VS Code: open the file, then click Run (or type
    python smart_deal_alert_simple_json.py
in the terminal).
"""

import json
import os

# ---------------------------------------------------------
# 1. DATA
# ---------------------------------------------------------

# Hardcoded users for login: username -> password
USERS = {
    "john": "1234",
    "asha": "5678"
}

# The JSON file where tracked products are saved between runs
DATA_FILE = "tracked_products.json"

# This will hold our list of tracked products once the program starts.
# We fill it in load_tracked_products() below.
tracked_products = []


# ---------------------------------------------------------
# 2. LOADING AND SAVING (JSON file = our simple "database")
# ---------------------------------------------------------

def load_tracked_products():
    """
    Load tracked_products from the JSON file.
    If the file doesn't exist yet (first time running the program),
    start with two sample products instead, so there's something to see.
    """
    global tracked_products

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            tracked_products = json.load(file)
    else:
        tracked_products = [
            {"id": 1, "name": "Laptop", "target_price": 700, "last_price": 750},
            {"id": 2, "name": "Headphones", "target_price": 50, "last_price": 60}
        ]
        save_tracked_products()  # create the file right away with these samples


def save_tracked_products():
    """Save tracked_products to the JSON file, overwriting the old contents."""
    with open(DATA_FILE, "w") as file:
        json.dump(tracked_products, file, indent=2)


# ---------------------------------------------------------
# 3. LOGIN
# ---------------------------------------------------------

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

        if username in USERS and USERS[username] == password:
            print(f"\n✅ Login successful. Welcome, {username}!")
            return username

        attempts -= 1
        print(f"❌ Wrong username or password. Attempts left: {attempts}")

    print("\n🚫 Too many failed attempts. Exiting program.")
    return None


# ---------------------------------------------------------
# 4. HELPER FUNCTIONS
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
    """Work out the next id number for a new product."""
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
# 5. MAIN FEATURES
# ---------------------------------------------------------

def startup_price_check():
    """
    Go through every already-tracked product and ask the user to type
    in its current price (this stands in for "fetching" a real price).
    Then check if it's a deal, and save the updated prices to the file.
    """
    if not tracked_products:
        print("\n📭 You aren't tracking any products yet.")
        return

    print("\n🔄 Let's check the latest price for each product you're tracking.")
    for product in tracked_products:
        print(f"\nProduct: {product['name']} (target price: {product['target_price']})")
        new_price = get_positive_number("Enter the current price you found: ")
        product["last_price"] = new_price
        notify_if_deal(product)

    save_tracked_products()


def show_tracked_products():
    """Print every tracked product in a simple numbered format."""
    if not tracked_products:
        print("\n📭 You aren't tracking any products yet.")
        return

    print("\n===== TRACKED PRODUCTS =====")
    for product in tracked_products:
        print(f"[{product['id']}] {product['name']} — "
              f"target: {product['target_price']}, last price: {product['last_price']}")


def add_product():
    """Ask the user for a new product name, target price, and current price."""
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
    save_tracked_products()

    print(f"\n✅ '{name}' added to your tracked products.")
    notify_if_deal(new_product)


def view_or_update_product():
    """Let the user pick a tracked product and enter a fresh price for it."""
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
    save_tracked_products()
    notify_if_deal(product)


def delete_product():
    """Let the user pick a tracked product by id and remove it from the list."""
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
    save_tracked_products()

    print(f"🗑️  '{product['name']}' has been removed from your tracked products.")


# ---------------------------------------------------------
# 6. MAIN PROGRAM (menu loop)
# ---------------------------------------------------------

def main():
    print("========================================")
    print("      📦 SMART DEAL ALERT — SIMPLE 📦")
    print("========================================")

    user = login()
    if user is None:
        return  # stop the program if login failed

    load_tracked_products()
    startup_price_check()

    while True:
        show_tracked_products()

        print("\n===== MAIN MENU =====")
        print("1. View/update an existing tracked product")
        print("2. Add a new product to track")
        print("3. Delete a tracked product")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            view_or_update_product()
        elif choice == "2":
            add_product()
        elif choice == "3":
            delete_product()
        elif choice == "4":
            print("\n👋 Thanks for using Smart Deal Alert. Goodbye!")
            break
        else:
            print("⚠️  Invalid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
