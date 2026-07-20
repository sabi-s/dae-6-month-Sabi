"""
Smart Deal Alert — Simple Beginner Edition
--------------------------------------------
No API, no CSV, no JSON. Everything lives in memory (a Python list)
while the program is running. When you close the program, the list is
gone — that's the trade-off for keeping things simple while learning.

Run this in VS Code: open the file, then click Run (or type
    python smart_deal_alert_simple.py
in the terminal).
"""

# ---------------------------------------------------------
# 1. DATA
# ---------------------------------------------------------

# Hardcoded users for login: username -> password
USERS = {
    "john": "1234",
    "asha": "5678"
}

# This list represents products the user is "already tracking".
# In a real app this would come from a file or database — here we just
# start with two sample products already in the list, hardcoded.
tracked_products = [
    {"id": 1, "name": "Laptop", "target_price": 700, "last_price": 750},
    {"id": 2, "name": "Headphones", "target_price": 50, "last_price": 60}
]


# ---------------------------------------------------------
# 2. LOGIN
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
# 3. HELPER FUNCTIONS
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
# 4. MAIN FEATURES
# ---------------------------------------------------------

def startup_price_check():
    """
    Go through every already-tracked product and ask the user to type
    in its current price (this stands in for "fetching" a real price).
    Then check if it's a deal.
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
    notify_if_deal(product)


# ---------------------------------------------------------
# 5. MAIN PROGRAM (menu loop)
# ---------------------------------------------------------

def main():
    print("========================================")
    print("      📦 SMART DEAL ALERT — SIMPLE 📦")
    print("========================================")

    user = login()
    if user is None:
        return  # stop the program if login failed

    startup_price_check()

    while True:
        show_tracked_products()

        print("\n===== MAIN MENU =====")
        print("1. View/update an existing tracked product")
        print("2. Add a new product to track")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ").strip()

        if choice == "1":
            view_or_update_product()
        elif choice == "2":
            add_product()
        elif choice == "3":
            print("\n👋 Thanks for using Smart Deal Alert. Goodbye!")
            break
        else:
            print("⚠️  Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
