"""
Smart Deal Alert — Live Pricing Edition (SerpApi + CSV storage)
-----------------------------------------------------------------
Tracks real products (by name or link) against a target price using
SerpApi's Google Shopping engine. The watchlist is saved to a CSV file
(watchlist.csv) so it persists between runs and can also be opened
directly in Excel or Google Sheets.

SETUP (do this once):
1. Create a free account at https://serpapi.com and copy your API key
   from the dashboard.
2. Install the official SerpApi client library:
       pip install google-search-results
3. Set your API key as an environment variable (never hardcode it in
   code you might share or commit to GitHub):

   Windows (PowerShell), one-time for future terminals:
       setx SERPAPI_API_KEY "your_key_here"
       (then close and reopen the terminal)

   macOS / Linux (add to ~/.zshrc or ~/.bashrc to make it permanent):
       export SERPAPI_API_KEY="your_key_here"

   If you skip this step, the program will just ask you to paste the
   key when it starts (fine for testing, not for sharing your code).

4. Run the program:
       python smart_deal_alert_csv.py
"""

import os
import csv
from datetime import datetime

# The SerpApi client library. If this import fails, run:
#   pip install google-search-results
from serpapi import GoogleSearch


# ---------------------------------------------------------
# 1. CONFIG
# ---------------------------------------------------------

WATCHLIST_FILE = "watchlist.csv"

# Column order for the CSV file — used for both reading and writing
FIELDNAMES = [
    "id", "query", "target_price", "product_title",
    "product_link", "source", "last_price", "last_checked"
]


def get_api_key():
    """
    Get the SerpApi key from an environment variable.
    Falls back to asking the user directly if it isn't set.
    """
    api_key = os.environ.get("SERPAPI_API_KEY")
    if not api_key:
        print("\n⚠️  No SERPAPI_API_KEY environment variable found.")
        api_key = input("Paste your SerpApi key here for this session: ").strip()
    return api_key


SERPAPI_API_KEY = get_api_key()


# ---------------------------------------------------------
# 2. WATCHLIST STORAGE (CSV file = our "database")
# ---------------------------------------------------------

def load_watchlist():
    """
    Load the watchlist from the CSV file.
    Returns an empty list if the file doesn't exist yet.

    CSV stores everything as plain text, so we convert "id" back to int
    and the price fields back to float as we read each row.
    """
    if not os.path.exists(WATCHLIST_FILE):
        return []

    watchlist = []
    with open(WATCHLIST_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            row["id"] = int(row["id"])
            row["target_price"] = float(row["target_price"])
            # last_price can be blank if a fetch ever failed, so handle that case
            row["last_price"] = float(row["last_price"]) if row["last_price"] else None
            watchlist.append(row)

    return watchlist


def save_watchlist(watchlist):
    """Save the watchlist back to the CSV file, overwriting the old contents."""
    with open(WATCHLIST_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writeheader()
        for item in watchlist:
            writer.writerow(item)


def next_id(watchlist):
    """Work out the next unique id for a new watchlist entry."""
    if not watchlist:
        return 1
    return max(item["id"] for item in watchlist) + 1


# ---------------------------------------------------------
# 3. SERPAPI INTEGRATION
# ---------------------------------------------------------

def clean_query(user_input):
    """
    If the user pasted a URL, turn it into readable search keywords.
    Otherwise, just use their text as-is (e.g. "iPhone 15 128GB").
    Google Shopping search works best with plain product names, so this
    is a best-effort cleanup, not a guarantee.
    """
    if user_input.startswith("http"):
        last_part = user_input.rstrip("/").split("/")[-1]
        cleaned = last_part.replace("-", " ").replace("_", " ")
        return cleaned
    return user_input


def fetch_shopping_price(query):
    """
    Search Google Shopping via SerpApi and return the top result as a dict:
    { "title": ..., "price": float, "link": ..., "source": ... }
    Returns None if nothing was found or the request failed.
    """
    params = {
        "engine": "google_shopping_light",
        "q": query,
        "api_key": SERPAPI_API_KEY,
        "hl": "en",
        "gl": "us"
    }

    try:
        search = GoogleSearch(params)
        results = search.get_dict()
    except Exception as error:
        print(f"⚠️  Error contacting SerpApi: {error}")
        return None

    shopping_results = results.get("shopping_results", [])
    if not shopping_results:
        print(f"⚠️  No shopping results found for '{query}'.")
        return None

    top_result = shopping_results[0]
    return {
        "title": top_result.get("title", query),
        "price": top_result.get("extracted_price"),
        "link": top_result.get("product_link") or top_result.get("link", ""),
        "source": top_result.get("source", "Unknown store")
    }


# ---------------------------------------------------------
# 4. CORE FEATURES
# ---------------------------------------------------------

def get_positive_float(prompt):
    """Keep asking until the user enters a valid positive number."""
    while True:
        try:
            value = float(input(prompt))
            if value <= 0:
                print("⚠️  Price must be greater than zero.")
                continue
            return value
        except ValueError:
            print("⚠️  Please enter a valid number (e.g., 499.99).")


def add_product(watchlist):
    """Ask the user for a product (name or link) and a target price, then save it."""
    raw_input_value = input("\nEnter a product name or product link: ").strip()
    if not raw_input_value:
        print("⚠️  Product name/link can't be empty.")
        return

    query = clean_query(raw_input_value)
    target_price = get_positive_float("Enter your target price: ")

    print(f"\n🔎 Looking up '{query}' on Google Shopping...")
    result = fetch_shopping_price(query)
    if result is None:
        print("❌ Could not find this product. It was not added to your watchlist.")
        return

    entry = {
        "id": next_id(watchlist),
        "query": query,
        "target_price": target_price,
        "product_title": result["title"],
        "product_link": result["link"],
        "source": result["source"],
        "last_price": result["price"],
        "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    watchlist.append(entry)
    save_watchlist(watchlist)

    print(f"✅ Added '{entry['product_title']}' (from {entry['source']}) to your watchlist.")
    print(f"   Current price: {entry['last_price']} | Target: {entry['target_price']}")


def view_watchlist(watchlist):
    """Print every tracked product and its latest known price."""
    if not watchlist:
        print("\n📭 Your watchlist is empty. Add a product first.")
        return

    print("\n===== YOUR WATCHLIST =====")
    for item in watchlist:
        print(f"\n[{item['id']}] {item['product_title']}")
        print(f"    Store        : {item['source']}")
        print(f"    Target price : {item['target_price']}")
        print(f"    Last price   : {item['last_price']}")
        print(f"    Last checked : {item['last_checked']}")


def remove_product(watchlist):
    """Remove a product from the watchlist by its id."""
    view_watchlist(watchlist)
    if not watchlist:
        return

    try:
        item_id = int(input("\nEnter the id of the product to remove: "))
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    updated_watchlist = [item for item in watchlist if item["id"] != item_id]
    if len(updated_watchlist) == len(watchlist):
        print("⚠️  No product with that id was found.")
        return

    watchlist[:] = updated_watchlist  # update the list in place
    save_watchlist(watchlist)
    print("🗑️  Product removed.")


def check_all_prices(watchlist):
    """
    Re-fetch the live price for every tracked product, update the
    watchlist file, and alert on any product that has hit its target.
    """
    if not watchlist:
        print("\n📭 Your watchlist is empty. Add a product first.")
        return

    print("\n🔄 Checking live prices for all tracked products...")
    deals_found = []

    for item in watchlist:
        print(f"\nChecking '{item['product_title']}'...")
        result = fetch_shopping_price(item["query"])

        if result is None or result["price"] is None:
            print("   ⚠️  Could not fetch a fresh price this time. Keeping the last known price.")
            continue

        # Update the record with the freshest data
        item["last_price"] = result["price"]
        item["product_title"] = result["title"]
        item["product_link"] = result["link"]
        item["source"] = result["source"]
        item["last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"   Current price: {item['last_price']} | Target: {item['target_price']}")

        if item["last_price"] <= item["target_price"]:
            deals_found.append(item)

    save_watchlist(watchlist)

    # ---- Notifications ----
    print("\n===== PRICE CHECK SUMMARY =====")
    if deals_found:
        for item in deals_found:
            print(f"🎉 DEAL ALERT! '{item['product_title']}' is now {item['last_price']} "
                  f"(target was {item['target_price']}). Buy now: {item['product_link']}")
    else:
        print("⏳ No products have hit their target price yet. Check again later.")


# ---------------------------------------------------------
# 5. MAIN PROGRAM (menu loop)
# ---------------------------------------------------------

def main():
    print("========================================")
    print("   📦 SMART DEAL ALERT — LIVE EDITION 📦")
    print("========================================")

    watchlist = load_watchlist()

    while True:
        print("\n===== MAIN MENU =====")
        print("1. Add a product to track")
        print("2. Check prices now")
        print("3. View watchlist")
        print("4. Remove a product")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ").strip()

        if choice == "1":
            add_product(watchlist)
        elif choice == "2":
            check_all_prices(watchlist)
        elif choice == "3":
            view_watchlist(watchlist)
        elif choice == "4":
            remove_product(watchlist)
        elif choice == "5":
            print("\n👋 Thanks for using Smart Deal Alert. Goodbye!")
            break
        else:
            print("⚠️  Invalid choice. Please enter a number from 1 to 5.")


if __name__ == "__main__":
    main()
