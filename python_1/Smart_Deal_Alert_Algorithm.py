"""
Smart Deal Alert - Algorithm (Python Style Pseudocode)

This file documents the algorithm used by the Smart Deal Alert project.
It is for learning and planning only (not executable application logic).
"""

print("SMART DEAL ALERT - ALGORITHM")

# START

# Display Welcome Message

# Load user data from JSON file

# WHILE True:
#     Display Menu:
#     1. Login
#     2. Register
#     3. Exit
#
#     IF Login:
#         Ask username and password
#         IF credentials are valid:
#             Load user's tracked products
#             FOR each product:
#                 Ask latest price
#                 Update current price
#                 IF current price <= target price:
#                     Display "DEAL ALERT! BUY NOW!"
#                 ELSE:
#                     Display "WAIT - Still too expensive."
#
#             WHILE logged in:
#                 Display Dashboard Menu
#                 1. View/Update Product
#                 2. Add Product
#                 3. Delete Product
#                 4. Logout
#
#                 IF View/Update:
#                     Display products in table
#                     Select Product ID
#                     Show selected product
#                     Enter latest price
#                     Update price
#                     Compare target price
#                     Display alert
#
#                 ELIF Add Product:
#                     Ask product details
#                     Save product
#
#                 ELIF Delete Product:
#                     Delete selected product
#
#                 ELIF Logout:
#                     Return to Welcome Menu
#
#         ELSE:
#             Allow up to 3 login attempts
#
#     ELIF Register:
#         Create new account
#
#     ELIF Exit:
#         Break loop
#
# END
