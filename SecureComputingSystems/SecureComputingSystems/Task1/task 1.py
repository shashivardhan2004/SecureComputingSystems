# ----------------------------------------
# Secure Authentication System (Final Version)
# ----------------------------------------

import hashlib
import os
import re
import time
import json


USER_DB = "users.json"


# ----------------------------------------
# Username Validation
# ----------------------------------------
def is_valid_username(username):
    """
    Username must:
    - Be 3 to 20 characters long
    - Contain only letters, numbers, and underscores
    """
    pattern = r'^[A-Za-z0-9_]{3,20}$'
    return re.match(pattern, username)


# ----------------------------------------
# Password Complexity Validation
# ----------------------------------------
def is_strong_password(password):
    """
    Password must:
    - Be at least 12 characters long
    - Contain at least one number
    - Contain at least one special character
    """
    pattern = r'^(?=.*\d)(?=.*[^\w\s]).{12,}$'
    return re.match(pattern, password)


# ----------------------------------------
# Hash Password with SHA-256 + Salt
# ----------------------------------------
def hash_password(password, salt=None):
    """
    Hash password using SHA-256 with a unique 16-byte salt
    """
    if salt is None:
        salt = os.urandom(16)

    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.sha256(salt + password_bytes).hexdigest()

    return salt, hashed_password


# ----------------------------------------
# Load Users
# ----------------------------------------
def load_users():
    try:
        with open(USER_DB, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


# ----------------------------------------
# Save Users
# ----------------------------------------
def save_users(users):
    with open(USER_DB, "w") as file:
        json.dump(users, file, indent=4)


# ----------------------------------------
# Register User
# ----------------------------------------
def register():
    print("\nUser Registration")

    users = load_users()

    # Username input with validation loop
    while True:
        username = input("Enter username: ").strip()

        if not is_valid_username(username):
            print("Invalid username. Use 3–20 characters (letters, numbers, underscores only).")
            continue

        if username in users:
            print("Username already exists.")
            continue

        break

    # Show password requirements BEFORE input
    print("\nPassword Requirements:")
    print("- At least 12 characters")
    print("- Must include at least one number")
    print("- Must include at least one special character")

    # Password input with validation loop
    while True:
        password = input("Enter password: ")

        if is_strong_password(password):
            break
        else:
            print("Weak password. Please try again.")

    # Hash password with unique salt
    salt, hashed_password = hash_password(password)

    # Store user securely
    users[username] = {
        "salt": salt.hex(),
        "password": hashed_password
    }

    save_users(users)

    print("Registration successful.")


# ----------------------------------------
# Login User
# ----------------------------------------
def login():
    print("\nUser Login")

    username = input("Enter username: ").strip()
    password = input("Enter password: ")

    users = load_users()

    # Check if user exists
    if username not in users:
        print("User not found.")
        time.sleep(2)  # Delay ONLY on failure
        return

    stored_salt = bytes.fromhex(users[username]["salt"])
    stored_password = users[username]["password"]

    # Hash input password using stored salt
    _, hashed_input = hash_password(password, stored_salt)

    # Validate login
    if hashed_input == stored_password:
        print("Login successful.")
    else:
        print("Incorrect password.")
        time.sleep(2)  # Delay ONLY on failure


# ----------------------------------------
# Main Menu
# ----------------------------------------
def main():
    while True:
        print("\nAuthentication System")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Exiting system.")
            break
        else:
            print("Invalid option. Please try again.")


# ----------------------------------------
# Run Program
# ----------------------------------------
if __name__ == "__main__":
    main()