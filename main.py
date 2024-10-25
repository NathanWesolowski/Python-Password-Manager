from database import initialize_db, add_password, retrieve_passwords, delete_password, update_password, set_master_password, verify_master_password, master_password_exists
from encryption import encrypt_password, decrypt_password, generate_key
import os

# Generate a key if not already generated
if not os.path.exists("secret.key"):
    generate_key()

# Initialize the database
initialize_db()

def setup_master_password():
    print("Set up a master password for your password manager.")
    while True:
        master_password = input("Enter a master password: ")
        confirm_password = input("Confirm master password: ")
        if master_password == confirm_password:
            set_master_password(master_password)
            print("Master password set successfully!")
            break
        else:
            print("Passwords do not match. Try again.")

def authenticate_user():
    attempts = 3
    while attempts > 0:
        master_password = input("Enter your master password: ")
        if verify_master_password(master_password):
            print("Authentication successful!")
            return True
        else:
            attempts -= 1
            print(f"Incorrect password. {attempts} attempt(s) left.")
    print("Failed to authenticate. Exiting application.")
    return False

def add_new_password():
    website = input("Enter the website: ")
    username = input("Enter the username: ")
    password = input("Enter the password: ")
    encrypted_password = encrypt_password(password)
    add_password(website, username, encrypted_password)
    print("Password added successfully.")

def view_passwords():
    passwords = retrieve_passwords()
    for id, website, username, encrypted_password in passwords:
        decrypted_password = decrypt_password(encrypted_password)
        print(f"ID: {id}, Website: {website}, Username: {username}, Password: {decrypted_password}")

def delete_password_entry():
    entry_id = int(input("Enter the ID of the password entry you want to delete: "))
    delete_password(entry_id)
    print("Password entry deleted successfully.")

def edit_password_entry():
    entry_id = int(input("Enter the ID of the password entry you want to edit: "))
    new_password = input("Enter the new password: ")
    encrypted_password = encrypt_password(new_password)
    update_password(entry_id, encrypted_password)
    print("Password updated successfully.")

def main():
    # Set up or authenticate master password
    if not master_password_exists():  # Check if any master password is set
        setup_master_password()
    elif not authenticate_user():
        return  # Exit if authentication fails

    # Main application loop after authentication
    while True:
        choice = input(
            "Choose an option:\n"
            "1. Add new password\n"
            "2. View saved passwords\n"
            "3. Delete a password\n"
            "4. Edit a password\n"
            "5. Exit\n"
        )
        if choice == '1':
            add_new_password()
        elif choice == '2':
            view_passwords()
        elif choice == '3':
            delete_password_entry()
        elif choice == '4':
            edit_password_entry()
        elif choice == '5':
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
