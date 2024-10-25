from database import initialize_db, add_password, retrieve_passwords, delete_password, update_password
from encryption import encrypt_password, decrypt_password, generate_key
import os

# Generate a key if not already generated
if not os.path.exists("secret.key"):
    generate_key()

# Initialize the database
initialize_db()

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
