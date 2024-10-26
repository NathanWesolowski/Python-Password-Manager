import tkinter as tk
from tkinter import ttk
import zipfile
from zxcvbn import zxcvbn
from tkinter import messagebox, filedialog, simpledialog
from datetime import datetime, timedelta
import random
import string
import base64
from cryptography.fernet import Fernet
from database import initialize_db, add_password, retrieve_passwords, delete_password, update_entry, set_master_password, verify_master_password, master_password_exists, get_expiring_passwords, export_passwords, import_passwords, import_data
from encryption import encrypt_password, decrypt_password, generate_key, load_key
import os
import json

if not os.path.exists("secret.key"):
    generate_key()

initialize_db()

INACTIVITY_TIMEOUT = 5 * 60 * 1000

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("700x400")
        self.inactivity_timer = None

        if not master_password_exists():
            self.setup_master_password()
        else:
            self.authenticate_user()

    def reset_inactivity_timer(self):
        if self.inactivity_timer:
            self.root.after_cancel(self.inactivity_timer)
        self.inactivity_timer = self.root.after(INACTIVITY_TIMEOUT, self.auto_logout)

    def auto_logout(self):
        messagebox.showinfo("Session Timeout", "You have been logged out due to inactivity.")
        self.authenticate_user()

    def setup_master_password(self):
        self.clear_window()
        tk.Label(self.root, text="Set a Master Password", font=("Arial", 14)).pack(pady=10)
        password_entry = tk.Entry(self.root, show="*", width=30)
        password_entry.pack(pady=5)
        confirm_entry = tk.Entry(self.root, show="*", width=30)
        confirm_entry.pack(pady=5)

        def save_password():
            master_password = password_entry.get()
            confirm_password = confirm_entry.get()
            if master_password == confirm_password:
                set_master_password(master_password)
                messagebox.showinfo("Success", "Master password set successfully!")
                self.show_main_menu()
            else:
                messagebox.showerror("Error", "Passwords do not match. Try again.")
            self.reset_inactivity_timer()

        tk.Button(self.root, text="Set Password", command=save_password).pack(pady=10)

    def import_passwords(file_path):
        """Imports passwords from an encrypted file into the database."""
        with open(file_path, "r") as file:
            data = json.load(file)

        for entry in data:
            # Decode and decrypt the password before storing it in the database
            decrypted_password_bytes = base64.b64decode(entry["password"])
            decrypted_password = decrypt_password(decrypted_password_bytes)  # Decrypt bytes to get the original password
            add_password(entry["website"], entry["username"], decrypted_password)

    def authenticate_user(self):
        self.clear_window()
        tk.Label(self.root, text="Enter Master Password", font=("Arial", 14)).pack(pady=10)
        password_entry = tk.Entry(self.root, show="*", width=30)
        password_entry.pack(pady=5)

        def check_password():
            if verify_master_password(password_entry.get()):
                messagebox.showinfo("Success", "Authentication successful!")
                self.check_expiring_passwords()
                self.show_main_menu()
            else:
                messagebox.showerror("Error", "Incorrect password. Try again.")
                password_entry.delete(0, tk.END)
            self.reset_inactivity_timer()

        tk.Button(self.root, text="Login", command=check_password).pack(pady=10)
    
    def add_new_password(self):
        self.clear_window()
        tk.Label(self.root, text="Add New Password", font=("Arial", 14)).pack(pady=10)

        tk.Label(self.root, text="Website").pack()
        website_entry = tk.Entry(self.root, width=30)
        website_entry.pack()

        tk.Label(self.root, text="Username").pack()
        username_entry = tk.Entry(self.root, width=30)
        username_entry.pack()

        tk.Label(self.root, text="Password").pack()
        password_entry = tk.Entry(self.root, width=30, show="*")
        password_entry.pack()

        # Password Strength Label
        strength_label = tk.Label(self.root, text="Password Strength: ", font=("Arial", 10))
        strength_label.pack(pady=5)

        # Password Generator Button
        def suggest_password():
            suggested_password = self.generate_strong_password()
            password_entry.delete(0, tk.END)
            password_entry.insert(0, suggested_password)
            update_strength_label(suggested_password)

        # Password Strength Update
        def update_strength_label(password):
            if not password:
                strength_label.config(text="Password Strength: N/A")
                return
    
            result = zxcvbn(password)
            score = result['score']
            strength_text = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
            strength_label.config(text=f"Password Strength: {strength_text[score]}")

        password_entry.bind("<KeyRelease>", lambda event: update_strength_label(password_entry.get()))

        # Show/Hide Password Checkbox
        def toggle_password_visibility():
            if show_password_var.get():
                password_entry.config(show="")
            else:
                password_entry.config(show="*")

        show_password_var = tk.BooleanVar()
        show_password_checkbox = tk.Checkbutton(self.root, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
        show_password_checkbox.pack()

        tk.Button(self.root, text="Suggest Strong Password", command=suggest_password).pack(pady=5)

        def save_password():
            website = website_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            if website and username and password:
                encrypted_password = encrypt_password(password)
                add_password(website, username, encrypted_password)
                messagebox.showinfo("Success", "Password added successfully!")
                self.show_main_menu()
            else:
                messagebox.showerror("Error", "Please fill in all fields.")

        tk.Button(self.root, text="Save Password", command=save_password).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_main_menu).pack(pady=5)

    def generate_strong_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password
    
    def check_expiring_passwords(self):
        """Checks for and notifies the user of any passwords that haven't been updated in the specified duration."""
        expired_passwords = get_expiring_passwords()
        if expired_passwords:
            message = "The following passwords have not been updated in 90+ days:\n"
            for id, website, username, _, _ in expired_passwords:
                message += f"- {website} ({username})\n"
            messagebox.showwarning("Password Expiration Notice", message)

    def export_data(self):
        """Exports passwords and encryption key to a zip file."""
        # Open dialog for the user to select the save location and file name
        zip_path = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("Zip files", "*.zip")])
        if zip_path:
            try:
                # Create the zip file and add both the password data and encryption key
                with zipfile.ZipFile(zip_path, "w") as zip_file:
                    # Retrieve passwords and prepare them for export
                    data = []
                    for id, website, username, encrypted_password, created_at in retrieve_passwords():
                        encrypted_password_base64 = base64.b64encode(encrypted_password).decode("utf-8")
                        data.append({
                            "website": website,
                            "username": username,
                            "password": encrypted_password_base64,
                            "created_at": created_at
                        })

                    # Write password data to JSON and add it to the zip file
                    data_json = json.dumps(data)
                    zip_file.writestr("password_data.json", data_json)

                    # Add the encryption key to the zip file
                    key_path = os.path.join(os.path.expanduser("~"), ".password_manager", "secret.key")
                    zip_file.write(key_path, "secret.key")
                
                messagebox.showinfo("Success", f"Data exported successfully to {zip_path}")
            
            except Exception as e:
                messagebox.showerror("Export Failed", f"Error during export: {e}")

    def import_data(self):
        """Imports password data and encryption key from a zip file."""
        # Prompt the user to select a zip file for import
        zip_path = filedialog.askopenfilename(title="Select Backup Zip File", filetypes=[("Zip files", "*.zip")])
        if zip_path:
            try:
                # Extract the zip file contents
                with zipfile.ZipFile(zip_path, "r") as zip_file:
                    # Extract password_data.json and secret.key to temporary locations
                    zip_file.extract("password_data.json", "/tmp")
                    zip_file.extract("secret.key", "/tmp")

                # Load the encryption key from the extracted key file
                with open("/tmp/secret.key", "rb") as key_file:
                    key = key_file.read()
                    fernet = Fernet(key)

                # Load and decrypt password data from password_data.json
                with open("/tmp/password_data.json", "r") as data_file:
                    data = json.load(data_file)
                    for entry in data:
                        encrypted_password_bytes = base64.b64decode(entry["password"])
                        decrypted_password = fernet.decrypt(encrypted_password_bytes).decode("utf-8")
                        # Add the decrypted password back to the database
                        add_password(entry["website"], entry["username"], decrypted_password)

                messagebox.showinfo("Import Successful", "Data imported successfully.")
            
            except Exception as e:
                messagebox.showerror("Import Failed", f"Error during import: {e}")

    def backup_user_data(self):
        """Trigger a backup of the current data and encryption key."""
        try:
            backup_folder = backup_data()
            messagebox.showinfo("Backup Successful", f"Backup created at: {backup_folder}")
        except Exception as e:
            messagebox.showerror("Backup Failed", f"Error creating backup: {e}")

        # Add a button to trigger backup
        tk.Button(self.root, text="Backup Data", command=self.backup_user_data).pack(fill="x", pady=5)

    def show_main_menu(self):
        self.clear_window()
        tk.Label(self.root, text="Password Manager", font=("Arial", 16)).pack(pady=10)

        tk.Button(self.root, text="Add New Password", command=self.add_new_password).pack(fill="x", pady=5)
        tk.Button(self.root, text="View Saved Passwords", command=self.view_passwords).pack(fill="x", pady=5)
        tk.Button(self.root, text="Edit a Password", command=self.edit_password_entry).pack(fill="x", pady=5)
        tk.Button(self.root, text="Delete a Password", command=self.delete_password_entry).pack(fill="x", pady=5)
        
        # Add Export and Import buttons
        tk.Button(self.root, text="Export Data", command=self.export_data).pack(fill="x", pady=5)
        tk.Button(self.root, text="Import Data", command=self.import_data).pack(fill="x", pady=5)
        
        tk.Button(self.root, text="Exit", command=self.root.quit).pack(fill="x", pady=5)

        self.reset_inactivity_timer()  # Reset timer on entering the main menu

    def view_passwords(self):
        self.clear_window()
        tk.Label(self.root, text="Saved Passwords", font=("Arial", 14)).pack(pady=10)
        passwords = retrieve_passwords()

        for id, website, username, encrypted_password, created_at in passwords:
            try:
                print(f"Attempting to decrypt password for {website}")
                print(f"Encrypted (base64): {encrypted_password}")
                decrypted_password = decrypt_password(encrypted_password)  # Decryption step
                print(f"Decrypted password: {decrypted_password}")
                tk.Label(self.root, text=f"Website: {website}, Username: {username}, Password: {decrypted_password}, Last Updated: {created_at}").pack()
            except Exception as e:
                print(f"Error decrypting password for {website}: {e}")
                tk.Label(self.root, text=f"Website: {website}, Username: {username}, Password: [Error Decrypting], Last Updated: {created_at}").pack()

        tk.Button(self.root, text="Back", command=self.show_main_menu).pack(pady=10)
        self.reset_inactivity_timer()  # Reset timer on interaction

    def edit_password_entry(self):
        self.clear_window()
        
        tk.Label(self.root, text="Select the entry to edit", font=("Arial", 14)).pack(pady=10)
        
        # Retrieve all passwords to display in dropdown
        passwords = retrieve_passwords()
        
        if not passwords:
            messagebox.showinfo("Info", "No passwords found to edit.")
            self.show_main_menu()
            return
        
        # Create a list of options with website and username
        options = [f"{id}: {website} ({username})" for id, website, username, _, _ in passwords]
        
        # Create a dropdown menu to select an entry
        selected_option = tk.StringVar(self.root)
        selected_option.set(options[0])  # Set the first option as default
        dropdown = ttk.Combobox(self.root, textvariable=selected_option, values=options, state="readonly", width=50)
        dropdown.pack(pady=5)

        # Define update function within this method to use `self` and `selected_option`
        def update_selected_entry():
            # Extract ID from the selected option
            selected_id = int(selected_option.get().split(":")[0])

            # Prompt the user for new values
            new_website = simpledialog.askstring("Edit Entry", "Enter the new website:")
            new_username = simpledialog.askstring("Edit Entry", "Enter the new username:")
            new_password = simpledialog.askstring("Edit Entry", "Enter the new password:")

            # Update the fields that the user provides
            if new_website or new_username or new_password:
                # Encrypt the password if it was updated
                encrypted_password = encrypt_password(new_password) if new_password else None

                # Pass the updates to the database function
                update_entry(selected_id, new_website, new_username, encrypted_password)
                messagebox.showinfo("Success", "Entry updated successfully!")
            self.show_main_menu()

        # Button to confirm the selected entry for editing
        tk.Button(self.root, text="Edit Selected Entry", command=update_selected_entry).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.show_main_menu).pack(pady=5)
        
        self.reset_inactivity_timer()  # Reset timer on interaction

    def delete_password_entry(self):
        entry_id = simpledialog.askinteger("Delete Password", "Enter the ID of the password entry to delete:")
        if entry_id:
            delete_password(entry_id)
            messagebox.showinfo("Success", "Password entry deleted successfully!")
        self.reset_inactivity_timer()  # Reset timer on interaction

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

def import_user_data(self):

    """Prompts for a zip file to import data and encryption key."""
    zip_path = filedialog.askopenfilename(title="Select Backup Zip File", filetypes=[("Zip Files", "*.zip")])
    if zip_path:
        try:
            import_data(zip_path)
            messagebox.showinfo("Import Successful", "Data imported successfully.")
        except Exception as e:
            messagebox.showerror("Import Failed", f"Error during import: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()