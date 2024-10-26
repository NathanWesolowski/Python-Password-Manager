import os
import zipfile
import sqlite3
import hashlib
import json
import base64
from datetime import datetime, timedelta
from encryption import encrypt_password, decrypt_password, generate_key, load_key, Fernet


# Define the path in the user's home directory for universal access
base_dir = os.path.join(os.path.expanduser("~"), ".password_manager")
db_path = os.path.join(base_dir, "password_manager.db")

# Ensure the base directory exists
os.makedirs(base_dir, exist_ok=True)

def initialize_db():
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT
        )'''
    )
    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL
        )'''
    )
    connection.commit()
    connection.close()

def set_master_password(master_password):
    hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("DELETE FROM master")  # Ensure only one master password exists
    cursor.execute("INSERT INTO master (password_hash) VALUES (?)", (hashed_password,))
    connection.commit()
    connection.close()

def verify_master_password(master_password):
    hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("SELECT password_hash FROM master")
    result = cursor.fetchone()
    connection.close()
    return result and hashed_password == result[0]

def master_password_exists():
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("SELECT password_hash FROM master")
    result = cursor.fetchone()
    connection.close()
    return result is not None

def add_password(website, username, password):
    """Encrypts the password if it's a string and adds it to the database."""
    if isinstance(password, bytes):
        encrypted_password = password  # Already encrypted
    else:
        encrypted_password = encrypt_password(password)  # Encrypt if it's not already

    # Convert encrypted password to a base64 string for consistent storage
    encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("INSERT INTO passwords (website, username, password, created_at) VALUES (?, ?, ?, ?)",
                   (website, username, encrypted_password_base64, created_at))
    connection.commit()
    connection.close()

def retrieve_passwords():
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM passwords")
    results = cursor.fetchall()
    connection.close()

    # Decode the base64 password back to bytes
    decoded_results = []
    for id, website, username, password_base64, created_at in results:
        encrypted_password_bytes = base64.b64decode(password_base64)
        decoded_results.append((id, website, username, encrypted_password_bytes, created_at))

    return decoded_results

def delete_password(entry_id):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
    connection.commit()
    connection.close()

def update_password(entry_id, new_password):
    new_created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encrypted_password = encrypt_password(new_password)  # Encrypt the password before updating
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("UPDATE passwords SET password = ?, created_at = ? WHERE id = ?", 
                   (encrypted_password, new_created_at, entry_id))
    connection.commit()
    connection.close()

def get_expiring_passwords(days_threshold=90):
    threshold_date = datetime.now() - timedelta(days=days_threshold)
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM passwords WHERE datetime(created_at) < ?", (threshold_date,))
    results = cursor.fetchall()
    connection.close()
    return results

def export_passwords(file_path):
    """Exports all passwords in encrypted form to a file."""
    passwords = retrieve_passwords()
    data_to_export = []
    
    for id, website, username, password, created_at in passwords:
        # Password is already encrypted in the database
        encrypted_password = base64.b64encode(password).decode('utf-8')  # Convert bytes to base64 string
        data_to_export.append({
            "website": website,
            "username": username,
            "password": encrypted_password,
            "created_at": created_at
        })
    
    with open(file_path, "w") as file:
        json.dump(data_to_export, file)

def import_passwords(file_path, key_path=None):
    """Imports passwords from an encrypted file, avoiding duplicates."""
    
    key = load_key() if key_path is None else open(key_path, "rb").read()
    fernet = Fernet(key)
    
    with open(file_path, "r") as file:
        data = json.load(file)

    for entry in data:
        try:
            encrypted_password_bytes = base64.b64decode(entry["password"])
            decrypted_password = fernet.decrypt(encrypted_password_bytes).decode("utf-8")
            
            # Check if the entry already exists
            if not entry_exists(entry["website"], entry["username"]):
                add_password(entry["website"], entry["username"], decrypted_password)
            else:
                print(f"Skipped duplicate entry for {entry['website']} ({entry['username']})")
        
        except Exception as e:
            print(f"Failed to import entry {entry['website']} ({entry['username']}): {e}")

def entry_exists(website, username):
    """Check if an entry with the given website and username exists in the database."""
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("SELECT 1 FROM passwords WHERE website = ? AND username = ?", (website, username))
    result = cursor.fetchone()
    connection.close()
    return result is not None

    """Imports passwords from an encrypted file, avoiding duplicates."""
    
    key = load_key() if key_path is None else open(key_path, "rb").read()
    fernet = Fernet(key)
    
    with open(file_path, "r") as file:
        data = json.load(file)

    for entry in data:
        try:
            encrypted_password_bytes = base64.b64decode(entry["password"])
            decrypted_password = fernet.decrypt(encrypted_password_bytes).decode("utf-8")
            
            # Check if the entry already exists
            if not entry_exists(entry["website"], entry["username"]):
                add_password(entry["website"], entry["username"], decrypted_password)
            else:
                print(f"Skipped duplicate entry for {entry['website']} ({entry['username']})")
        
        except Exception as e:
            print(f"Failed to import entry {entry['website']} ({entry['username']}): {e}")

def update_entry(entry_id, new_website=None, new_username=None, new_password=None):
    """Updates specified fields of a password entry."""
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    updates = []
    values = []

    if new_website:
        updates.append("website = ?")
        values.append(new_website)
    if new_username:
        updates.append("username = ?")
        values.append(new_username)
    if new_password:
        # Encrypt if it's a plain string
        encrypted_password = new_password if isinstance(new_password, bytes) else encrypt_password(new_password)
        # Base64 encode the encrypted password for consistent storage
        encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')
        updates.append("password = ?")
        values.append(encrypted_password_base64)

    values.append(entry_id)
    query = f"UPDATE passwords SET {', '.join(updates)} WHERE id = ?"
    cursor.execute(query, values)

    connection.commit()
    connection.close()


    """Imports data and encryption key from a zip file into the app database."""
    import zipfile
    from encryption import load_key, Fernet
    import json

    # Extract zip contents
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        zip_file.extract("password_data.json", "/tmp")
        zip_file.extract("secret.key", "/tmp")

    # Load the encryption key from the extracted key file
    with open("/tmp/secret.key", "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)

    # Load and decrypt each password entry
    with open("/tmp/password_data.json", "r") as data_file:
        data = json.load(data_file)
        for entry in data:
            encrypted_password_bytes = base64.b64decode(entry["password"])
            decrypted_password = fernet.decrypt(encrypted_password_bytes).decode("utf-8")
            add_password(entry["website"], entry["username"], decrypted_password)
    
    print("Data imported successfully.")

def export_data(retrieve_passwords_func, encryption_key):
    """Exports current database data and encryption key into a zip file."""
    
    # Folder to save backups
    export_folder = os.path.join(os.path.expanduser("~"), "PasswordManagerExports")
    os.makedirs(export_folder, exist_ok=True)
    
    # Timestamped filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    zip_filename = os.path.join(export_folder, f"password_backup_{timestamp}.zip")

    # Prepare data to export
    data = []
    for id, website, username, encrypted_password, created_at in retrieve_passwords_func():
        encrypted_password_base64 = base64.b64encode(encrypted_password).decode("utf-8")
        data.append({
            "website": website,
            "username": username,
            "password": encrypted_password_base64,
            "created_at": created_at
        })
    
    # Write data and key to zip
    with zipfile.ZipFile(zip_filename, "w") as zip_file:
        data_json = json.dumps(data)
        zip_file.writestr("password_data.json", data_json)  # Add password data to zip
        zip_file.writestr("encryption_key.key", encryption_key.decode())  # Add encryption key

    print(f"Data exported successfully to: {zip_filename}")
    return zip_filename

def import_data(zip_path, add_password_func):
    """Imports data and encryption key from a zip file into the app database."""
    
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        # Extract files from the zip
        with zip_file.open("password_data.json") as data_file:
            data = json.load(data_file)

        # Load the encryption key from the zip file
        with zip_file.open("encryption_key.key") as key_file:
            key = key_file.read()
            fernet = Fernet(key)
        
        # Decrypt and import passwords
        for entry in data:
            encrypted_password_bytes = base64.b64decode(entry["password"])
            decrypted_password = fernet.decrypt(encrypted_password_bytes).decode("utf-8")
            add_password_func(entry["website"], entry["username"], decrypted_password)
    
    print("Data imported successfully.")
    return True