import sqlite3
import hashlib

def initialize_db():
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    # Create the passwords table if it doesn't exist
    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )'''
    )
    # Create the master table if it doesn't exist
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
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    cursor.execute("DELETE FROM master")  # Ensure only one master password exists
    cursor.execute("INSERT INTO master (password_hash) VALUES (?)", (hashed_password,))
    connection.commit()
    connection.close()

def verify_master_password(master_password):
    hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    cursor.execute("SELECT password_hash FROM master")
    result = cursor.fetchone()
    connection.close()
    if result is None:
        return False
    return hashed_password == result[0]

def master_password_exists():
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    cursor.execute("SELECT password_hash FROM master")
    result = cursor.fetchone()
    connection.close()
    return result is not None  # Returns True if a master password is set


def add_password(website, username, password):
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                   (website, username, password))
    connection.commit()
    connection.close()

def retrieve_passwords():
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM passwords")
    results = cursor.fetchall()
    connection.close()
    return results

def delete_password(entry_id):
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
    connection.commit()
    connection.close()

def update_password(entry_id, new_password):
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    cursor.execute("UPDATE passwords SET password = ? WHERE id = ?", (new_password, entry_id))
    connection.commit()
    connection.close()

