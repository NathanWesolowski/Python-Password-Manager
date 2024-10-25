import sqlite3

def initialize_db():
    connection = sqlite3.connect("password_manager.db")
    cursor = connection.cursor()
    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )'''
    )
    connection.commit()
    connection.close()

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