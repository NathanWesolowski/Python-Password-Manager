import os
import base64
from cryptography.fernet import Fernet

# Set the encryption key path in the `.password_manager` folder in the user's home directory
base_dir = os.path.join(os.path.expanduser("~"), ".password_manager")
key_path = os.path.join(base_dir, "secret.key")

# Ensure the base directory exists, creating it if necessary
os.makedirs(base_dir, exist_ok=True)

def generate_key():
    """
    Generates a new encryption key and saves it to the key file.
    This function only creates the key if it does not already exist.
    """
    if not os.path.exists(key_path):
        key = Fernet.generate_key()  # Generate a new encryption key
        with open(key_path, "wb") as key_file:
            key_file.write(key)  # Save the key to the specified path

def load_key():
    """
    Loads the encryption key from the key file.
    If the key does not exist, it generates a new one.
    """
    if not os.path.exists(key_path):
        generate_key()  # Only generate the key if it doesn't exist
    with open(key_path, "rb") as key_file:
        key = key_file.read()  # Read the key from the file
    print(f"Loaded key from {key_path}: {key}")
    return key

def encrypt_password(password):
    """
    Encrypts a password using the loaded encryption key.
    
    Args:
        password (str): The password to be encrypted.
        
    Returns:
        bytes: The encrypted password.
    """
    fernet = Fernet(load_key())  # Create a Fernet instance with the encryption key
    return fernet.encrypt(password.encode())  # Encrypts the password as bytes

def decrypt_password(encrypted_password):
    """
    Decrypts an encrypted password using the loaded encryption key.
    
    Args:
        encrypted_password (bytes): The encrypted password.
        
    Returns:
        str: The decrypted password.
    """
    fernet = Fernet(load_key())  # Create a Fernet instance with the encryption key
    return fernet.decrypt(encrypted_password).decode()  # Decrypts the password back to its original form

if __name__ == "__main__":
    # Example usage: encrypting and decrypting a sample password
    test_password = "SamplePassword123!"
    print("Original Password:", test_password)

    # Encrypt the password
    encrypted = encrypt_password(test_password)
    print("Encrypted Password (base64):", base64.b64encode(encrypted).decode('utf-8'))

    # Decrypt the password
    decrypted = decrypt_password(encrypted)
    print("Decrypted Password:", decrypted)
