from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_password(password):
    fernet = Fernet(load_key())
    return fernet.encrypt(password.encode())

def decrypt_password(encrypted_password):
    fernet = Fernet(load_key())
    return fernet.decrypt(encrypted_password).decode()
