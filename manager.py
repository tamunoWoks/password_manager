"""
Python Script for a password manager
"""
#Import necessary modules
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import secrets

def generate_salt() -> bytes:
    """Generate a secure random salt."""
    return secrets.token_bytes(16)


def derive_key(master_pwd: str, salt: bytes) -> bytes:
    """Derive a key from the master password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))

def load_salt() -> bytes:
    """Load the salt from a file or create a new one if not present."""
    if os.path.exists("salt.bin"):
        with open("salt.bin", "rb") as f:
            return f.read()
    else:
        salt = generate_salt()
        with open("salt.bin", "wb") as f:
            f.write(salt)
        return salt

# Prompt user for the master password and derive the encryption key
master_pwd = input("What is your Master Password? ")
salt = load_salt()
key = derive_key(master_pwd, salt)
fer = Fernet(key)

def view():
    """Display all stored passwords."""
    try:
        with open("passwords.txt", "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue  # Skip empty lines
                parts = line.split("|")
                if len(parts) != 2:
                    print(f"Skipping malformed line: {line}")
                    continue  # Skip lines that don't have exactly two parts

                user, encrypted_pass = parts
                try:
                    decrypted_pass = fer.decrypt(encrypted_pass.encode()).decode()
                    print(f"User: {user} | Password: {decrypted_pass}")
                except Exception as e:
                    print(f"Failed to decrypt password for user {user}: {e}")
    except FileNotFoundError:
        print("No passwords file found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def add():
    """Add a new password entry."""
    name = input("Account Name: ")
    pwd = input("Password: ")
    encrypted_pass = fer.encrypt(pwd.encode()).decode()

    with open("passwords.txt", "a") as f:
        f.write(f"{name}|{encrypted_pass}\n")

def main():
    """Main loop to add or view passwords."""
    while True:
        mode = input(
            "Would you like to add a new password or view existing ones (view, add)? Press q to quit: "
        ).lower()
        if mode == "q":
            break
        elif mode == "view":
            view()
        elif mode == "add":
            add()
        else:
            print("Invalid mode. Please enter 'view', 'add', or 'q'.")