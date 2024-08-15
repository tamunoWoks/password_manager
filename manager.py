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

