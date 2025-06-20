import os
from cryptography.fernet import Fernet

# Load your Fernet key from environment variable
FERNET_KEY = os.getenv("FERNET_KEY")

if not FERNET_KEY:
    raise ValueError("FERNET_KEY environment variable not set!")

fernet = Fernet(FERNET_KEY.encode())

def encrypt_text(plain_text: str) -> str:
    """Encrypt a string and return as base64 string."""
    encrypted = fernet.encrypt(plain_text.encode())
    return encrypted.decode()

def decrypt_text(encrypted_text: str) -> str:
    """Decrypt a base64 string back to plain text."""
    decrypted = fernet.decrypt(encrypted_text.encode())
    return decrypted.decode()