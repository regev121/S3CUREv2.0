import bcrypt
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()
cipher_suite = Fernet(os.environ["ENCRYPTION_KEY"].encode("utf-8"))

_DUMMY_HASH = bcrypt.hashpw(os.urandom(32), bcrypt.gensalt())

# --- 2. ניהול סיסמאות (Bcrypt) ---


def get_password_hash(password: str) -> str:
    """הופך סיסמה להאש לשמירה ב-DB"""
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    """בודק אם הסיסמה נכונה"""
    try:
        pwd_bytes = plain_password.encode("utf-8")
        hash_bytes = hashed_password.encode("utf-8") if hashed_password else _DUMMY_HASH
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except ValueError:
        return False


# --- 3. הצפנת מפתחות AWS (AES-256) ---


def encrypt_data(data: str) -> str:
    return cipher_suite.encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str) -> str:
    return cipher_suite.decrypt(encrypted_data.encode()).decode()
