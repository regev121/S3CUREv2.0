import bcrypt
from cryptography.fernet import Fernet
from jose import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.environ["SECRET_KEY"]
if len(SECRET_KEY.encode("utf-8")) < 32:
    raise ValueError("SECRET_KEY must be at least 32 bytes.")
cipher_suite = Fernet(os.environ["ENCRYPTION_KEY"].encode("utf-8"))

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- 2. ניהול סיסמאות (Bcrypt) ---


def get_password_hash(password: str) -> str:
    """הופך סיסמה להאש לשמירה ב-DB"""
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """בודק אם הסיסמה נכונה"""
    try:
        pwd_bytes = plain_password.encode("utf-8")
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False


# --- 3. הצפנת מפתחות AWS (AES-256) ---


def encrypt_data(data: str) -> str:
    return cipher_suite.encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str) -> str:
    return cipher_suite.decrypt(encrypted_data.encode()).decode()


# --- 4. ניהול טוקנים (JWT) ---


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """יוצר טוקן גישה למשתמש שהתחבר"""
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta is not None else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode.update({"exp": expire})

    # שימוש ב-SECRET_KEY לחתימה
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
