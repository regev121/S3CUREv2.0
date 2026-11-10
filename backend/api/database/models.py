from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.api.database.connection import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    # קשר: למשתמש אחד יש הרבה חשבונות
    s3_accounts = relationship("S3Account", back_populates="owner")


class S3Account(Base):
    __tablename__ = "s3_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))

    alias_name = Column(String)  # שם לתצוגה (למשל "Production Env")
    endpoint_url = Column(String, default="http://127.0.0.1:9000")
    region = Column(String, default="us-east-1")

    # --- הליבה של האבטחה (Security Core) ---
    # המפתחות נשמרים כאן אך ורק לאחר הצפנת AES-256
    access_key_encrypted = Column(String, nullable=False)
    secret_key_encrypted = Column(String, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    # קשר חזרה למשתמש
    owner = relationship("User", back_populates="s3_accounts")
