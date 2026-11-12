from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, Float, ForeignKey, Index, Integer, JSON, String
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


class AppRole(Base):
    __tablename__ = "app_roles"
    __table_args__ = (CheckConstraint("role IN ('ADMIN', 'AUDITOR')", name="app_role_values"),)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role = Column(String(7), nullable=False)


class ScanRecord(Base):
    __tablename__ = "scan_records"
    __table_args__ = (Index("scan_records_user_time", "username", "modified_at"),)

    key = Column(String(1024), primary_key=True)
    username = Column(String, nullable=False)
    scanned_at = Column(DateTime(timezone=True), nullable=False, index=True)
    modified_at = Column(DateTime(timezone=True), nullable=False)
    score = Column(Float, nullable=False)
    config_version = Column(String)
    config_created_at = Column(String)
    severity_counts = Column(JSON, nullable=False)


class ScanIndexState(Base):
    __tablename__ = "scan_index_state"

    id = Column(Integer, primary_key=True)
    ready = Column(Boolean, nullable=False)


class BulkScanJob(Base):
    __tablename__ = "bulk_scan_jobs"

    id = Column(String(32), primary_key=True)
    active_slot = Column(Integer, unique=True)
    status = Column(String(16), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)
    total = Column(Integer, nullable=False, default=0)
    scanned = Column(Integer, nullable=False, default=0)
    failed = Column(Integer, nullable=False, default=0)


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
