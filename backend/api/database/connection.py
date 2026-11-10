import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()
database_url = os.environ["DATABASE_URL"]
engine = create_engine(database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    with SessionLocal() as db:
        yield db


def init_db():
    from backend.api.database import models  # Register models before creating tables.

    Base.metadata.create_all(bind=engine)



def lock_app_identity(db, username):
    """Serialize provisioning of equivalent usernames across PostgreSQL sessions."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:identity))"),
            {"identity": "s3cure:minio:" + username.casefold()},
        )
