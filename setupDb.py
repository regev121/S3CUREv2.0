import argparse
from getpass import getpass
from pathlib import Path

from dotenv import set_key
from sqlalchemy import URL, create_engine, inspect, select
from sqlalchemy.exc import SQLAlchemyError


def configure_postgres():
    env_path = Path(__file__).resolve().with_name(".env")
    if not env_path.is_file():
        raise SystemExit("Create .env from .env.example before configuring PostgreSQL.")
    host = input("PostgreSQL host [127.0.0.1]: ").strip() or "127.0.0.1"
    try:
        port = int(input("PostgreSQL port [5432]: ").strip() or "5432")
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        raise SystemExit("The port must be between 1 and 65535.")
    database = input("Database name: ").strip()
    username = input("PostgreSQL username: ").strip()
    if not database or not username:
        raise SystemExit("Enter a database name and username.")
    url = URL.create(
        "postgresql+psycopg2", username=username, password=getpass("PostgreSQL password: "),
        host=host, port=port, database=database,
    )
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            connection.exec_driver_sql("SELECT 1")
            tables = set(inspect(connection).get_table_names())
    except SQLAlchemyError:
        raise SystemExit("PostgreSQL connection failed. Check the host, port, database, and login.")
    finally:
        engine.dispose()
    set_key(env_path, "DATABASE_URL", url.render_as_string(hide_password=False))
    detected = ", ".join(sorted(tables & {"users", "s3_accounts"})) or "none"
    print(f"Connected. S3CURE tables found: {detected}. DATABASE_URL saved in .env.")


def main():
    parser = argparse.ArgumentParser(description="Initialize S3CURE and enroll an existing MinIO user.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--app-user", help="Existing MinIO user to enroll in the S3CURE login database.")
    mode.add_argument("--set-role", nargs=2, metavar=("USERNAME", "ROLE"),
                      help="Assign ADMIN, AUDITOR, or USER to an existing S3CURE account.")
    mode.add_argument("--index-scans", action="store_true", help="Index archived MinIO scan summaries.")
    parser.add_argument("--role", choices=("ADMIN", "AUDITOR", "USER"),
                        help="Application role for a new --app-user account.")
    mode.add_argument("--configure-postgres", action="store_true",
                      help="Test a PostgreSQL login and save it in .env.")
    args = parser.parse_args()
    if args.role and not args.app_user:
        parser.error("--role requires --app-user.")
    if args.set_role and args.set_role[1] not in ("ADMIN", "AUDITOR", "USER"):
        parser.error("Use ADMIN, AUDITOR, or USER.")
    if args.configure_postgres:
        configure_postgres()
        return

    from backend.api.database.connection import SessionLocal, init_db, lock_app_identity
    from backend.api.database.models import AppRole, User
    from backend.core.authentication.security import get_password_hash
    from backend.core.graphLoader.s3Loader import S3Loader

    init_db()
    if args.index_scans:
        from backend.core.scan_index import backfill_scan_index

        with SessionLocal() as db:
            count = backfill_scan_index(S3Loader(), db)
        print(f"Checked {count} archived scans.")
        return
    if args.set_role:
        username, role = args.set_role
        if S3Loader().is_scanner_name(username):
            raise SystemExit("The scanner is a service account.")
        with SessionLocal() as db:
            lock_app_identity(db, username)
            user = db.scalar(select(User).where(User.username == username))
            if user is None:
                raise SystemExit("The app user does not exist.")
            current = db.get(AppRole, user.id)
            if role != "USER":
                db.merge(AppRole(user_id=user.id, role=role))
            elif current:
                db.delete(current)
            db.commit()
        print(f"Application role saved for {username}.")
        return

    if not args.app_user:
        print("S3CURE tables ready.")
        return

    loader = S3Loader()
    if loader.is_scanner_name(args.app_user):
        raise SystemExit("The scanner is a service account.")
    loader.get_user_info(args.app_user)
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == args.app_user)):
            raise SystemExit("The app user already exists.")
        password = getpass("S3CURE login password: ")
        if not 1 <= len(password.encode("utf-8")) <= 72 or password != getpass("Confirm password: "):
            raise SystemExit("Passwords must match and contain 1–72 bytes.")
        user = User(username=args.app_user, hashed_password=get_password_hash(password))
        db.add(user)
        if args.role in ("ADMIN", "AUDITOR"):
            db.flush()
            db.add(AppRole(user_id=user.id, role=args.role))
        db.commit()
    print(f"App user enrolled: {args.app_user}")


if __name__ == "__main__":
    main()
