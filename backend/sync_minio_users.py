"""Create missing MinIO identities for existing S3CURE accounts."""

from collections import Counter

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from backend.api.database.connection import SessionLocal, lock_app_identity
from backend.api.database.models import User
from backend.core.graphLoader.s3Loader import IdentityConflict, MinioError, S3Loader


def main():
    with SessionLocal() as db:
        names = list(db.scalars(select(User.username).order_by(User.username)))
    loader = S3Loader()
    app_names = [name for name in names if not loader.is_scanner_name(name)]
    name_counts = Counter(name.casefold() for name in app_names)
    skipped = len(names) - len(app_names)
    created = []
    linked = []
    conflicts = []
    failures = []

    for name in app_names:
        if name_counts[name.casefold()] > 1:
            conflicts.append(name)
            print(f"Needs review: {name} differs from another app username only by case.")
            continue
        try:
            with SessionLocal() as db:
                lock_app_identity(db, name)
                was_created = loader.provision_app_identity(name, link_existing=True)
            (created if was_created else linked).append(name)
            print(f"{'Created' if was_created else 'Already linked'}: {name}")
        except IdentityConflict as error:
            conflicts.append(name)
            print(f"Needs review: {name}. {error}")
        except MinioError as error:
            failures.append(name)
            print(f"Failed: {name}. {error}")

    actual = set(loader.get_all_users())
    missing = [name for name in created + linked if name not in actual]
    if missing:
        failures.extend(missing)
        print(f"Could not verify in MinIO: {', '.join(missing)}")
    print(
        f"{len(created)} created, {len(linked)} already linked, "
        f"{skipped} service entries skipped, {len(conflicts)} need review, {len(failures)} failed."
    )
    return 1 if failures else 2 if conflicts else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MinioError, SQLAlchemyError) as error:
        raise SystemExit(f"User sync stopped ({type(error).__name__}).") from None
