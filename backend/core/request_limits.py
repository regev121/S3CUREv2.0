from contextlib import contextmanager
from hashlib import sha256
from threading import BoundedSemaphore, Lock
from time import time

from fastapi import HTTPException
from sqlalchemy import delete, text
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from backend.api.database.models import RequestLimit


def _rate_error(retry_after, detail="Too many requests. Try again shortly."):
    return HTTPException(status_code=429, detail=detail, headers={"Retry-After": str(retry_after)})


def consume_limit(db, scope, identity, *, limit, seconds):
    now = int(time())
    window = now - now % seconds
    key = sha256(f"{scope}:{identity}".encode()).hexdigest()
    insert = postgres_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    query = insert(RequestLimit).values(key=key, window=window, count=1)
    accepted = db.execute(query.on_conflict_do_update(
        index_elements=[RequestLimit.key, RequestLimit.window],
        set_={"count": RequestLimit.count + 1},
        where=RequestLimit.count < limit,
    ).returning(RequestLimit.count)).scalar_one_or_none()
    db.execute(delete(RequestLimit).where(RequestLimit.window < now - 600))
    db.commit()
    if accepted is None:
        raise _rate_error(window + seconds - now)


_scan_slots = BoundedSemaphore(4)
_scan_gate = Lock()
_local_scans = set()


@contextmanager
def reserve_scan(db, user_id):
    """Keep scan leases until the request commits or rolls back."""
    if db.get_bind().dialect.name == "postgresql":
        # Keep this dedicated connection open even if the scan's data session commits.
        with db.get_bind().connect() as connection:
            def acquire(namespace, key):
                return connection.scalar(text("SELECT pg_try_advisory_xact_lock(:ns, :key)"),
                                         {"ns": namespace, "key": key})

            if not acquire(27810, user_id) or not any(acquire(27811, slot) for slot in range(4)):
                raise _rate_error(5, "Scan capacity is busy. Try again shortly.")
            yield
        return

    # SQLite is supported for local single-process demos.
    with _scan_gate:
        if user_id in _local_scans or not _scan_slots.acquire(blocking=False):
            raise _rate_error(5, "Scan capacity is busy. Try again shortly.")
        _local_scans.add(user_id)
    try:
        yield
    finally:
        with _scan_gate:
            _local_scans.remove(user_id)
            _scan_slots.release()
