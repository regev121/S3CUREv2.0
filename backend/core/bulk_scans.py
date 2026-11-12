import logging
from datetime import datetime, timedelta, timezone
from functools import partial
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from backend.api.database.connection import SessionLocal
from backend.api.database.models import BulkScanJob
from backend.core.graphLoader.riskEngine import RiskEngine
from backend.core.scan_index import record_scan


logger = logging.getLogger(__name__)
INACTIVITY_LIMIT = timedelta(minutes=30)


def _expire_inactive(db):
    db.execute(
        update(BulkScanJob)
        .where(BulkScanJob.active_slot == 1, BulkScanJob.updated_at < datetime.now(timezone.utc) - INACTIVITY_LIMIT)
        .values(active_slot=None, status="interrupted", updated_at=datetime.now(timezone.utc))
    )


def job_data(job):
    return {
        "job_id": job.id, "status": job.status, "total": job.total,
        "scanned": job.scanned, "failed": job.failed,
    }


def queue_scan(db):
    _expire_inactive(db)
    job = BulkScanJob(id=uuid4().hex, active_slot=1, status="queued", updated_at=datetime.now(timezone.utc))
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        active = db.scalar(select(BulkScanJob).where(BulkScanJob.active_slot == 1))
        if active:
            return job_data(active), False
        # The competing job finished before the active-row lookup.
        return queue_scan(db)
    return job_data(job), True


def get_job(db, job_id):
    _expire_inactive(db)
    db.commit()
    return db.get(BulkScanJob, job_id)


def _update_job(db, job_id, **values):
    result = db.execute(
        update(BulkScanJob).where(BulkScanJob.id == job_id, BulkScanJob.active_slot == 1)
        .values(updated_at=datetime.now(timezone.utc), **values)
    )
    db.commit()
    return result.rowcount == 1


def run_bulk_scan(job_id, loader):
    with SessionLocal() as db:
        try:
            if not _update_job(db, job_id, status="running"):
                return
            engine = RiskEngine(loader)
            usernames = loader.get_all_users()
            if not _update_job(db, job_id, total=len(usernames)):
                return
            scanned = failed = 0
            for username in usernames:
                try:
                    engine.analyze_user_return_data(username, on_archived=partial(record_scan, db))
                    scanned += 1
                except (RuntimeError, OSError, ValueError, ClientError, BotoCoreError) as error:
                    db.rollback()
                    failed += 1
                    logger.warning("Bulk scan %s failed for one identity (%s).", job_id, type(error).__name__)
                if not _update_job(db, job_id, scanned=scanned, failed=failed):
                    return
            _update_job(db, job_id, status="completed", active_slot=None)
        except Exception:
            db.rollback()
            logger.exception("Bulk scan %s stopped.", job_id)
            _update_job(db, job_id, status="failed", active_slot=None)
