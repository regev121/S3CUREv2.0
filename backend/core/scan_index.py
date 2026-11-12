from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert


SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low")


def _severity(violation):
    label = str(violation.get("rule", "")).partition(":")[0].title()
    if label in SEVERITY_LEVELS:
        return label
    score = violation.get("severity", 0)
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


def utc(value):
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def summarize(key, report, modified):
    scanned_at = datetime.fromisoformat(report["scanned_at"]) if report.get("scanned_at") else modified
    return {
        "key": key, "username": report["user"], "score": report["risk_score"],
        "scanned_at": utc(scanned_at), "modified_at": utc(scanned_at),
        "config_version": report.get("risk_config_version"),
        "config_created_at": report.get("risk_config_created_at"),
        "severity_counts": dict(Counter(
            _severity(item) for item in report.get("violated_rules", []) if isinstance(item, dict)
        )),
    }


def store_summary(db, summary):
    from backend.api.database.models import ScanRecord

    insert = postgres_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    query = insert(ScanRecord).values(**summary)
    db.execute(query.on_conflict_do_nothing(index_elements=[ScanRecord.key]))


def record_scan(db, key, report, scanned_at):
    store_summary(db, summarize(key, report, scanned_at))
    db.commit()


def backfill_scan_index(loader, db):
    from backend.api.database.models import ScanIndexState

    count = 0
    for key, report, modified in loader.iter_reports():
        store_summary(db, summarize(key, report, modified))
        count += 1
        if count % 500 == 0:
            db.commit()
    db.merge(ScanIndexState(id=1, ready=True))
    db.commit()
    return count


def index_ready(db):
    from backend.api.database.models import ScanIndexState

    state = db.get(ScanIndexState, 1)
    return state is not None and state.ready


def indexed_records(db):
    from backend.api.database.models import ScanRecord

    if index_ready(db):
        query = select(
            ScanRecord.key, ScanRecord.username, ScanRecord.score, ScanRecord.config_version,
            ScanRecord.config_created_at, ScanRecord.scanned_at, ScanRecord.severity_counts,
        ).order_by(ScanRecord.scanned_at, ScanRecord.key)
        return db.execute(query).mappings().yield_per(1000)
    return None


def _history_entry(key, modified, score, version):
    return {
        "filename": key, "last_modified": utc(modified).isoformat(),
        "score": score, "risk_config_version": version,
    }


def scan_history(loader, db, username, limit, offset):
    from backend.api.database.models import ScanRecord

    if index_ready(db):
        condition = ScanRecord.username == username
        count = db.scalar(select(func.count()).select_from(ScanRecord).where(condition))
        rows = db.scalars(
            select(ScanRecord).where(condition)
            .order_by(ScanRecord.modified_at.desc(), ScanRecord.key.desc()).offset(offset).limit(limit)
        )
        return count, [
            _history_entry(row.key, row.modified_at, row.score, row.config_version) for row in rows
        ]

    reports = [summarize(key, report, modified) for key, report, modified in loader.iter_reports(username)]
    reports.sort(key=lambda row: (row["modified_at"], row["key"]), reverse=True)
    return len(reports), [
        _history_entry(row["key"], row["modified_at"], row["score"], row["config_version"])
        for row in reports[offset:offset + limit]
    ]
