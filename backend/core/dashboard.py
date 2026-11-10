from collections import Counter
from datetime import datetime, timedelta, timezone
from time import perf_counter
from urllib.request import urlopen

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from backend.core.graphLoader.s3Loader import MinioError


SEVERITY_COLORS = {
    "Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#198754",
}


def _risk_status(score):
    if score is None:
        return "Awaiting scans"
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High Risk"
    if score >= 40:
        return "Moderate"
    return "Healthy"


def _severity(violation):
    label = str(violation.get("rule", "")).partition(":")[0].title()
    if label in SEVERITY_COLORS:
        return label
    score = violation.get("severity", 0)
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def _average(rows):
    return round(sum(row["score"] for row in rows) / len(rows), 2) if rows else None


def _availability(loader, db):
    started = perf_counter()
    try:
        with urlopen(f"{loader.endpoint}/minio/health/ready", timeout=3) as response:
            minio_online = response.status == 200
    except OSError:
        minio_online = False
    latency = round((perf_counter() - started) * 1000) if minio_online else None
    try:
        db.execute(text("SELECT 1"))
        db_online = True
    except SQLAlchemyError:
        db_online = False

    telemetry = {
        "apiOnline": True,
        "minioOnline": minio_online,
        "databaseOnline": db_online,
        "minioLatencyMs": latency,
        "availableBytes": None,
        "totalBytes": None,
        "uptimeSeconds": None,
    }
    if minio_online:
        try:
            info = loader.storage_info()
        except MinioError:
            return telemetry
        drives = {}
        uptimes = []
        for server in info.get("servers", []):
            if isinstance(server.get("uptime"), (int, float)):
                uptimes.append(server["uptime"])
            for drive in server.get("drives", []):
                if drive.get("state") not in (None, "ok", "online"):
                    continue
                total = drive.get("totalspace", drive.get("totalSpace"))
                used = drive.get("usedspace", drive.get("usedSpace"))
                free = drive.get("availspace", drive.get("availableSpace"))
                if free is None and isinstance(total, int) and isinstance(used, int):
                    free = max(total - used, 0)
                if isinstance(total, int) and isinstance(free, int):
                    drive_id = drive.get("uuid") or (server.get("endpoint"), drive.get("endpoint"))
                    drives[drive_id] = total, free
        if drives:
            telemetry["totalBytes"] = sum(total for total, _ in drives.values())
            telemetry["availableBytes"] = sum(free for _, free in drives.values())
        if uptimes:
            telemetry["uptimeSeconds"] = min(uptimes)
    return telemetry


def build_dashboard(loader, db):
    telemetry = _availability(loader, db)
    reports = []
    archive_available = True
    try:
        for key, report, modified in loader.iter_reports():
            scanned_at = datetime.fromisoformat(report["scanned_at"]) if report.get("scanned_at") else modified
            if scanned_at.tzinfo is None:
                scanned_at = scanned_at.replace(tzinfo=timezone.utc)
            reports.append({
                "id": key,
                "user": report["user"],
                "score": report["risk_score"],
                "time": scanned_at,
                "violations": report.get("violated_rules", []),
            })
    except (BotoCoreError, ClientError, MinioError, KeyError, ValueError):
        archive_available = False

    reports.sort(key=lambda row: row["time"])
    latest = {row["user"]: row for row in reports}
    current_score = _average(list(latest.values()))
    violations = Counter(
        _severity(violation)
        for row in latest.values() for violation in row["violations"]
        if isinstance(violation, dict)
    )
    most_at_risk = max(latest.values(), key=lambda row: row["score"], default=None)

    first_day = datetime.now(timezone.utc).date() - timedelta(days=6)
    risk_history = []
    known = {}
    index = 0
    for offset in range(7):
        day = first_day + timedelta(days=offset)
        while index < len(reports) and reports[index]["time"].astimezone(timezone.utc).date() <= day:
            row = reports[index]
            known[row["user"]] = row
            index += 1
        risk_history.append({"day": day.isoformat(), "score": _average(list(known.values()))})

    return {
        "stats": {
            "totalUsersScanned": len(latest),
            "avgRiskScore": current_score,
            "criticalViolations": violations["Critical"],
            "systemHealth": _risk_status(current_score),
            "lastScan": reports[-1]["time"].isoformat() if reports else None,
            "mostAtRisk": (
                {"user": most_at_risk["user"], "score": most_at_risk["score"]} if most_at_risk else None
            ),
        },
        "riskHistory": risk_history,
        "violationsBySeverity": [
            {"name": severity, "value": violations[severity], "color": color}
            for severity, color in SEVERITY_COLORS.items()
        ],
        "recentActivity": [
            {"id": row["id"], "user": row["user"], "score": row["score"],
             "time": row["time"].isoformat(), "status": _risk_status(row["score"])}
            for row in reversed(reports[-10:])
        ],
        "telemetry": {**telemetry, "archiveAvailable": archive_available},
    }
