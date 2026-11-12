from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from time import perf_counter
from urllib.request import urlopen

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from backend.core.graphLoader.s3Loader import MinioError
from backend.core.scan_index import indexed_records, summarize, utc


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


def _average(rows):
    return round(sum(row["score"] for row in rows) / len(rows), 2) if rows else None


def _daily_scores(reports):
    by_day = defaultdict(dict)
    for row in reports:
        day = row["time"].astimezone(timezone.utc).date()
        by_day[day][row["user"]] = row
    return {day: _average(rows.values()) for day, rows in by_day.items()}


def _history_views(reports, first_day):
    scores = _daily_scores(reports)
    general = {
        "id": "general", "label": "General (last 7 days)",
        "history": [
            {"day": day.isoformat(), "score": scores.get(day)}
            for day in (first_day + timedelta(days=offset) for offset in range(7))
        ],
    }
    versions = defaultdict(list)
    for row in reports:
        versions[row["riskConfigVersion"]].append(row)

    views = [general]
    labels = {}
    for version, rows in sorted(versions.items(), key=lambda entry: entry[1][-1]["time"], reverse=True):
        created_at = next((row["configCreatedAt"] for row in rows if row["configCreatedAt"]), None)
        date = datetime.fromisoformat(created_at) if created_at else rows[0]["time"]
        label = f"CONFIG_Creation_Date:{date:%d/%m/%Y}" if version else "Legacy scans"
        labels[version] = label
        daily = _daily_scores(rows)
        views.append({
            "id": version or "legacy", "label": label,
            "dateEstimated": bool(version and not created_at),
            "history": [{"day": day.isoformat(), "score": score} for day, score in daily.items()],
        })
    duplicates = Counter(view["label"] for view in views)
    seen = Counter()
    for view in views[1:]:
        label = view["label"]
        if duplicates[label] > 1:
            seen[label] += 1
            view["label"] = f"{label} ({seen[label]}/{duplicates[label]})"
            labels[view["id"]] = view["label"]
    return views, labels


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
        summaries = indexed_records(db) if telemetry.get("databaseOnline", True) else None
        if summaries is None:
            summaries = (summarize(key, report, modified) for key, report, modified in loader.iter_reports())
        for summary in summaries:
            reports.append({
                "id": summary["key"],
                "user": summary["username"],
                "score": summary["score"],
                "riskConfigVersion": summary["config_version"],
                "configCreatedAt": summary["config_created_at"],
                "time": utc(summary["scanned_at"]),
                "severityCounts": summary["severity_counts"],
            })
    except (BotoCoreError, ClientError, MinioError, KeyError, ValueError):
        archive_available = False

    reports.sort(key=lambda row: row["time"])
    selected_version = reports[-1]["riskConfigVersion"] if reports else None
    latest = {row["user"]: row for row in reports}
    comparable = [row for row in latest.values() if row["riskConfigVersion"] == selected_version]
    current_score = _average(comparable)
    violations = Counter()
    for row in comparable:
        violations.update(row["severityCounts"])
    most_at_risk = max(comparable, key=lambda row: row["score"], default=None)

    first_day = datetime.now(timezone.utc).date() - timedelta(days=6)
    history_views, config_labels = _history_views(reports, first_day)
    risk_history = []
    known = {}
    index = 0
    for offset in range(7):
        day = first_day + timedelta(days=offset)
        while index < len(reports) and reports[index]["time"].astimezone(timezone.utc).date() <= day:
            row = reports[index]
            known[row["user"]] = row
            index += 1
        daily_rows = [row for row in known.values() if row["riskConfigVersion"] == selected_version]
        risk_history.append({"day": day.isoformat(), "score": _average(daily_rows)})

    return {
        "stats": {
            "totalUsersScanned": len(latest),
            "avgRiskScore": current_score,
            "riskConfigVersion": selected_version,
            "comparableUsers": len(comparable),
            "criticalViolations": violations["Critical"],
            "systemHealth": _risk_status(current_score),
            "lastScan": reports[-1]["time"].isoformat() if reports else None,
            "mostAtRisk": (
                {"user": most_at_risk["user"], "score": most_at_risk["score"]} if most_at_risk else None
            ),
        },
        "riskHistory": risk_history,
        "riskHistoryViews": history_views,
        "violationsBySeverity": [
            {"name": severity, "value": violations[severity], "color": color}
            for severity, color in SEVERITY_COLORS.items()
        ],
        "recentActivity": [
            {"id": row["id"], "user": row["user"], "score": row["score"],
             "time": row["time"].isoformat(), "status": _risk_status(row["score"]),
             "riskConfigVersion": row["riskConfigVersion"],
             "riskConfigLabel": config_labels[row["riskConfigVersion"]]}
            for row in reversed(reports[-10:])
        ],
        "telemetry": {**telemetry, "archiveAvailable": archive_available},
    }
