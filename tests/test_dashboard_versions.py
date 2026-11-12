from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from backend.core import dashboard


def test_dashboard_compares_only_users_scanned_with_the_latest_configuration(monkeypatch):
    monkeypatch.setattr(dashboard, "_availability", lambda loader, db: {})
    monkeypatch.setattr(dashboard, "indexed_records", lambda db: None)
    now = datetime.now(timezone.utc).replace(hour=12, minute=0, second=0, microsecond=0)
    loader = Mock()
    loader.iter_reports.return_value = [
        ("legacy", {"user": "Legacy", "risk_score": 100}, now - timedelta(days=3)),
        ("other-version", {
            "user": "Other", "risk_score": 90, "risk_config_version": "old",
        }, now - timedelta(days=2)),
        ("early-current", {
            "user": "New", "risk_score": 30, "risk_config_version": "current",
            "risk_config_created_at": (now - timedelta(days=3)).isoformat(),
        }, now - timedelta(days=1)),
        ("latest", {
            "user": "New", "risk_score": 20, "risk_config_version": "current",
        }, now),
    ]

    data = dashboard.build_dashboard(loader, Mock())

    assert data["stats"]["riskConfigVersion"] == "current"
    assert data["stats"]["totalUsersScanned"] == 3
    assert data["stats"]["comparableUsers"] == 1
    assert data["stats"]["avgRiskScore"] == 20
    assert data["stats"]["mostAtRisk"] == {"user": "New", "score": 20}
    assert [day["score"] for day in data["riskHistory"][-3:]] == [None, 30, 20]
    assert [row["riskConfigVersion"] for row in data["recentActivity"]] == [
        "current", "current", "old", None,
    ]
    general, current, old, legacy = data["riskHistoryViews"]
    assert [day["score"] for day in general["history"]] == [None, None, None, 100, 90, 30, 20]
    assert current["label"] == f"CONFIG_Creation_Date:{now - timedelta(days=3):%d/%m/%Y}"
    assert not current["dateEstimated"]
    assert [day["score"] for day in current["history"]] == [30, 20]
    assert old["dateEstimated"]
    assert legacy["label"] == "Legacy scans"
