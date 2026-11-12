"""Run a repeatable scan and policy simulation using synthetic assignments."""

import json

from backend.core.graphLoader.riskEngine import RiskEngine
from backend.core.graphLoader.s3Loader import S3Loader


class DemoLoader(S3Loader):
    """Supply a local policy snapshot and capture scan results in memory."""

    def __init__(self):
        self.reports = []

    def get_risk_config(self):
        return None

    def get_user_assignments(self, username):
        assert username == "demo-analyst"
        return set(), {"prod-editors": self.get_group_policies_names("prod-editors")}

    def get_group_policies_names(self, group):
        return {
            "prod-editors": {"production-read", "production-delete"},
            "prod-readers": {"production-read"},
        }[group]

    def get_policy(self, name):
        return {"Statement": [{
            "Effect": "Allow",
            "Action": {
                "production-read": "s3:GetObject",
                "production-delete": "s3:DeleteObject",
            }[name],
            "Resource": "arn:aws:s3:::prod-bucket/*",
        }]}

    def archive_scan_result(self, username, report, graph):
        self.reports.append({**report, "graph_data": graph})


def run_demo():
    loader = DemoLoader()
    engine = RiskEngine(loader)
    username = "demo-analyst"
    engine.analyze_user_return_data(username)
    before, after, findings = engine.compare_simulation(
        username, remove_groups=["prod-editors"], add_groups=["prod-readers"],
    )
    return {
        "archived_scan": loader.reports[0],
        "simulation": {
            "removed_group": "prod-editors",
            "added_group": "prod-readers",
            "before": before,
            "after": after,
            "delta": round(after - before, 2),
            "findings": findings,
            "effective_groups_after_simulation": sorted(loader.get_user_assignments(username)[1]),
            "archived_scans": len(loader.reports),
        },
    }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
