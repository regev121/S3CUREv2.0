from datetime import datetime, timezone
from io import BytesIO
import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from backend.core.graphLoader.s3Loader import IdentityConflict, IdentityNotFound, MinioError, S3Loader
from backend.provision_minio import scanner_policy


class ObjectStore:
    def __init__(self):
        self.objects = {}
        self.failed_bucket = None

    def put_object(self, Bucket, Key, Body, ContentType):
        if Bucket == self.failed_bucket:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutObject")
        self.objects[Bucket, Key] = Body, ContentType, datetime.now(timezone.utc)

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": BytesIO(self.objects[Bucket, Key][0])}

    def get_paginator(self, operation):
        assert operation == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        yield {"Contents": [
            {"Key": key, "LastModified": row[2]}
            for (bucket, key), row in self.objects.items()
            if bucket == Bucket and key.startswith(Prefix)
        ]}


def test_scans_simulation_roles_and_telemetry(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'app.db').as_posix()}")
    monkeypatch.setenv("SECRET_KEY", "unit-test-placeholder-key-for-authentication")
    monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("MINIO_SCANNER_ACCESS_KEY", "scanner")
    monkeypatch.setenv("RAW_SCAN_BUCKET", "test-raw")
    monkeypatch.setenv("PROCCESSED_SCAN_BUCKET", "test-processed")
    monkeypatch.delenv("LEGACY_SCAN_BUCKET", raising=False)

    from backend.api.database.connection import SessionLocal, init_db
    from backend.api.database.models import User
    from backend.api.deps import get_loader
    from backend.core.authentication.security import create_access_token, get_password_hash
    from backend.core import dashboard
    from backend.main import app

    loader = S3Loader()
    loader.s3 = ObjectStore()
    app.dependency_overrides[get_loader] = lambda: loader
    monkeypatch.setattr(dashboard, "urlopen", lambda *args, **kwargs:
                        MagicMock(**{"__enter__.return_value.status": 200}))
    calls = []
    users = {
        "Alice": {"policyName": "prod-read", "memberOf": ["Ops", "QA"]},
        "Admin": {"policyName": "diagnostics", "memberOf": ["Owners"]},
        "Auditor": {"policyName": "diagnostics", "memberOf": []},
        "Empty": {"memberOf": []},
        "scanner": {"policyName": "s3cure-scanner", "memberOf": []},
    }
    groups = {"Ops": "prod-read", "QA": "prod-read", "Owners": "consoleAdmin"}
    policy = {"Statement": [{
        "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::prod-bucket",
    }]}

    def fake_mc(command, alias, *args, options=()):
        calls.append((command, alias))
        if command == ("admin", "user", "list"):
            return [{"accessKey": name} for name in users]
        if command == ("admin", "user", "info"):
            if args[0] not in users:
                raise IdentityNotFound("MinIO identity does not exist.")
            return [users[args[0]]]
        if command == ("admin", "group", "info"):
            return [{"groupStatus": "enabled", "groupPolicy": groups[args[0]]}]
        if command == ("admin", "policy", "info"):
            return [{"policy": json.dumps(policy)}]
        if command == ("admin", "policy", "list"):
            return [{"policy": "prod-read"}]
        if command == ("admin", "group", "list"):
            return [{"groups": list(groups)}]
        if command == ("admin", "user", "add"):
            username, password = args
            assert alias == loader.admin_alias and password.startswith("s3c-")
            if username == "FailedSignup":
                raise MinioError("IAM service unavailable")
            assert username not in users
            users[username] = {"memberOf": []}
            return [{"status": "success"}]
        if command == ("admin", "policy", "attach"):
            assert alias == loader.admin_alias and args == ("prod-read",) and options == ("--user=Empty",)
            return [{"status": "success"}]
        if command == ("admin", "info"):
            return [{"info": {"servers": [{
                "uptime": 120, "drives": [{"state": "ok", "totalspace": 200, "availspace": 80}],
            }]}}]
        raise AssertionError(f"Unexpected MinIO command: {command}")

    monkeypatch.setattr(loader, "_mc", fake_mc)
    init_db()
    login_password = "app-password-for-test"
    password_hash = get_password_hash(login_password)
    with SessionLocal() as db:
        db.add_all(User(username=name, hashed_password=password_hash) for name in [*users, "Scanner"])
        db.commit()

    try:
        with TestClient(app) as client:
            def login(name):
                response = client.post("/api/auth/login", data={"username": name, "password": login_password})
                assert response.status_code == 200, response.text
                return {"Authorization": f"Bearer {response.json()['access_token']}"}

            alice = login("Alice")
            auditor = login("Auditor")
            admin = login("Admin")
            assert client.get("/api/auth/me", headers=admin).json()["role"] == "ADMIN"
            original_admin = users["Admin"]
            users["Admin"] = {"policyName": "policy_admin", "memberOf": []}
            assert client.get("/api/auth/me", headers=admin).json()["role"] == "ADMIN"
            assert client.get("/api/scan/config/risks", headers=admin).status_code == 200
            users["Admin"] = original_admin
            assert client.get("/api/auth/me", headers=auditor).json()["role"] == "AUDITOR"
            for name in ("scanner", "Scanner"):
                credentials = {"username": name, "password": login_password}
                assert client.post("/api/auth/login", data=credentials).status_code == 401
                stale_token = create_access_token({"sub": name})
                assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale_token}"}).status_code == 401
            assert client.get("/api/scan/users").status_code == 401
            assert client.get("/api/scan/users", headers=alice).status_code == 403
            assert client.post("/api/scan/user/Empty", headers=alice).status_code == 403
            assert client.get("/api/scan/history/Empty", headers=alice).status_code == 403
            assert client.get("/api/scan/dashboard/stats", headers=alice).status_code == 403
            assert client.post("/api/scan/user/scanner", headers=admin).status_code == 403
            assert client.post("/api/scan/simulate", headers=auditor, json={"username": "Alice"}).status_code == 403
            assert client.get("/api/scan/config/risks", headers=auditor).status_code == 403
            assert client.get("/api/scan/iam/options", headers=auditor).status_code == 403
            rules = client.get("/api/scan/config/risks", headers=admin).json()["risk_rules"]
            assert [rule["severity"] for rule in rules] == [9, 10, 7, 8, 5, 5, 1, 10]
            catalog = client.get("/api/scan/iam/options", headers=admin).json()
            assert catalog["users"] == ["Admin", "Alice", "Auditor", "Empty"]
            assert catalog["policies"] == ["prod-read"]
            assert client.post("/api/scan/policy/attach", headers=auditor,
                               json={"username": "Alice", "policy_name": "prod-read"}).status_code == 403

            scan = client.post("/api/scan/user/Alice", headers=alice)
            assert scan.status_code == 200, scan.text
            data = scan.json()
            assert data["violation_details"][0]["evidence"] == [{
                "policy": "prod-read",
                "resource": "prod-bucket",
                "action": "s3:GetObject",
                "direct": True,
                "groups": ["Ops", "QA"],
                "conditional": False,
            }]
            assert data["score"] > 0
            assert {node["type"] for node in data["graph_data"]["nodes"]} == {"USER", "POLICY", "RESOURCE"}
            assert len(data["graph_data"]["edges"]) == 2
            assert len(loader.s3.objects) == 2
            (raw_bucket, raw), (processed_bucket, js) = list(loader.s3.objects)
            assert (raw_bucket, processed_bucket) == ("test-raw", "test-processed")
            assert raw.endswith("/Alice_Scan_Raw.json")
            assert js == raw.removesuffix("_Raw.json") + "_Processed.js"
            report = json.loads(loader.s3.objects[raw_bucket, raw][0])
            exported_js = loader.s3.objects[processed_bucket, js][0].decode()
            assert report["graph_data"] == data["graph_data"]
            assert json.loads(exported_js.removeprefix("const graphData = ").removesuffix(";\n")) == data["graph_data"]

            options = client.get("/api/scan/simulate/options/Alice", headers=admin).json()
            assert options["direct_policies"] == ["prod-read"]
            assert options["member_groups"] == ["Ops", "QA"]
            partial = client.post("/api/scan/simulate", headers=admin, json={
                "username": "Alice", "remove_policies": ["prod-read"], "remove_groups": ["Ops"],
            }).json()
            assert partial["comparison"]["delta"] == 0
            simulated_grant = partial["violation_details"][0]["evidence"][0]
            assert not simulated_grant["direct"]
            assert simulated_grant["groups"] == ["QA"]
            full = client.post("/api/scan/simulate", headers=admin, json={
                "username": "Alice", "remove_policies": ["prod-read"], "remove_groups": ["Ops", "QA"],
            }).json()
            assert full["comparison"]["simulated_score"] == 0
            assert full["comparison"]["current_score"] == data["score"]
            assert len(loader.s3.objects) == 2
            assert all(alias == loader.scanner_alias for cmd, alias in calls if cmd in (
                ("admin", "user", "info"), ("admin", "group", "info"), ("admin", "policy", "info"),
            ))

            dashboard_data = client.get("/api/scan/dashboard/stats", headers=auditor).json()
            assert dashboard_data["stats"]["lastScan"]
            assert dashboard_data["stats"]["mostAtRisk"]["user"] == "Alice"
            assert dashboard_data["telemetry"]["availableBytes"] == 80
            assert dashboard_data["telemetry"]["uptimeSeconds"] == 120
            assert dashboard_data["riskHistory"][-1]["score"] == data["score"]
            assert dashboard_data["violationsBySeverity"][0]["value"] == 1

            empty = client.post("/api/scan/user/Empty", headers=auditor).json()
            assert empty["score"] == 0 and len(empty["graph_data"]["nodes"]) == 1
            assert len(loader.s3.objects) == 4
            loader.s3.failed_bucket = loader.processed_bucket
            failed = client.post("/api/scan/user/Alice", headers=alice)
            assert failed.status_code == 503
            history = client.get("/api/scan/history/Alice", headers=alice).json()
            assert history["history_count"] == 1
            assert client.post("/api/scan/policy/attach", headers=admin,
                               json={"username": "Empty", "policy_name": "prod-read"}).status_code == 200

            users["MinioOnly"] = {"policyName": "consoleAdmin", "memberOf": []}
            new_account = {"username": "FreshUser", "password": login_password}
            assert client.post("/api/auth/register", json=new_account).status_code == 200
            assert "FreshUser" in users
            assert client.get("/api/auth/me", headers=login("FreshUser")).json()["role"] == "USER"
            assert client.post("/api/auth/register", json={**new_account, "username": "freshuser"}).status_code == 409
            assert client.post("/api/auth/register", json={**new_account, "username": "MinioOnly"}).status_code == 409
            assert client.post("/api/auth/register", json={**new_account, "username": "FailedSignup"}).status_code == 503
            assert not loader.provision_app_identity("FreshUser", link_existing=True)
            with pytest.raises(IdentityConflict):
                loader.provision_app_identity("Scanner", link_existing=True)
            with SessionLocal() as db:
                assert db.query(User).filter(User.username == "FreshUser").count() == 1
                for name in ("FailedSignup", "MinioOnly", "freshuser"):
                    assert db.query(User).filter(User.username == name).count() == 0

    finally:
        app.dependency_overrides.clear()


def test_scanner_policy_limits_writes_to_its_buckets():
    statements = scanner_policy("raw-scan", "processed-scan")["Statement"]
    actions = {action for statement in statements for action in statement["Action"]}
    assert actions & {"admin:CreateUser", "admin:CreatePolicy", "s3:CreateBucket", "s3:DeleteObject"} == set()
    writes = next(statement for statement in statements if "s3:PutObject" in statement["Action"])
    assert {resource.split(":")[-1].split("/")[0] for resource in writes["Resource"]} == {
        "raw-scan", "processed-scan",
    }
