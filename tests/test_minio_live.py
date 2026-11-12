import json
import os
import secrets
from contextlib import ExitStack
from subprocess import run
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.core.graphLoader.s3Loader import S3Loader
from backend.provision_minio import scanner_policy


@pytest.mark.skipif(os.getenv("S3CURE_RUN_MINIO_TESTS") != "1", reason="Requires an opted-in local MinIO deployment")
def test_real_minio_policy_scan_and_archive(monkeypatch, tmp_path):
    load_dotenv()
    loader = S3Loader()
    endpoint = urlsplit(loader.endpoint)
    assert endpoint.hostname in {"127.0.0.1", "::1", "localhost"}
    # Check the selected CLI alias before creating test resources.
    alias = loader._mc(("alias", "list"), loader.admin_alias)[0]
    assert alias["URL"].rstrip("/") == loader.endpoint

    name = "s3cure-test-" + uuid4().hex[:12]
    raw, processed, data = (name + suffix for suffix in ("-raw", "-processed", "-data"))
    scanner = name + "-scanner"
    secret = secrets.token_urlsafe(32)
    allow, deny, scan_policy = (name + suffix for suffix in ("-allow", "-deny", "-scan-policy"))

    def mc(command, *args):
        return loader._mc(command, loader.admin_alias, *args)

    def bucket_command(command, bucket):
        assert bucket in (raw, processed, data)
        result = run([loader.mc_command, *command, f"{loader.admin_alias}/{bucket}"],
                     capture_output=True, timeout=30)
        assert result.returncode == 0, f"MinIO rejected {command[0]} for the isolated test bucket."

    def create_policy(stack, policy_name, document):
        path = tmp_path / (policy_name + ".json")
        path.write_text(json.dumps(document), encoding="utf-8")
        mc(("admin", "policy", "create"), policy_name, str(path))
        stack.callback(mc, ("admin", "policy", "rm"), policy_name)

    with ExitStack() as cleanup:
        for bucket in (raw, processed, data):
            bucket_command(["mb"], bucket)
            cleanup.callback(bucket_command, ["rb", "--force"], bucket)
        create_policy(cleanup, scan_policy, scanner_policy(raw, processed))
        for policy_name, effect in ((allow, "Allow"), (deny, "Deny")):
            create_policy(cleanup, policy_name, {"Version": "2012-10-17", "Statement": [{
                "Effect": effect, "Action": ["s3:DeleteBucket"], "Resource": [f"arn:aws:s3:::{data}"],
            }]})
        for username, password in ((scanner, secret), (name, secrets.token_urlsafe(32))):
            loader.create_identity(username, password)
            cleanup.callback(mc, ("admin", "user", "remove"), username)
        for username, policy_name in ((scanner, scan_policy), (name, allow)):
            loader.change_policy("attach", username, policy_name)
        monkeypatch.setenv("MINIO_SCANNER_ACCESS_KEY", scanner)
        monkeypatch.setenv("MINIO_SCANNER_SECRET_KEY", secret)
        monkeypatch.setenv("RAW_SCAN_BUCKET", raw)
        monkeypatch.setenv("PROCCESSED_SCAN_BUCKET", processed)
        monkeypatch.delenv("LEGACY_SCAN_BUCKET", raising=False)
        scanner_loader = S3Loader()
        scanner_loader.save_risk_config({"risk_rules": [{
            "description": "Delete an isolated test bucket", "severity": 10,
            "resource_pattern": data, "risky_actions": ["s3:DeleteBucket"],
        }]})
        db_url = f"sqlite:///{(tmp_path / 'live-api.db').as_posix()}"
        monkeypatch.setenv("DATABASE_URL", db_url)
        monkeypatch.setenv("SECRET_KEY", secrets.token_urlsafe(48))
        monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
        from backend.api.database import connection
        from backend.api.database.models import User
        from backend.api.deps import get_loader
        from backend.core.authentication.security import get_password_hash
        from backend.core.scan_index import backfill_scan_index
        from backend.main import app

        db_engine = create_engine(db_url)
        cleanup.callback(db_engine.dispose)
        sessions = sessionmaker(bind=db_engine)
        monkeypatch.setattr(connection, "engine", db_engine)
        monkeypatch.setattr(connection, "SessionLocal", sessions)
        monkeypatch.setitem(app.dependency_overrides, get_loader, lambda: scanner_loader)
        connection.init_db()
        password = secrets.token_urlsafe(24)
        with sessions() as db:
            db.add(User(username=name, hashed_password=get_password_hash(password)))
            db.commit()
            assert backfill_scan_index(scanner_loader, db) == 0
        with TestClient(app) as client:
            login = client.post("/api/auth/login", data={"username": name, "password": password})
            assert login.status_code == 200
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            path = "/api/scan/user/" + name
            first = client.post(path, headers=headers)
            assert first.status_code == 200 and first.json()["score"] == 100
            loader.change_policy("attach", name, deny)
            second = client.post(path, headers=headers)
            assert second.status_code == 200 and second.json()["score"] == 0
            history = client.get("/api/scan/history/" + name, headers=headers)
            assert history.status_code == 200 and history.json()["history_count"] == 2
        reports = list(scanner_loader.iter_reports(name))
        assert sorted(report["risk_score"] for _, report, _ in reports) == [0, 100]
        for key, report, _ in reports:
            assert report["graph_data"]["nodes"]
            processed_key = key.removesuffix("_Scan_Raw.json") + "_Scan_Processed.js"
            with scanner_loader.s3.get_object(Bucket=processed, Key=processed_key)["Body"] as graph:
                assert graph.read().startswith(b"const graphData = ")
        with pytest.raises(ClientError) as forbidden:
            scanner_loader.s3.put_object(Bucket=data, Key="scanner-write-check", Body=b"isolated test")
        assert forbidden.value.response["Error"]["Code"] == "AccessDenied"
