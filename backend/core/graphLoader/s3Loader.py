import json
import os
import secrets
import subprocess
from datetime import datetime, timezone
from functools import cached_property
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


class MinioError(RuntimeError):
    pass


class IdentityNotFound(MinioError):
    pass


class IdentityConflict(MinioError):
    pass


RISK_CONFIG_KEY = "config/risks-v2.json"
LEGACY_RISK_CONFIG_KEY = "config/risks.json"


def _names(value):
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return set()
    return {name.strip() for name in value if isinstance(name, str) and name.strip()}


def _policy_names(info):
    return (
        _names(info.get("policyName"))
        | _names(info.get("userPolicy"))
        | _names(info.get("groupPolicy"))
        | _names(info.get("policies"))
    )


def policy_origins(direct, groups):
    origins = {policy: {"direct": True, "groups": []} for policy in direct}
    for group, policies in sorted(groups.items()):
        for policy in policies:
            origins.setdefault(policy, {"direct": False, "groups": []})["groups"].append(group)
    return origins


class S3Loader:
    """Use the scanner identity for reads and archival, and a separate alias for IAM changes."""

    def __init__(self):
        self.endpoint = os.getenv("MINIO_ENDPOINT", "http://127.0.0.1:9000").rstrip("/")
        self.scanner_access_key = os.getenv("MINIO_SCANNER_ACCESS_KEY", "scanner")
        self.scanner_secret_key = os.getenv("MINIO_SCANNER_SECRET_KEY")
        self.admin_alias = os.getenv("MINIO_ADMIN_ALIAS", "myminio")
        self.manager_alias = "s3curemanager"
        self.manager_access_key = os.getenv("MINIO_MANAGER_ACCESS_KEY")
        self.manager_secret_key = os.getenv("MINIO_MANAGER_SECRET_KEY")
        self.telemetry_alias = os.getenv("MINIO_TELEMETRY_ALIAS", self.manager_alias)
        self.root_access_key = os.getenv("MINIO_ROOT_ACCESS_KEY", "minioadmin")
        self.raw_bucket = os.getenv("RAW_SCAN_BUCKET", "raw-scan")
        self.processed_bucket = os.getenv("PROCCESSED_SCAN_BUCKET", "processed-scan")
        self.legacy_bucket = os.getenv("LEGACY_SCAN_BUCKET")
        self.scanner_alias = "s3curescanner"
        self.mc_command = os.getenv("MINIO_MC_COMMAND", "mc")
        if self.raw_bucket == self.processed_bucket:
            raise MinioError("Raw and processed scan buckets must be distinct.")
        if self.admin_alias in (self.scanner_alias, self.manager_alias):
            raise MinioError("The scanner and manager aliases are reserved.")

    @cached_property
    def s3(self):
        self._require_scanner()
        return boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.scanner_access_key,
            aws_secret_access_key=self.scanner_secret_key,
            region_name="us-east-1",
            config=Config(
                connect_timeout=3,
                read_timeout=8,
                retries={"total_max_attempts": 2},
                s3={"addressing_style": "path"},
            ),
        )

    def _require_scanner(self):
        if not self.scanner_secret_key:
            raise MinioError("MINIO_SCANNER_SECRET_KEY is required.")

    def _mc(self, command, alias, *args, options=(), stdin=None):
        env = os.environ.copy()
        for setting in (
            "DATABASE_URL", "DATABASE_SETUP_URL", "ENCRYPTION_KEY", "SECRET_KEY",
            "MINIO_SCANNER_SECRET_KEY", "MINIO_MANAGER_SECRET_KEY",
            "MINIO_ROOT_PASSWORD", "MINIO_ROOT_PASSWORD_FILE", "MINIO_OPERATOR_CONFIG_DIR",
        ):
            env.pop(setting, None)
        if alias in (self.scanner_alias, self.manager_alias):
            access_key, secret_key = (
                (self.scanner_access_key, self.scanner_secret_key) if alias == self.scanner_alias
                else (self.manager_access_key, self.manager_secret_key)
            )
            if not access_key or not secret_key:
                raise MinioError("MinIO service credentials are required.")
            endpoint = urlsplit(self.endpoint)
            credentials = f"{quote(access_key, safe='')}:{quote(secret_key, safe='')}"
            env[f"MC_HOST_{alias}"] = urlunsplit(
                (endpoint.scheme, f"{credentials}@{endpoint.netloc}", "", "", "")
            )
        if any(arg.startswith("-") for arg in args):
            raise MinioError("Invalid MinIO name.")
        try:
            result = subprocess.run(
                [self.mc_command, "--json", "--no-color", *command, *options, alias, *args],
                capture_output=True,
                input=stdin,
                encoding="utf-8",
                env=env,
                timeout=12,
            )
            records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            raise MinioError("The MinIO CLI request failed.") from error
        if result.returncode or any(row.get("status") == "error" for row in records):
            errors = (result.stdout + result.stderr).lower()
            if command == ("admin", "user", "info") and any(
                marker in errors for marker in ("nosuchuser", "specified user does not exist")
            ):
                raise IdentityNotFound("MinIO identity does not exist.")
            raise MinioError(f"MinIO rejected {' '.join(command)}.")
        return records

    def _read(self, command, *args):
        return self._mc(command, self.scanner_alias, *args)

    def get_user_info(self, username):
        rows = self._read(("admin", "user", "info"), username)
        if len(rows) != 1:
            raise MinioError("Unexpected response to MinIO user lookup.")
        return rows[0]

    def get_group_info(self, group):
        rows = self._read(("admin", "group", "info"), group)
        if len(rows) != 1:
            raise MinioError("Unexpected response to MinIO group lookup.")
        return rows[0]

    def get_group_policies_names(self, group):
        info = self.get_group_info(group)
        return _policy_names(info) if info.get("groupStatus", info.get("status")) not in (
            "disabled", "inactive", "off"
        ) else set()

    def get_user_assignments(self, username):
        info = self.get_user_info(username)
        if info.get("userStatus") in ("disabled", "inactive", "off"):
            return set(), {}
        groups = {}
        for membership in info.get("memberOf") or []:
            if isinstance(membership, str):
                groups[membership] = self.get_group_policies_names(membership)
            elif isinstance(membership, dict):
                name = membership.get("name") or membership.get("key")
                if name:
                    groups[name] = (
                        _policy_names(membership) if "policies" in membership
                        else self.get_group_policies_names(name)
                    )
        return _policy_names(info), groups

    def get_policy(self, name):
        rows = self._read(("admin", "policy", "info"), name)
        if len(rows) == 1:
            info = rows[0]
            nested = info.get("policyInfo") or {}
            policy = nested.get("Policy") or nested.get("policy") or info.get("policy") or info
            if isinstance(policy, str):
                try:
                    policy = json.loads(policy)
                except ValueError as error:
                    raise MinioError("Unexpected response to MinIO policy lookup.") from error
            if isinstance(policy, dict) and "Statement" in policy:
                return policy
        raise MinioError("Unexpected response to MinIO policy lookup.")

    def get_user_access_data(self, username):
        direct, groups = self.get_user_assignments(username)
        return [
            {"name": name, "content": self.get_policy(name), "origin": origin}
            for name, origin in sorted(policy_origins(direct, groups).items())
        ]

    def is_scanner_name(self, username):
        return username.casefold() in ("scanner", self.scanner_access_key.casefold())

    def is_service_identity(self, username):
        reserved = {value.casefold() for value in (self.manager_access_key, self.root_access_key, "minioadmin") if value}
        return self.is_scanner_name(username) or username.casefold() in reserved

    def get_all_users(self):
        rows = self._read(("admin", "user", "list"))
        return sorted(
            row["accessKey"] for row in rows
            if row.get("accessKey") and not self.is_service_identity(row["accessKey"])
        )

    def list_policy_names(self):
        policies = self._mc(("admin", "policy", "list"), self.manager_alias)
        return sorted({row["policy"] for row in policies if isinstance(row.get("policy"), str)})

    def list_catalog(self):
        # Only admin endpoints call this method. The scanner does not need catalog access.
        group_rows = self._mc(("admin", "group", "list"), self.manager_alias)
        return {
            "policies": self.list_policy_names(),
            "groups": sorted({
                group for row in group_rows
                for group in (row.get("groups") or [row.get("groupName") or row.get("group")])
                if isinstance(group, str)
            }),
        }

    def list_simulation_options(self, username):
        direct, groups = self.get_user_assignments(username)
        return {
            **self.list_catalog(),
            "direct_policies": sorted(direct),
            "member_groups": sorted(groups),
        }

    def change_policy(self, action, username, policy):
        if self.is_service_identity(username) or policy in {"s3cure-scanner", "s3cure-iam-manager"}:
            raise IdentityConflict("Service identities and their policies are managed by the operator.")
        # --user= prevents a username from being interpreted as another CLI option.
        if policy.startswith("-") or username.startswith("-"):
            raise MinioError("Invalid MinIO name.")
        self._mc(("admin", "policy", action), self.manager_alias, policy, options=(f"--user={username}",))

    def change_group(self, action, username, group):
        if self.is_service_identity(username):
            raise IdentityConflict("Service identities are managed by the operator.")
        self._mc(("admin", "group", action), self.manager_alias, group, username)

    def create_identity(self, username, secret, *, operator=False):
        if any(character in secret for character in "\r\n\0"):
            raise IdentityConflict("MinIO secrets must be a single line.")
        alias = self.admin_alias if operator else self.manager_alias
        self._mc(("admin", "user", "add"), alias, username, stdin=secret + "\n")

    def provision_app_identity(self, username, *, link_existing=False):
        if self.is_service_identity(username):
            raise IdentityConflict("This name is reserved for a service identity.")
        matching = [name for name in self.get_all_users() if name.casefold() == username.casefold()]
        if matching:
            if link_existing and matching == [username]:
                return False
            raise IdentityConflict("This MinIO identity already exists or differs only by letter case.")
        self.create_identity(username, "s3c-" + secrets.token_urlsafe(32))
        return True

    @staticmethod
    def _user_prefix(username):
        return f"scans/{quote(username, safe='')}/"

    def archive_scan_result(self, username, report, graph):
        now = datetime.now(timezone.utc)
        user_key = quote(username, safe="")
        prefix = f"{self._user_prefix(username)}{now:%H%M%S%f_%Y%m%d}_{uuid4().hex}/"
        raw_key = f"{prefix}{user_key}_Scan_Raw.json"
        processed_key = f"{prefix}{user_key}_Scan_Processed.js"
        raw = {**report, "scanned_at": now.isoformat(), "graph_data": graph}
        self.s3.put_object(
            Bucket=self.raw_bucket, Key=raw_key,
            Body=json.dumps(raw, ensure_ascii=False).encode("utf-8"),
            ContentType="application/json",
        )
        js = "const graphData = " + json.dumps(raw["graph_data"]).replace("<", "\\u003c") + ";\n"
        self.s3.put_object(
            Bucket=self.processed_bucket, Key=processed_key,
            Body=js.encode("utf-8"), ContentType="text/javascript",
        )
        return {"raw": raw_key, "processed": processed_key, "scanned_at": raw["scanned_at"]}

    def _list_objects(self, bucket, prefix):
        pages = self.s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for page in pages:
            yield from page.get("Contents", [])

    def _read_json(self, bucket, key):
        obj = self.s3.get_object(Bucket=bucket, Key=key)
        with obj["Body"] as body:
            return json.load(body)

    def iter_reports(self, username=None):
        prefix = self._user_prefix(username) if username is not None else "scans/"
        for obj in self._list_objects(self.processed_bucket, prefix):
            key = obj["Key"]
            if key.endswith("_Scan_Processed.js"):
                raw_key = key.removesuffix("_Scan_Processed.js") + "_Scan_Raw.json"
                yield raw_key, self._read_json(self.raw_bucket, raw_key), obj["LastModified"]
        if self.legacy_bucket:
            prefix = "reports/" if username is None else f"reports/{username}_"
            for obj in self._list_objects(self.legacy_bucket, prefix):
                if obj["Key"].endswith(".json"):
                    report = self._read_json(self.legacy_bucket, obj["Key"])
                    if username is None or report.get("user") == username:
                        yield obj["Key"], report, obj["LastModified"]

    def get_risk_config(self):
        return self.get_risk_config_snapshot()[0]

    def get_risk_config_snapshot(self):
        sources = dict.fromkeys((
            (self.processed_bucket, RISK_CONFIG_KEY),
            (self.processed_bucket, LEGACY_RISK_CONFIG_KEY),
            (self.legacy_bucket, LEGACY_RISK_CONFIG_KEY),
        ))
        for bucket, key in sources:
            if not bucket:
                continue
            try:
                obj = self.s3.get_object(Bucket=bucket, Key=key)
                with obj["Body"] as body:
                    return json.load(body), obj.get("ETag") if key == RISK_CONFIG_KEY else None
            except ClientError as error:
                if error.response["Error"]["Code"] not in ("NoSuchKey", "404"):
                    raise
        return None, None

    def get_bucket_policies(self):
        try:
            buckets = self.s3.list_buckets()["Buckets"]
        except (ClientError, BotoCoreError):
            return {}, "unavailable"
        policies = {}
        coverage = "complete"
        for bucket in buckets:
            name = bucket["Name"]
            try:
                policies[name] = json.loads(self.s3.get_bucket_policy(Bucket=name)["Policy"])
            except ClientError as error:
                if error.response["Error"]["Code"] not in ("NoSuchBucketPolicy", "NoSuchBucket"):
                    coverage = "partial"
            except (BotoCoreError, ValueError):
                coverage = "partial"
        return policies, coverage

    def save_risk_config(self, rules, revision=None):
        condition = {"IfMatch": revision} if revision else {"IfNoneMatch": "*"}
        result = self.s3.put_object(
            Bucket=self.processed_bucket, Key=RISK_CONFIG_KEY,
            Body=json.dumps(rules).encode("utf-8"), ContentType="application/json",
            **condition,
        )
        return result["ETag"]

    def storage_info(self):
        rows = self._mc(("admin", "info"), self.telemetry_alias)
        if len(rows) != 1:
            raise MinioError("Unexpected response to MinIO storage lookup.")
        return rows[0].get("info", rows[0])
