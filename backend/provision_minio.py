"""Prepare scan buckets and permissions on the MinIO deployment selected by the admin alias."""

import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from dotenv import load_dotenv

from backend.core.graphLoader.s3Loader import IdentityNotFound, LEGACY_RISK_CONFIG_KEY, RISK_CONFIG_KEY, S3Loader


def scanner_policy(raw_bucket, processed_bucket):
    raw = f"arn:aws:s3:::{raw_bucket}"
    processed = f"arn:aws:s3:::{processed_bucket}"
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": [
            "admin:GetUser", "admin:ListUsers", "admin:GetGroup", "admin:GetPolicy",
        ], "Resource": ["*"]},
        {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets", "s3:GetBucketPolicy"],
         "Resource": ["arn:aws:s3:::*"]},
        {"Effect": "Allow", "Action": ["s3:GetBucketLocation"], "Resource": [raw, processed]},
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [processed]},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": [
            f"{raw}/scans/*", f"{processed}/scans/*",
            f"{processed}/{LEGACY_RISK_CONFIG_KEY}", f"{processed}/{RISK_CONFIG_KEY}",
        ]},
    ]}


def manager_policy():
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": [
            "admin:CreateUser", "admin:ListGroups", "admin:ListUserPolicies",
            "admin:UpdatePolicyAssociation", "admin:AddUserToGroup", "admin:RemoveUserFromGroup",
            "admin:ServerInfo", "admin:StorageInfo",
        ],
        "Resource": ["*"],
    }]}


def main():
    load_dotenv()
    if os.getenv("MINIO_OPERATOR_CONFIG_DIR"):
        os.environ["MC_CONFIG_DIR"] = os.environ["MINIO_OPERATOR_CONFIG_DIR"]
    loader = S3Loader()
    if not loader.scanner_secret_key:
        raise SystemExit("Set MINIO_SCANNER_SECRET_KEY in .env first.")
    if not loader.manager_access_key or not loader.manager_secret_key:
        raise SystemExit("Set MINIO_MANAGER_ACCESS_KEY and MINIO_MANAGER_SECRET_KEY in .env first.")
    if (loader.is_scanner_name(loader.manager_access_key)
            or loader.manager_access_key.casefold() in {loader.root_access_key.casefold(), "minioadmin"}):
        raise SystemExit("Use a dedicated name for the IAM manager.")
    for bucket in (loader.raw_bucket, loader.processed_bucket):
        subprocess.run(
            [loader.mc_command, "mb", "--ignore-existing", f"{loader.admin_alias}/{bucket}"],
            check=True, timeout=30,
        )
    services = (
        (loader.scanner_access_key, loader.scanner_secret_key, "s3cure-scanner",
         scanner_policy(loader.raw_bucket, loader.processed_bucket)),
        (loader.manager_access_key, loader.manager_secret_key, "s3cure-iam-manager", manager_policy()),
    )
    with TemporaryDirectory(prefix="s3cure-policy-") as temp:
        for username, secret, name, document in services:
            try:
                loader._mc(("admin", "user", "info"), loader.admin_alias, username)
            except IdentityNotFound:
                loader.create_identity(username, secret, operator=True)
            policy_file = Path(temp) / (name + ".json")
            policy_file.write_text(json.dumps(document), encoding="utf-8")
            loader._mc(("admin", "policy", "create"), loader.admin_alias, name, str(policy_file))
            loader._mc(("admin", "policy", "attach"), loader.admin_alias, name, options=(f"--user={username}",))
    loader.get_all_users()
    loader.list_catalog()
    loader.storage_info()
    print(f"Scan buckets configured: {loader.raw_bucket}, {loader.processed_bucket}")


if __name__ == "__main__":
    main()
