"""Prepare scan buckets and permissions on the MinIO deployment selected by the admin alias."""

import json
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


def main():
    load_dotenv()
    loader = S3Loader()
    if not loader.scanner_secret_key:
        raise SystemExit("Set MINIO_SCANNER_SECRET_KEY in .env first.")
    for bucket in (loader.raw_bucket, loader.processed_bucket):
        subprocess.run(
            [loader.mc_command, "mb", "--ignore-existing", f"{loader.admin_alias}/{bucket}"],
            check=True, timeout=30,
        )
    try:
        loader._mc(("admin", "user", "info"), loader.admin_alias, loader.scanner_access_key)
    except IdentityNotFound:
        loader.create_identity(loader.scanner_access_key, loader.scanner_secret_key)

    with TemporaryDirectory(prefix="s3cure-policy-") as temp:
        policy_file = Path(temp) / "scanner.json"
        policy_file.write_text(json.dumps(scanner_policy(loader.raw_bucket, loader.processed_bucket)),
                               encoding="utf-8")
        loader._mc(("admin", "policy", "create"), loader.admin_alias, "s3cure-scanner", str(policy_file))
    loader._mc(
        ("admin", "policy", "attach"), loader.admin_alias, "s3cure-scanner",
        options=(f"--user={loader.scanner_access_key}",),
    )
    # Check the configured scanner credentials without printing them.
    loader.get_all_users()
    print(f"Scan buckets configured: {loader.raw_bucket}, {loader.processed_bucket}")


if __name__ == "__main__":
    main()
