# S3CURE

S3CURE is a MinIO IAM risk analysis tool. It maps user policies to S3 resources, scores potential exposure, and lets administrators compare policy changes in a simulation. FastAPI serves a React UI, PostgreSQL stores application accounts, and MinIO holds IAM policies and scan artifacts.

## Local setup

Use Python 3.11 or newer, Node.js 22, the MinIO server and `mc`, and a PostgreSQL database. Run the commands below from this directory in PowerShell.

```powershell
python -m pip install -r requirements.txt
if (-not (Test-Path -LiteralPath '.env')) { Copy-Item .env.example .env }
python -c "import secrets; from cryptography.fernet import Fernet; print(secrets.token_urlsafe(48)); print(Fernet.generate_key().decode())"
```

For a new .env file, put the first generated value in `SECRET_KEY` and the second in `ENCRYPTION_KEY`. Set the scanner password before provisioning. Keep the keys stable across restarts. If you are reconnecting an existing database, use its original encryption key to retain access to encrypted account records.

For an existing S3CURE database, set DATABASE_URL in .env and start the API with the uvicorn command below. The API uses the existing schema. To enter the login interactively, the following optional command checks connectivity and table names in a read-only transaction before saving DATABASE_URL.

```powershell
python setupDb.py --configure-postgres
```

For a fresh local MinIO deployment, run this in a separate PowerShell window. Use the same data directory on subsequent starts and pass it as one quoted argument. Point `MINIO_ENDPOINT` at an existing deployment if you already have one.

```powershell
$dataDir = Join-Path $env:LOCALAPPDATA 'S3CURE\minio-data'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$licenseFile = Read-Host 'Full path to the MinIO license file'
minio.exe server --address '127.0.0.1:9000' --console-address '127.0.0.1:9001' --license "$licenseFile" "$dataDir"
```

Use a dedicated data directory outside OneDrive for the fresh instance. Keep the backup directories available for recovery. AIStor requires an active license for S3 object operations. [MinIO licensing](https://docs.min.io/aistor/operations/licenses/)

In another terminal, check the instance before provisioning.

```powershell
curl.exe -i http://127.0.0.1:9000/minio/health/cluster
```

Configure `MINIO_ADMIN_ALIAS` with `mc alias set` for that same deployment. Then prepare the buckets and the scanner account.

```powershell
python -m backend.provision_minio
```

The provisioner uses the admin alias to create the buckets and attach `s3cure-scanner`. The scanner policy allows IAM reads and object writes within the scan buckets. If you reuse an existing `scanner` identity, verify its existing policy and group assignments and use its current secret in `.env`.

The recovery inventory in minio-restore.json documents the sample buckets and IAM policy definitions. Configure assignments for the identities in your MinIO deployment.

Use a named MinIO account to enroll the first application administrator. Application roles live in PostgreSQL and are assigned with the operator command.

```powershell
python setupDb.py --app-user YourMinioUsername --role ADMIN
python setupDb.py --index-scans
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

For an existing database, assign application roles to the accounts that should retain access, then index the archive. The setup commands add any missing tables and reuse existing accounts. Set a role to `USER` to remove the elevated app assignment.

```powershell
python setupDb.py --set-role ExistingAdmin ADMIN
python setupDb.py --set-role ExistingAuditor AUDITOR
python setupDb.py --index-scans
```

In a second PowerShell terminal, start the frontend.

```powershell
Set-Location frontend
npm ci --legacy-peer-deps
npm run dev
```

Open the Vite address printed in the terminal. Set `VITE_API_BASE_URL` when the API uses a different address.

## Sync app users to MinIO

In IAM Manager, a signed-in administrator can create a S3CURE account and a MinIO identity with the same username. New accounts start with the application role `USER`. Run the sync command for accounts already in PostgreSQL. It reads the database and creates only missing MinIO identities. It preserves existing IAM passwords, policies and group memberships. The scanner uses its MinIO credentials directly. The app reserves the scanner name regardless of case and excludes historical scanner rows from login and account sync. Other names that differ only by case require review.

```powershell
python -m backend.sync_minio_users
```

## Scan behavior

- `ADMIN` can scan any user, run a simulation, manage IAM, and update risk rules.
- `AUDITOR` can scan users and open the telemetry dashboard.
- `USER` can scan their own profile.
- `scanner` is the internal MinIO identity used to read IAM and save scan objects.

The scanner flattens direct and inherited policies into a `User → Policy → Resource` graph and evaluates the recovered risk rules with the permission trie. Simulations compare one snapshot with hypothetical policy and group changes in memory.

`RAW_SCAN_BUCKET` stores the JSON report and `PROCCESSED_SCAN_BUCKET` stores the matching JS graph. Each scan has a timestamped UTC prefix, so repeated scans retain their history while keeping filenames such as `Alice_Scan_Raw.json` and `Alice_Scan_Processed.js`. Dashboard and history include completed pairs. If an older `reports/` archive exists, set `LEGACY_SCAN_BUCKET` and grant scanner read access to that prefix separately.

After indexing, the Dashboard and scan history read compact records from PostgreSQL. Run `python setupDb.py --index-scans` again after importing an external archive or to reconcile reports left by an interrupted write. User history accepts `limit` and `offset` and returns the total count. Bulk scans return HTTP 202 and a job ID. The Dashboard and Config poll the job endpoint for progress. Run one bulk scan at a time. A job with no recorded progress for 30 minutes is marked interrupted and can be started again.

Each new scan stores a SHA-256 fingerprint of the effective rules and scoring model. The dashboard defaults to a seven-day trend across configurations and averages the last scan for each user on each day with scans. The dropdown also shows the history for individual configurations and for legacy scans. Configuration labels use `CONFIG_Creation_Date:dd/mm/yyyy`. When creation metadata is missing, the dashboard labels the date as the first archived scan for that version. Current risk and severity metrics compare users under the latest scanned configuration. The dashboard also shows the last scan and live service telemetry. `MINIO_TELEMETRY_ALIAS` can be set to a read-only MinIO alias with `admin:ServerInfo` for disk capacity and uptime. By default it uses the configured admin alias.

## How the risk engine works

1. Resolve the user's direct policies and each group's policies. Take their set union and fetch each policy document once.
2. Build a directed graph with three layers. Traverse from the user through each policy to its resources, at a fixed depth of two.
3. Index each resource grant in a permission trie by the literal characters before its first wildcard. A search checks compatible prefixes and evaluates whether the grant and rule patterns can match a common string. The glob syntax supports '*' for zero or more characters and '?' for one character. A bare bucket selector in a risk rule covers that bucket and its objects. An exact bucket grant keeps its own scope.
4. Apply explicit Deny to the overlapping action and resource scope, including `NotAction` and `NotResource` exceptions. A deployment-wide rule requires coverage of the full action and resource scope. For other rules, access outside a denied scope can still trigger a finding.
5. Evaluate supported IAM conditions against the request context. The Simulator accepts a source IP, HTTP or HTTPS, and an S3 listing prefix. For a complete request, `IfExists` matches an absent key and `Null` tests key presence. During a scan, unknown request values and unsupported conditions are marked as unresolved. Findings retain the policy and resource pattern, plus direct or group provenance.
6. For R001, inspect the MinIO bucket policy for anonymous read or listing access within the bucket's scope. The scanner reads bucket names and policies using `s3:ListAllMyBuckets` and `s3:GetBucketPolicy`. Run `python -m backend.provision_minio` to update those scanner permissions on an existing deployment.
7. For a simulation, resolve the existing and proposed assignments separately, then evaluate both using the same identity and bucket policy snapshots. A grant shared by two groups survives the removal of either group by itself.

The score measures potential exposure relative to the configured rules, including findings with unresolved conditions. Each matching rule contributes its severity once. The score is 100 times the sum of matching severities divided by the total severity. The eight default rules sum to 55. Graph edges are stored in a list, so collecting edges for P policies costs O((P + 1)E) for E edges, plus trie construction and rule evaluation.

## Risk configuration

Use **Config** to edit active rules or add templates from the rule catalog. Templates cover IAM administration, access keys, availability, sensitive data, audit retention, and encryption. Each change stays in the draft until you save the configuration. Run **Scan all users** to score the latest permissions under the saved rules.

**Manual JSON** accepts a pasted IAM policy or a JSON file. **Import from MinIO** reads a named identity policy and copies its document into the editor. An Allow statement defines an action and resource combination to flag. In a mixed document, Deny statements exclude matching scope. A Deny-only document defines access to flag when the scanned identity still has it. Conditions use the same request context as scans and simulations. Saving a rule updates S3CURE's scoring configuration in MinIO.

## Recovery provenance

This repository contains the recovered application, rebuilt from the surviving S3CURE source, sample IAM policies and project documentation. The recovery commits document the work performed to restore the system.

## Reproducible demo

Run from the repository root with the Python dependencies installed.

```powershell
python -m backend.demo_risk
```

The synthetic analyst starts in prod-editors and can read and delete objects in a private production bucket. The simulated move to prod-readers keeps read access and drops the delete grant, changing the score from 18.18 to 0. The JSON output includes the policy graphs, the ruleset fingerprint, and the simulated delta. The demo runs entirely in memory with synthetic IAM data.

## Verification

```powershell
python -m pip install pytest httpx
python -m pytest tests -q
Set-Location frontend
npm run lint
npm run build
```

The API suite uses temporary SQLite and an in-memory MinIO stand-in. To also test against MinIO, configure a local endpoint and matching admin alias in `.env`, then run the opt-in test. It creates and removes its own buckets, policies, and users, and exercises Allow, Deny, and the scanner's archive permissions.

```powershell
$env:S3CURE_RUN_MINIO_TESTS = '1'
python -m pytest tests/test_minio_live.py -q
```
