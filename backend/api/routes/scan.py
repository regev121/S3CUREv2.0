from datetime import datetime, timezone
from functools import partial

from botocore.exceptions import ClientError
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.api.database.connection import get_db
from backend.api.deps import get_current_user, get_loader, get_requester_role
from backend.api.dto.group import GroupMembershipRequest
from backend.api.dto.policyAttachment import PolicyAttachmentRequest
from backend.api.dto.risk import RiskRule, RiskRulesUpdate
from backend.api.dto.simulation import SimulationRequest
from backend.core.dashboard import build_dashboard
from backend.core.bulk_scans import get_job, job_data, queue_scan, run_bulk_scan
from backend.core.graphLoader.riskEngine import RiskEngine, risk_rule_catalog
from backend.core.scan_index import record_scan, scan_history

router = APIRouter()
REVIEW_ROLES = ("ADMIN", "AUDITOR")


def _require_role(role, allowed):
    if role not in allowed:
        raise HTTPException(status_code=403, detail="You do not have access to this operation.")


def _require_target(loader, requester, role, target):
    if loader.is_scanner_name(target) or (role == "USER" and requester.username != target):
        raise HTTPException(status_code=403, detail="You cannot access scans for this identity.")


@router.get("/users")
def get_all_users(role=Depends(get_requester_role), loader=Depends(get_loader)):
    _require_role(role, REVIEW_ROLES)
    return {"users": loader.get_all_users()}


@router.post("/user/{username}")
def scan_user(username, requester=Depends(get_current_user), role=Depends(get_requester_role),
              loader=Depends(get_loader), db: Session = Depends(get_db)):
    _require_target(loader, requester, role, username)
    engine = RiskEngine(loader)
    score, violations, graph = engine.analyze_user_return_data(username, on_archived=partial(record_scan, db))
    return {
        "message": "Scan complete",
        "user": username,
        "score": score,
        "risk_config_version": engine.config_version,
        "risk_config_label": engine.config_label,
        "bucket_policy_coverage": engine.bucket_policy_snapshot[1],
        "violations_count": len(violations),
        "violations": [v["rule"] for v in violations],
        "violation_details": violations,
        "graph_data": graph,
    }


@router.get("/history/{username}")
def get_user_history(username, requester=Depends(get_current_user), role=Depends(get_requester_role),
                     loader=Depends(get_loader), db: Session = Depends(get_db),
                     limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    _require_target(loader, requester, role, username)
    count, reports = scan_history(loader, db, username, limit, offset)
    return {"user": username, "history_count": count, "reports": reports}


def _start_bulk_scan(tasks, db, loader):
    job, created = queue_scan(db)
    if created:
        tasks.add_task(run_bulk_scan, job["job_id"], loader)
    return job


@router.post("/initialize", status_code=202)
def initialize_scans(tasks: BackgroundTasks, role=Depends(get_requester_role),
                     loader=Depends(get_loader), db: Session = Depends(get_db)):
    _require_role(role, ("ADMIN",))
    return _start_bulk_scan(tasks, db, loader)


@router.post("/all", status_code=202)
def run_global_scan(tasks: BackgroundTasks, role=Depends(get_requester_role),
                    loader=Depends(get_loader), db: Session = Depends(get_db)):
    _require_role(role, REVIEW_ROLES)
    return _start_bulk_scan(tasks, db, loader)


@router.get("/jobs/{job_id}")
def bulk_scan_status(job_id: str, role=Depends(get_requester_role), db: Session = Depends(get_db)):
    _require_role(role, REVIEW_ROLES)
    job = get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    return job_data(job)


@router.get("/simulate/options/{username}")
def simulation_options(username, role=Depends(get_requester_role), loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    if loader.is_scanner_name(username):
        raise HTTPException(status_code=403, detail="The scanner is a service account.")
    return loader.list_simulation_options(username)


@router.post("/simulate")
def run_simulation(request: SimulationRequest, role=Depends(get_requester_role),
                   loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    if loader.is_scanner_name(request.username):
        raise HTTPException(status_code=403, detail="The scanner is a service account.")
    engine = RiskEngine(loader)
    current, simulated, violations = engine.compare_simulation(
        request.username, request.add_policies, request.remove_policies,
        request.add_groups, request.remove_groups,
        context=request.context.policy_values() if request.context else None,
        partial=request.context.partial if request.context else True,
    )
    delta = round(simulated - current, 2)
    return {
        "user": request.username,
        "risk_config_version": engine.config_version,
        "risk_config_label": engine.config_label,
        "bucket_policy_coverage": engine.bucket_policy_snapshot[1],
        "comparison": {
            "current_score": current,
            "simulated_score": simulated,
            "delta": delta,
            "is_improvement": delta < 0,
            "status": "Risk Increased" if delta > 0 else "Risk Decreased" if delta < 0 else "Stable",
        },
        "simulated_violations": [v["rule"] for v in violations],
        "violation_details": violations,
    }


@router.get("/config/risks")
def get_risk_configuration(role=Depends(get_requester_role), loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    rules, revision = loader.get_risk_config_snapshot()
    engine = RiskEngine(loader, rules=rules)
    return {**engine.risk_rules, "label": engine.config_label, "revision": revision}


@router.get("/config/risk-catalog")
def get_risk_rule_catalog(role=Depends(get_requester_role)):
    _require_role(role, ("ADMIN",))
    return {"rules": risk_rule_catalog()}


@router.get("/config/policies")
def list_risk_policy_sources(role=Depends(get_requester_role), loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    return {"policies": loader.list_policy_names()}


@router.get("/config/policies/{name}")
def read_risk_policy_source(name: str, role=Depends(get_requester_role), loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    if name not in loader.list_policy_names():
        raise HTTPException(status_code=404, detail="MinIO policy not found.")
    return {"policy": loader.get_policy(name)}


@router.post("/config/risks/validate")
def validate_risk_rule(rule: RiskRule, role=Depends(get_requester_role)):
    _require_role(role, ("ADMIN",))
    return rule.model_dump(exclude_none=True)


@router.post("/config/risks")
def update_risk_configuration(update: RiskRulesUpdate, role=Depends(get_requester_role),
                              loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    previous_rules, revision = loader.get_risk_config_snapshot()
    conflict = HTTPException(status_code=409, detail="Configuration changed. Reload before saving your changes.")
    if "base_revision" in update.model_fields_set and update.base_revision != revision:
        raise conflict
    previous = RiskEngine(loader, rules=previous_rules)
    new_rules = update.model_dump(include={"risk_rules"}, exclude_none=True)
    updated = RiskEngine(loader, rules=new_rules)
    created_at = previous.config_created_at if previous.config_version == updated.config_version else None
    updated.config_created_at = created_at or datetime.now(timezone.utc).isoformat()
    try:
        revision = loader.save_risk_config({**new_rules, "created_at": updated.config_created_at}, revision)
    except ClientError as error:
        if error.response["Error"]["Code"] in ("PreconditionFailed", "ConditionalRequestConflict", "412"):
            raise conflict from error
        raise
    return {"message": "Configuration updated successfully", "rules_count": len(update.risk_rules),
            "label": updated.config_label, "revision": revision}


@router.get("/iam/options")
def iam_options(role=Depends(get_requester_role), loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    return {"users": loader.get_all_users(), **loader.list_catalog()}


@router.post("/policy/attach")
def attach_policy(request: PolicyAttachmentRequest, role=Depends(get_requester_role),
                  loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    loader.change_policy("attach", request.username, request.policy_name)
    return {"message": "Policy attached"}


@router.post("/policy/detach")
def detach_policy(request: PolicyAttachmentRequest, role=Depends(get_requester_role),
                  loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    loader.change_policy("detach", request.username, request.policy_name)
    return {"message": "Policy detached"}


@router.post("/group/add-member")
def add_group_member(request: GroupMembershipRequest, role=Depends(get_requester_role),
                     loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    loader.change_group("add", request.username, request.group_name)
    return {"message": "Group membership added"}


@router.post("/group/remove-member")
def remove_group_member(request: GroupMembershipRequest, role=Depends(get_requester_role),
                        loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    loader.change_group("remove", request.username, request.group_name)
    return {"message": "Group membership removed"}


@router.get("/dashboard/stats")
def get_dashboard_stats(role=Depends(get_requester_role), loader=Depends(get_loader),
                        db: Session = Depends(get_db)):
    _require_role(role, REVIEW_ROLES)
    return build_dashboard(loader, db)
