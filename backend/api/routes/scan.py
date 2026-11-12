from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.api.database.connection import get_db
from backend.api.deps import get_current_user, get_loader, get_requester_role
from backend.api.dto.group import GroupMembershipRequest
from backend.api.dto.policyAttachment import PolicyAttachmentRequest
from backend.api.dto.risk import RiskRulesUpdate
from backend.api.dto.simulation import SimulationRequest
from backend.core.dashboard import build_dashboard
from backend.core.graphLoader.riskEngine import RiskEngine

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
              loader=Depends(get_loader)):
    _require_target(loader, requester, role, username)
    score, violations, graph = RiskEngine(loader).analyze_user_return_data(username)
    return {
        "message": "Scan complete",
        "user": username,
        "score": score,
        "violations_count": len(violations),
        "violations": [v["rule"] for v in violations],
        "violation_details": violations,
        "graph_data": graph,
    }


@router.get("/history/{username}")
def get_user_history(username, requester=Depends(get_current_user), role=Depends(get_requester_role),
                     loader=Depends(get_loader)):
    _require_target(loader, requester, role, username)
    reports = [
        {"filename": key, "last_modified": modified.isoformat(), "score": report["risk_score"]}
        for key, report, modified in loader.iter_reports(username)
    ]
    reports.sort(key=lambda report: report["last_modified"], reverse=True)
    return {"user": username, "history_count": len(reports), "reports": reports}


def _bulk_scan(loader):
    engine = RiskEngine(loader)
    results = []
    for username in loader.get_all_users():
        try:
            score, _, _ = engine.analyze_user_return_data(username)
            results.append({"user": username, "status": "scanned", "score": score})
        except (RuntimeError, OSError, ValueError) as error:
            results.append({"user": username, "status": "error", "error": str(error)})
        except (ClientError, BotoCoreError):
            results.append({"user": username, "status": "error", "error": "Scan storage failed."})
    return {"message": "Bulk scan complete", "details": results}


@router.post("/initialize")
def initialize_scans(role=Depends(get_requester_role), loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    return _bulk_scan(loader)


@router.post("/all")
def run_global_scan(role=Depends(get_requester_role), loader=Depends(get_loader)):
    _require_role(role, REVIEW_ROLES)
    return _bulk_scan(loader)


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
    current, simulated, violations = RiskEngine(loader).compare_simulation(
        request.username, request.add_policies, request.remove_policies,
        request.add_groups, request.remove_groups,
    )
    delta = round(simulated - current, 2)
    return {
        "user": request.username,
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
    return RiskEngine(loader).risk_rules


@router.post("/config/risks")
def update_risk_configuration(update: RiskRulesUpdate, role=Depends(get_requester_role),
                              loader=Depends(get_loader)):
    _require_role(role, ("ADMIN",))
    loader.save_risk_config(update.model_dump())
    return {"message": "Configuration updated successfully", "rules_count": len(update.risk_rules)}


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
