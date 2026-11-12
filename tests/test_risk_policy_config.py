from backend.api.dto.risk import RiskRule, RiskRulesUpdate
from backend.core.graphLoader.riskEngine import RiskEngine, risk_rule_catalog


class Loader:
    def get_risk_config(self):
        return None


def statement(action, resource=None, effect="Allow", condition=None):
    data = {"Effect": effect, "Action": action}
    if resource:
        data["Resource"] = "arn:aws:s3:::" + resource
    if condition:
        data["Condition"] = condition
    return data


def engine_with(statements):
    rule = RiskRule.model_validate({
        "description": "Test permissions", "severity": 5, "policy": {"Statement": statements},
    })
    return RiskEngine(Loader(), rules={"risk_rules": [rule.model_dump(exclude_none=True)]})


def test_manual_rules_keep_each_statement_action_and_resource_together():
    engine = engine_with([
        statement("s3:GetObject", "finance-bucket/*"),
        statement("s3:DeleteObject", "prod-bucket/*"),
    ])
    policies = {"example": {"Statement": [statement("s3:DeleteObject", "finance-bucket/*")]}}
    assert engine._evaluate("Alice", policies) == (0, [])
    policies["example"]["Statement"].append(statement("s3:DeleteObject", "prod-bucket/*"))
    score, findings = engine._evaluate("Alice", policies)
    assert score == 100
    assert findings[0]["evidence"][0]["matched_resource"] == "prod-bucket/*"


def test_deny_only_flags_access_and_actual_explicit_deny_prevents_that_finding():
    engine = engine_with([statement("s3:DeleteObject", "prod-bucket/*", "Deny")])
    policies = {"example": {"Statement": [statement("s3:DeleteObject", "prod-bucket/*")]}}
    assert engine._evaluate("Alice", policies)[0] == 100
    policies["guardrail"] = {"Statement": statement("s3:DeleteObject", "prod-bucket/*", "Deny")}
    assert engine._evaluate("Alice", policies) == (0, [])


def test_mixed_policy_exclusions_and_request_context_apply_to_manual_rules():
    condition = {"Bool": {"aws:SecureTransport": False}}
    engine = engine_with([
        statement("s3:GetObject", "prod-bucket/*", condition=condition),
        statement("s3:GetObject", "prod-bucket/excluded/*", "Deny"),
    ])
    policies = {"example": {"Statement": [statement("s3:GetObject", "prod-bucket/excluded/*")]}}
    assert engine._evaluate("Alice", policies) == (0, [])
    policies["example"]["Statement"] = [statement("s3:GetObject", "prod-bucket/*")]
    assert engine._evaluate("Alice", policies)[1][0]["evidence"][0]["conditional"]
    assert engine._evaluate("Alice", policies, context={"aws:securetransport": True}) == (0, [])


def test_catalog_flags_console_iam_capabilities_with_no_bucket_resource():
    rules = RiskRulesUpdate.model_validate({"risk_rules": risk_rule_catalog()})
    engine = RiskEngine(Loader(), rules=rules.model_dump(exclude_none=True))
    policies = {"consoleAdmin": {"Statement": [{"Effect": "Allow", "Action": ["admin:*"]}]}}
    score, findings = engine._evaluate("Admin", policies)
    assert score > 0
    assert any(finding["rule"] == "CRITICAL: Change IAM permissions" for finding in findings)
    assert all(grant["policy"] == "consoleAdmin" for finding in findings for grant in finding["evidence"])
