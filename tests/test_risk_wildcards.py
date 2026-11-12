import pytest

from backend.api.dto.risk import RiskRulesUpdate
from backend.core.graphLoader.riskEngine import RiskEngine
from backend.core.graphLoader.trie import PermissionTrie, patterns_overlap


class RulesLoader:
    def __init__(self, rules=None):
        self.rules = rules

    def get_risk_config(self):
        return self.rules


@pytest.mark.parametrize(("left", "right", "expected"), [
    ("s3:Get*", "s3:*Object", True),
    ("s3:Get*", "s3:Put*", False),
    ("prod-?/reports/*/file-?.json", "prod-a/reports/2026/*", True),
    ("prod-?/reports/*/file-?.json", "prod-a/reports/*/*.csv", False),
    ("prod-bucket/*", "prod-bucket", False),
    ("prod-bucket/a/*", "prod-bucket/a/nested/key", True),
    ("prod-bucket/log?.txt", "prod-bucket/log.txt", False),
])
def test_glob_intersection(left, right, expected):
    assert patterns_overlap(left, right) is expected
    assert patterns_overlap(right, left) is expected


def test_trie_keeps_bucket_actions_separate_and_finds_wildcard_grants():
    trie = PermissionTrie()
    trie.insert("arn:aws:s3:::prod-bucket", ["s3:ListBucket"])
    trie.insert("arn:aws:s3:::prod-bucket/private/*", ["s3:GetObject"])
    trie.insert("arn:aws:s3:::prod-?/reports/*", ["s3:PutObject"])

    assert trie.get_allowed_actions("prod-bucket") == {"s3:ListBucket"}
    assert trie.get_allowed_actions("prod-bucket/private/a/b.txt") == {"s3:GetObject"}
    assert trie.get_allowed_actions("prod-b/reports/2026/*") == {"s3:PutObject"}
    assert trie.get_allowed_actions("prod-bucket/public/*") == set()
    assert trie.get_allowed_actions("*") == {"s3:ListBucket", "s3:GetObject", "s3:PutObject"}


def evaluate(engine, action, resource):
    return engine._evaluate("Example", {
        "sample": {"Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]},
    })


def test_default_risk_rules_match_scoped_grants_and_keep_administrator_breadth():
    engine = RiskEngine(RulesLoader())
    score, violations = evaluate(engine, "s3:Put*Policy", "prod-bucket")
    assert score == 14.55
    assert violations[0]["actual_allowed_actions"] == ["s3:Put*Policy"]

    score, violations = evaluate(engine, "s3:GetObject", "*")
    assert score == 16.36
    assert len(violations) == 1
    assert evaluate(engine, "s3:GetObject", "prod-bucket/private/*")[0] == 16.36
    assert evaluate(engine, "s3:*", "prod-bucket")[0] == 58.18
    assert evaluate(engine, "s3:*", "*")[0] == 90.91
    assert evaluate(engine, "*", "*")[0] == 100


def test_rule_mode_is_configurable_and_legacy_administrator_rule_keeps_its_scope():
    rule = {
        "description": "CRITICAL: Full Administrative Power",
        "severity": 10,
        "resource_pattern": "*",
        "risky_actions": ["s3:*"],
    }
    legacy = RiskEngine(RulesLoader({"risk_rules": [rule]}))
    assert legacy.risk_rules["risk_rules"][0]["require_global_grant"] is True
    assert evaluate(legacy, "s3:GetObject", "prod-bucket/*")[0] == 0

    saved = RiskRulesUpdate.model_validate({
        "risk_rules": [{**rule, "require_global_grant": False}],
    }).model_dump()
    custom = RiskEngine(RulesLoader(saved))
    assert evaluate(custom, "s3:GetObject", "prod-bucket/*")[0] == 100
