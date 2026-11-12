from backend.core.graphLoader.riskEngine import RiskEngine
from backend.core.graphLoader.trie import has_uncovered_match


class Loader:
    def __init__(self, bucket_policies=None):
        self.bucket_policies = bucket_policies or {}

    def get_risk_config(self):
        return None

    def get_bucket_policies(self):
        return self.bucket_policies, "complete"


def test_explicit_deny_blocks_only_the_overlapping_requests():
    allow = {"Effect": "Allow", "Action": "s3:Delete*", "Resource": "arn:aws:s3:::prod-*/*"}
    deny = {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::prod-bucket/private/*"}
    engine = RiskEngine(Loader())

    def evaluate(statement):
        return engine._evaluate("Alice", {"editors": {"Statement": allow}, "restriction": {"Statement": statement}})

    assert evaluate(deny)[0] == 18.18
    score, findings = evaluate({**deny, "Resource": "arn:aws:s3:::prod-bucket/*"})
    assert score == 0 and findings == []
    assert any(edge["label"].startswith("DENIES") for edge in engine._export_graph_to_json()["edges"])


def test_request_context_evaluates_allow_and_deny_and_preserves_uncertainty():
    resource = "arn:aws:s3:::prod-bucket/*"
    statements = [
        {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": resource,
         "Condition": {"IpAddress": {"aws:SourceIp": ["192.0.2.0/24", "2001:db8::/32"]}}},
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": resource,
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
    ]
    engine = RiskEngine(Loader())
    policies = {"editors": {"Statement": statements}}
    assert engine._evaluate("Alice", policies)[1][0]["evidence"][0]["conditional"]
    assert engine._evaluate("Alice", policies, context={"aws:sourceip": "203.0.113.1"})[0] == 0
    assert engine._evaluate("Alice", policies, context={
        "aws:sourceip": "192.0.2.1", "aws:securetransport": False,
    })[0] == 0
    assert not engine._evaluate("Alice", policies, context={
        "aws:sourceip": "2001:db8::1", "aws:securetransport": True,
    })[1][0]["evidence"][0]["conditional"]


def test_anonymous_bucket_findings_use_the_principal_action_and_bucket_scope():
    grant = {"Sid": "public-reports", "Effect": "Allow", "Action": "s3:GetObj?ct",
             "Resource": "arn:aws:s3:::prod-bucket/reports/*"}
    policies = {"prod-bucket": {"Statement": [
        {**grant, "Principal": {"AWS": ["Alice"]}},
        {**grant, "Principal": "*", "Resource": "arn:aws:s3:::prod-bucket"},
    ]}, "other-bucket": {"Statement": {**grant, "Principal": "*"}}}
    assert RiskEngine(Loader(policies))._evaluate("Alice", {}) == (0, [])

    public = {**grant, "Principal": {"AWS": ["*"]}}
    deny = {"Effect": "Deny", "Action": "s3:GetObject", "Principal": "*",
            "Resource": "arn:aws:s3:::prod-bucket/reports/private/*"}
    policies["prod-bucket"]["Statement"].extend([public, deny])
    score, findings = RiskEngine(Loader(policies))._evaluate("Alice", {})
    assert score == 16.36
    assert findings[0]["evidence"] == [{
        "policy": "public-reports", "bucket": "prod-bucket", "action": "s3:GetObject",
        "resource": "prod-bucket/reports/*", "direct": False, "groups": [], "conditional": False,
    }]

    deny["Resource"] = public["Resource"]
    assert RiskEngine(Loader(policies))._evaluate("Alice", {}) == (0, [])
    deny["Condition"] = {"StringEquals": {"aws:principaltype": "User"}}
    public["Condition"] = {"Bool": {"aws:SecureTransport": True}}
    engine = RiskEngine(Loader(policies))
    assert engine._evaluate("Alice", {})[1][0]["evidence"][0]["conditional"]
    assert engine._evaluate("Alice", {}, context={"aws:securetransport": False}) == (0, [])


def test_deny_if_exists_distinguishes_absent_and_unknown_request_keys():
    grant = {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::prod-bucket/*"}
    policy = {"Statement": [grant, {
        **grant, "Effect": "Deny", "Condition": {"BoolIfExists": {"aws:SecureTransport": False}},
    }]}
    engine = RiskEngine(Loader())
    assert engine._evaluate("Alice", {"editors": policy}, partial=False) == (0, [])
    assert engine._evaluate("Alice", {"editors": policy})[1][0]["evidence"][0]["conditional"]


def test_denials_with_exceptions_leave_the_named_action_or_prefix_available():
    scope = "arn:aws:s3:::prod-bucket/*"
    allow = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": scope}
    deny = {"Effect": "Deny", "Principal": "*", "NotAction": "s3:GetObject", "Resource": scope}
    policy = {"prod-bucket": {"Statement": [allow, deny]}}
    assert RiskEngine(Loader(policy))._evaluate("Alice", {})[0] == 16.36

    deny = {"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject",
            "NotResource": "arn:aws:s3:::prod-bucket/allowed/*"}
    policy["prod-bucket"]["Statement"][1] = deny
    assert RiskEngine(Loader(policy))._evaluate("Alice", {})[0] == 16.36
    allow["Resource"] = "arn:aws:s3:::prod-bucket/private/*"
    assert RiskEngine(Loader(policy))._evaluate("Alice", {}) == (0, [])


def test_glob_union_can_cover_every_matching_request():
    assert not has_uncovered_match(
        ("s3:DeleteObject\0prod-bucket/*", "s3:Delete*\0prod-bucket/*"),
        (("s3:*\0prod-bucket/", ()), ("s3:DeleteObject\0prod-bucket/?*", ())),
    )
