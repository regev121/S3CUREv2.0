import pytest

from backend.core.graphLoader.conditions import evaluate_conditions


@pytest.mark.parametrize(("operator", "value", "context", "expected"), [
    ("StringEqualsIfExists", "reports/", {}, True),
    ("StringNotEqualsIfExists", "reports/", {}, True),
    ("StringEqualsIfExists", "reports/", {"s3:Prefix": "other/"}, False),
    ("StringEquals", "reports/", {}, False),
    ("StringNotEquals", "reports/", {}, True),
    ("Null", True, {}, True),
    ("Null", "false", {}, False),
    ("Null", True, {"s3:prefix": ""}, False),
    ("Null", False, {"s3:prefix": ""}, True),
    ("Null", True, {"s3:prefix": None}, True),
    ("NullIfExists", True, {}, None),
    ("UnsupportedIfExists", "reports/", {}, None),
])
def test_request_key_presence(operator, value, context, expected):
    assert evaluate_conditions({operator: {"s3:prefix": value}}, context) is expected


def test_partial_context_does_not_assume_omitted_keys_are_absent():
    conditions = {"StringEqualsIfExists": {"s3:prefix": "reports/"}, "Null": {"aws:sourceip": True}}
    assert evaluate_conditions(conditions, {}, partial=True) is None
    assert evaluate_conditions(conditions, {"s3:prefix": None, "aws:sourceip": None}, partial=True) is True
    assert evaluate_conditions(conditions, {"s3:prefix": "other/"}, partial=True) is False
