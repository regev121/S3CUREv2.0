import re
from functools import lru_cache
from ipaddress import ip_address, ip_network


_VARIABLE = re.compile(r"\$\{([^{}]+)\}")
_NEGATED = {"NotIpAddress", "StringNotLike", "StringNotEquals", "StringNotEqualsIgnoreCase"}
_SUPPORTED = _NEGATED | {
    "IpAddress", "StringLike", "StringEqualsIgnoreCase", "StringEquals", "Bool", "Null",
}


def substitute_variables(value, context, fallback):
    unresolved = False

    def replace(match):
        nonlocal unresolved
        key = match[1].lower()
        if context.get(key) is None:
            unresolved = True
            return fallback
        return str(context[key])

    return _VARIABLE.sub(replace, value), unresolved


@lru_cache(maxsize=4096)
def _glob(pattern):
    return re.compile(re.escape(pattern).replace(r"\*", ".*").replace(r"\?", "."), re.DOTALL)


def _evaluate(operator, actual, expected):
    if operator in ("IpAddress", "NotIpAddress"):
        address = ip_address(actual)
        matches = [address in ip_network(value, strict=False) for value in expected]
    elif operator in ("StringLike", "StringNotLike"):
        matches = [_glob(value).fullmatch(actual) is not None for value in expected]
    elif operator in ("StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"):
        matches = [actual.casefold() == value.casefold() for value in expected]
    elif operator in ("StringEquals", "StringNotEquals", "Bool"):
        matches = [actual == value for value in expected]
    return not any(matches) if operator in _NEGATED else any(matches)


def _string(value):
    return str(value).lower() if isinstance(value, bool) else str(value)


def _compare(operator, key, values, context, partial):
    base = operator.removesuffix("IfExists")
    if_exists = base != operator
    if base not in _SUPPORTED or (base == "Null" and if_exists):
        return None
    actual = context.get(key)
    if actual is None:
        if partial and key not in context:
            return None
        if base != "Null":
            return if_exists or base in _NEGATED

    values = values if isinstance(values, list) else [values]
    if base == "Null":
        expected = {_string(value) for value in values}
        return _string(actual is None) in expected if expected <= {"true", "false"} and expected else None

    expected = []
    for value in values:
        resolved, missing = substitute_variables(_string(value), context, "")
        if missing:
            return None
        expected.append(resolved)
    try:
        return _evaluate(base, _string(actual), expected)
    except ValueError:
        return None


def evaluate_conditions(conditions, context, *, partial=False):
    """Evaluate a request. A partial scan context leaves omitted keys unknown."""
    context = {key.lower(): value for key, value in context.items()}
    unresolved = False
    for operator, comparisons in conditions.items():
        for key, values in comparisons.items():
            decision = _compare(operator, key.lower(), values, context, partial)
            if decision is False:
                return False
            unresolved |= decision is None
    return None if unresolved else True
