import re
from functools import lru_cache
from ipaddress import ip_address, ip_network


_VARIABLE = re.compile(r"\$\{([^{}]+)\}")


def substitute_variables(value, context, fallback):
    unresolved = False

    def replace(match):
        nonlocal unresolved
        key = match[1].lower()
        if key not in context:
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
    elif operator == "Null":
        matches = [value == "false" for value in expected]  # The key is present.
    else:
        return None
    return not any(matches) if operator.startswith(("Not", "StringNot")) else any(matches)


def evaluate_conditions(conditions, context):
    """Return True, False, or None when request context or operator support is incomplete."""
    unresolved = False
    for operator, comparisons in conditions.items():
        for key, values in comparisons.items():
            key = key.lower()
            if key not in context:
                unresolved = True
                continue
            actual = context[key]
            actual = str(actual).lower() if isinstance(actual, bool) else str(actual)
            if not isinstance(values, list):
                values = [values]
            expected = []
            for value in values:
                value = str(value).lower() if isinstance(value, bool) else str(value)
                value, missing = substitute_variables(value, context, "")
                if missing:
                    break
                expected.append(value)
            try:
                decision = (
                    _evaluate(operator.removesuffix("IfExists"), actual, expected)
                    if len(expected) == len(values) else None
                )
            except ValueError:
                decision = None
            if decision is False:
                return False
            unresolved |= decision is None
    return None if unresolved else True
