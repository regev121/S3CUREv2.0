from functools import lru_cache


@lru_cache(maxsize=8192)
def patterns_overlap(left, right):
    """Find whether two * / ? glob patterns can match the same string."""
    pending = [(0, 0)]
    seen = set()
    while pending:
        i, j = pending.pop()
        if (i, j) in seen:
            continue
        seen.add((i, j))
        if i == len(left) and j == len(right):
            return True

        a = left[i] if i < len(left) else None
        b = right[j] if j < len(right) else None
        if a == "*":
            pending.append((i + 1, j))
        if b == "*":
            pending.append((i, j + 1))
        if a is not None and b is not None and (a == b or a in "*?" or b in "*?"):
            pending.append((i if a == "*" else i + 1, j if b == "*" else j + 1))

    return False


@lru_cache(maxsize=8192)
def has_uncovered_match(required, denied=(), exceptions=()):
    """Find a match in every required glob outside the exceptions and denied clauses.

    A NUL between action and resource keeps their wildcard matches independent.
    """
    if any(pattern in required and not excepted for pattern, excepted in denied):
        return False

    patterns = tuple(dict.fromkeys((
        *required, *exceptions, *(p for pattern, excluded in denied for p in (pattern, *excluded)),
    )))
    indexes = {pattern: index for index, pattern in enumerate(patterns)}
    needed = tuple(indexes[pattern] for pattern in required)
    excluded = tuple(indexes[pattern] for pattern in exceptions)
    blocked = tuple((indexes[pattern], tuple(indexes[p] for p in excepted)) for pattern, excepted in denied)
    alphabet = set("".join(patterns)) - {"*", "?"}
    alphabet.add(None)  # All characters that never occur literally in the patterns.

    def close(pattern, positions):
        positions = set(positions)
        for position in tuple(positions):
            while position < len(pattern) and pattern[position] == "*":
                position += 1
                positions.add(position)
        return frozenset(positions)

    @lru_cache(maxsize=None)
    def advance(pattern, positions, char):
        return close(pattern, (
            i if pattern[i] == "*" else i + 1
            for i in positions
            if i < len(pattern) and (
                pattern[i] == char or (char != "\0" and pattern[i] in "*?")
            )
        ))

    end_positions = tuple(map(len, patterns))
    start = tuple(close(pattern, (0,)) for pattern in patterns)
    pending = [start]
    seen = {start}
    while pending:
        states = pending.pop()
        accepted = [end in positions for end, positions in zip(end_positions, states)]
        if (all(accepted[i] for i in needed)
            and not any(accepted[i] for i in excluded)
            and not any(accepted[i] and not any(accepted[j] for j in exempt) for i, exempt in blocked)):
            return True
        for char in alphabet:
            next_states = tuple(advance(pattern, state, char) for pattern, state in zip(patterns, states))
            if all(next_states[i] for i in needed) and next_states not in seen:
                pending.append(next_states)
                seen.add(next_states)
    return False


def _literal_prefix(pattern):
    return pattern.split("*", 1)[0].split("?", 1)[0]


class TrieNode:
    def __init__(self):
        self.children = {}
        self.grants = {}


class PermissionTrie:
    """Index resource grants by their literal prefix before the first wildcard."""

    def __init__(self):
        self.root = TrieNode()

    def insert(self, resource_arn, actions):
        pattern = resource_arn.removeprefix("arn:aws:s3:::")
        if not pattern:
            return
        node = self.root
        for char in _literal_prefix(pattern):
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.grants.setdefault(pattern, set()).update(actions)

    def matching_grants(self, resource_pattern):
        selector = resource_pattern.removeprefix("arn:aws:s3:::")
        prefix = _literal_prefix(selector)
        node = self.root
        for char in prefix:
            # A grant may start with a wildcard before the selector's literal prefix ends.
            for pattern, actions in node.grants.items():
                if patterns_overlap(pattern, selector):
                    yield pattern, actions
            node = node.children.get(char)
            if node is None:
                return

        pending = [node]
        while pending:
            node = pending.pop()
            for pattern, actions in node.grants.items():
                if patterns_overlap(pattern, selector):
                    yield pattern, actions
            if prefix != selector:
                pending.extend(node.children.values())

    def get_allowed_actions(self, target_resource):
        return {action for _, actions in self.matching_grants(target_resource) for action in actions}
