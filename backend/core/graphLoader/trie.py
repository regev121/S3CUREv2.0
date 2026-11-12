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
