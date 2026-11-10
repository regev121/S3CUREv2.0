class TrieNode:
    def __init__(self):
        """
        Represents a single node within the Permission Trie.
        """
        self.children = {}
        self.is_wildcard = False
        self.allowed_actions = set()


class PermissionTrie:
    def __init__(self):
        """
        Initializes a Permission Trie.
        A specialized prefix tree designed for efficient matching of resource paths
        against IAM permission patterns, supporting wildcard handling.
        """
        self.root = TrieNode()

    def insert(self, resource_arn, actions):
        """
        Inserts a resource path into the Trie, associating it with the set of allowed actions.
        Handles wildcard segments ('*') by marking nodes as wildcard-enabled,
        propagating permissions to all potential child paths.
        """
        clean_path = self._normalize_path(resource_arn)
        parts = clean_path.split("/")

        node = self.root
        for part in parts:
            if part == "*" or part == "":
                node.is_wildcard = True
                # Wildcards imply the actions grant access to this level and all descendants.
                node.allowed_actions.update(actions)
                return

            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]

        # Associate actions with the specific leaf or intermediate node
        node.allowed_actions.update(actions)

    def get_allowed_actions(self, target_resource):
        """
        Retrieves the cumulative set of actions permitted for a specific target resource.
        Traverses the Trie to collect permissions from both exact matches and
        any wildcard nodes encountered along the path.
        """
        clean_path = self._normalize_path(target_resource)
        parts = clean_path.split("/")

        found_actions = set()
        self._collect_permissions(self.root, parts, 0, found_actions)
        return found_actions

    def _collect_permissions(self, node, parts, index, accumulator):
        """
        Recursive helper to traverse the Trie and accumulate permissions.
        """
        # 1. Applicability of Wildcards: If current node is a wildcard, its permissions apply to the target.
        if node.is_wildcard:
            accumulator.update(node.allowed_actions)

        # 2. Path Completion: If traversal reached the target depth, collect explicit permissions.
        if index == len(parts):
            accumulator.update(node.allowed_actions)
            return

        # 3. Recursive Descent: Continue traversing if path segments match.
        part = parts[index]
        if part in node.children:
            self._collect_permissions(
                node.children[part], parts, index + 1, accumulator
            )

    def _normalize_path(self, arn):
        """
        Standardizes the resource string for Trie insertion/lookup.
        Strips ARN prefixes to focus on the hierarchical path.
        """
        if arn == "*":
            return "*"
        if "arn:aws:s3:::" in arn:
            return arn.split("arn:aws:s3:::")[-1]
        return arn
