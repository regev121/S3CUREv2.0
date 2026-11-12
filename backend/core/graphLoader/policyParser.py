from backend.core.graphLoader.graph import SecurityGraph, NodeType


def as_list(value):
    return [value] if isinstance(value, str) else (value or [])


def policy_statements(document):
    statements = document.get("Statement", [])
    return [statements] if isinstance(statements, dict) else statements


def statement_scope(statement):
    not_actions = as_list(statement.get("NotAction"))
    not_resources = as_list(statement.get("NotResource"))
    actions = as_list(statement.get("Action")) or (["*"] if not_actions else [])
    service_scope = (actions or not_actions) and all(
        action.startswith(("admin:", "kms:", "sts:")) for action in (not_actions or actions)
    )
    resources = as_list(statement.get("Resource")) or (["*"] if not_resources or service_scope else [])
    return {
        "actions": actions,
        "resources": [arn.removeprefix("arn:aws:s3:::") for arn in resources],
        "conditions": statement.get("Condition") or {},
        "not_actions": not_actions,
        "not_resources": [arn.removeprefix("arn:aws:s3:::") for arn in not_resources],
    }


class PolicyParser:
    def __init__(self, graph: SecurityGraph):
        """
        Initializes the PolicyParser.
        Responsible for translating raw IAM Policy JSON documents into
        graph nodes and edges within the SecurityGraph.
        """
        self.graph = graph

    def load_policy_to_graph(self, user_name, policy_name, policy_content, origin=None):
        """
        Ingests a full IAM Policy document and maps it to the graph topology.
        Establishes the lineage: User -> Policy -> Resource(s).
        """
        user_id = f"user:{user_name}"
        policy_id = f"policy:{policy_name}"
        self.graph.add_node(user_id, NodeType.USER)
        self.graph.add_node(policy_id, NodeType.POLICY)
        self.graph.add_edge(user_id, policy_id, "HAS_POLICY", origin)

        for stmt in policy_statements(policy_content):
            self._process_statement(policy_id, stmt)

    def _process_statement(self, policy_id, statement):
        """
        Analyzes a single IAM Statement block to determine access effects.
        Records both positive access paths and explicit denials.
        """
        effect = statement.get("Effect", "Deny")

        if effect not in ("Allow", "Deny"):
            return

        metadata = statement_scope(statement)
        for resource_name in metadata.pop("resources"):
            resource_id = f"resource:{resource_name}"
            self.graph.add_node(resource_id, NodeType.RESOURCE)
            self.graph.add_edge(
                source=policy_id,
                target=resource_id,
                relationship_type="ALLOWS" if effect == "Allow" else "DENIES",
                metadata=metadata,
            )
