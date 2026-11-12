from backend.core.graphLoader.graph import SecurityGraph, NodeType


def as_list(value):
    return [value] if isinstance(value, str) else (value or [])


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

        statements = policy_content.get("Statement", [])

        # Normalize single-dict statement to list format
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            self._process_statement(policy_id, stmt)

    def _process_statement(self, policy_id, statement):
        """
        Analyzes a single IAM Statement block to determine access effects.
        Records both positive access paths and explicit denials.
        """
        effect = statement.get("Effect", "Deny")

        if effect not in ("Allow", "Deny"):
            return

        not_actions = as_list(statement.get("NotAction"))
        not_resources = as_list(statement.get("NotResource"))
        actions = as_list(statement.get("Action")) or (["*"] if not_actions else [])
        resources = as_list(statement.get("Resource")) or (["*"] if not_resources else [])
        conditions = statement.get("Condition", {})

        for resource_arn in resources:
            # Normalize ARN to a readable resource identifier
            resource_name = self._normalize_resource_name(resource_arn)

            # Register Resource Entity
            resource_id = f"resource:{resource_name}"
            self.graph.add_node(resource_id, NodeType.RESOURCE)

            # Establish Relationship: Policy allows access to Resource
            self.graph.add_edge(
                source=policy_id,
                target=resource_id,
                relationship_type="ALLOWS" if effect == "Allow" else "DENIES",
                metadata={
                    "actions": actions, "conditions": conditions, "not_actions": not_actions,
                    "not_resources": [self._normalize_resource_name(arn) for arn in not_resources],
                },
            )

    def _normalize_resource_name(self, arn):
        """
        Parses an AWS ARN string to extract the relevant resource path or bucket name.
        Reduces visual noise in the graph for common S3 patterns.
        """
        return arn.removeprefix("arn:aws:s3:::")
