import json
from pathlib import Path
from backend.core.graphLoader.s3Loader import S3Loader
from backend.core.graphLoader.graph import SecurityGraph, NodeType
from backend.core.graphLoader.policyParser import PolicyParser
from backend.core.graphLoader.trie import PermissionTrie


class RiskEngine:
    def __init__(self, loader=None):
        self.loader = loader or S3Loader()
        self.graph = SecurityGraph()
        self.parser = PolicyParser(self.graph)
        rules = self.loader.get_risk_config()
        if rules is None:
            with open(Path(__file__).with_name("risks.json"), encoding="utf-8") as config:
                rules = json.load(config)
        self.risk_rules = rules

    def _evaluate(self, username, policies):
        self.graph.clear()
        self.graph.add_node(f"user:{username}", NodeType.USER)
        for name, content in sorted(policies.items()):
            self.parser.load_policy_to_graph(username, name, content)
        return self._calculate_risk_score(username)

    def analyze_user(self, username):
        return self.analyze_user_return_data(username)[0]

    def analyze_user_return_data(self, username):
        policies = {
            item["name"]: item["content"] for item in self.loader.get_user_access_data(username)
        }
        risk_score, violations = self._evaluate(username, policies)
        graph = self._export_graph_to_json()
        self.loader.archive_scan_result(username, {
            "user": username,
            "risk_score": risk_score,
            "violated_rules": violations,
            "policies_analyzed": sorted(policies),
        }, graph)
        return risk_score, violations, graph

    def compare_simulation(self, username, add_policies=(), remove_policies=(), add_groups=(), remove_groups=()):
        direct, groups = self.loader.get_user_assignments(username)
        original = direct.union(*groups.values())
        simulated_direct = (direct - set(remove_policies)) | set(add_policies)
        simulated_groups = {
            group: policies for group, policies in groups.items() if group not in remove_groups
        }
        for group in add_groups:
            if group not in simulated_groups:
                simulated_groups[group] = self.loader.get_group_policies_names(group)
        simulated = simulated_direct.union(*simulated_groups.values())

        # Shared policies are loaded once so the baseline and the simulation use the same snapshot.
        documents = {name: self.loader.get_policy(name) for name in sorted(original | simulated)}
        current_score, _ = self._evaluate(username, {name: documents[name] for name in original})
        simulated_score, violations = self._evaluate(username, {name: documents[name] for name in simulated})
        return current_score, simulated_score, violations

    def simulate_user(self, username, add_policies=(), remove_policies=(), add_groups=(), remove_groups=()):
        _, simulated_score, violations = self.compare_simulation(
            username, add_policies, remove_policies, add_groups, remove_groups
        )
        return simulated_score, violations

    def _calculate_risk_score(self, username):
        """
        Computes the quantitative risk score based on the intersection of
        user permissions and defined risk rules.
        Utilizes a Permission Trie for efficient wildcard matching against resource patterns.
        """
        total_risk = 0
        violations = []

        # Calculate max theoretical risk for normalization
        max_possible_risk = sum(
            rule.get("severity", 10) for rule in self.risk_rules.get("risk_rules", [])
        )

        # Phase 1: Construct Permission Trie from Graph
        user_trie = PermissionTrie()
        user_edges = self.graph.get_edges_from(f"user:{username}")

        for edge in user_edges:
            policy_name = edge["target"]
            policy_edges = self.graph.get_edges_from(policy_name)
            for p_edge in policy_edges:
                resource_arn = p_edge["target"].removeprefix("resource:")
                actions = p_edge["metadata"].get("actions", [])
                user_trie.insert(resource_arn, actions)

        # Phase 2: Evaluate Risk Rules
        for rule in self.risk_rules.get("risk_rules", []):
            risky_resource = rule.get("resource_pattern")
            risky_actions_list = rule.get("risky_actions", [])

            allowed_on_resource = user_trie.get_allowed_actions(risky_resource)

            if not allowed_on_resource:
                continue

            violation_found = False

            # Semantic Action Matching (Wildcard Aware)
            for risky_act in risky_actions_list:
                if self._is_action_included(allowed_on_resource, risky_act):
                    violation_found = True
                    break

            if violation_found:
                severity = rule.get("severity", 10)
                total_risk += severity

                violations.append(
                    {
                        "rule": rule["description"],
                        "resource": risky_resource,
                        "severity": severity,
                        "actual_allowed_actions": sorted(allowed_on_resource),
                    }
                )

        # Normalization (0-100 Scale)
        if max_possible_risk == 0:
            normalized_score = 0
        else:
            normalized_score = (total_risk / max_possible_risk) * 100

        return round(normalized_score, 2), violations

    def _is_action_included(self, allowed_actions, risky_action):
        """
        Determines if a specific 'risky_action' is permitted by the 'allowed_actions' set.
        Supports complex AWS IAM wildcard matching logic.

        Examples:
        - allowed=['*'], risky='s3:GetObject' -> True
        - allowed=['s3:*'], risky='s3:GetObject' -> True
        - allowed=['s3:Get*'], risky='s3:GetObject' -> True
        """
        # Universal Admin Access (*)
        if risky_action == "*" and allowed_actions:
            return True

        for allowed in allowed_actions:
            # 1. Exact Match or Service Wildcard
            if allowed == "*" or allowed == risky_action:
                return True

            # 2. Prefix Wildcard Match (e.g. s3:*)
            if allowed.endswith("*"):
                prefix = allowed[:-1]
                if risky_action.startswith(prefix):
                    return True

        return False

    def _export_graph_to_json(self):
        """
        Serializes the internal graph topology into a JSON-compatible dictionary format.
        Designed for consumption by the Frontend visualization library (Vis.js).
        Includes styling metadata (colors, shapes) based on node types.
        """
        nodes = []
        for name, n_type in self.graph.nodes.items():
            # Default Style
            color = "#97C2FC" # Blue
            shape = "ellipse"

            # Theme Colors for Cyber Look
            if n_type == NodeType.USER:
                color = "#FFD700" # Gold
                shape = "box"
            elif n_type == NodeType.POLICY:
                color = "#FF4D4D" # Red/Pink
                shape = "ellipse"
            elif n_type == NodeType.RESOURCE:
                color = "#00FF00" # Matrix Green
                shape = "database"

            nodes.append({
                "id": name,
                "label": name.partition(":")[2],
                "shape": shape,
                "color": color,
                "type": n_type.value # e.g., "USER", "POLICY"
            })

        edges = []
        for edge in self.graph.edges:
            label = edge["type"]
            title = "" # Tooltip
            if "actions" in edge["metadata"]:
                actions = edge["metadata"]["actions"]
                label += f"\n({', '.join(actions)})"
                title = ", ".join(actions)

            edges.append({
                "from": edge["source"],
                "to": edge["target"],
                "label": label, # Visible label
                "title": title, # Tooltip
                "arrows": "to",
                "color": "#5c6c7c" # Grayish
            })

        return {"nodes": nodes, "edges": edges}


if __name__ == "__main__":
    engine = RiskEngine()
    engine.analyze_user("Bob")
