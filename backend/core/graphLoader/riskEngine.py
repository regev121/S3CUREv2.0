import json
from collections import defaultdict
from pathlib import Path
from backend.core.graphLoader.s3Loader import S3Loader, policy_origins
from backend.core.graphLoader.graph import SecurityGraph, NodeType
from backend.core.graphLoader.policyParser import PolicyParser
from backend.core.graphLoader.trie import PermissionTrie, patterns_overlap


def _requires_global_grant(rule):
    configured = rule.get("require_global_grant")
    if configured is not None:
        return configured
    # Saved configurations may predate this flag, including edits that dropped the rule ID.
    if rule.get("resource_pattern", "").removeprefix("arn:aws:s3:::") != "*":
        return False
    actions = rule.get("risky_actions")
    description = rule.get("description")
    return (
        actions == ["*"]
        and (rule.get("id") == "R006" or description == "MEDIUM: Admin Privileges Detected")
    ) or (
        actions == ["s3:*"]
        and (rule.get("id") == "R008" or description == "CRITICAL: Full Administrative Power")
    )


def _matches_action(granted, risky, require_global_grant):
    if require_global_grant and (risky == "*" or risky.endswith(":*")):
        # To cover a whole service, the grant must cover its prefix and every suffix.
        return granted.endswith("*") and patterns_overlap(granted, risky[:-1])
    return patterns_overlap(granted, risky)


class RiskEngine:
    def __init__(self, loader=None):
        self.loader = loader or S3Loader()
        self.graph = SecurityGraph()
        self.parser = PolicyParser(self.graph)
        rules = self.loader.get_risk_config()
        if rules is None:
            with open(Path(__file__).with_name("risks.json"), encoding="utf-8") as config:
                rules = json.load(config)
        self.risk_rules = {
            **rules,
            "risk_rules": [
                {**rule, "require_global_grant": _requires_global_grant(rule)}
                for rule in rules.get("risk_rules", [])
            ],
        }

    def _evaluate(self, username, policies, origins=None):
        self.graph.clear()
        self.graph.add_node(f"user:{username}", NodeType.USER)
        origins = origins or {}
        for name, content in sorted(policies.items()):
            self.parser.load_policy_to_graph(username, name, content, origins.get(name))
        return self._calculate_risk_score(username)

    def analyze_user(self, username):
        return self.analyze_user_return_data(username)[0]

    def analyze_user_return_data(self, username):
        grants = self.loader.get_user_access_data(username)
        policies = {item["name"]: item["content"] for item in grants}
        origins = {item["name"]: item["origin"] for item in grants}
        risk_score, violations = self._evaluate(username, policies, origins)
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
        simulated_score, violations = self._evaluate(
            username, {name: documents[name] for name in simulated},
            policy_origins(simulated_direct, simulated_groups),
        )
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
        provenance = defaultdict(set)
        origins = {}
        user_edges = self.graph.get_edges_from(f"user:{username}")

        for edge in user_edges:
            policy_id = edge["target"]
            policy_name = policy_id.removeprefix("policy:")
            origins[policy_name] = edge["metadata"]
            policy_edges = self.graph.get_edges_from(policy_id)
            for p_edge in policy_edges:
                resource_arn = p_edge["target"].removeprefix("resource:")
                actions = p_edge["metadata"].get("actions", [])
                user_trie.insert(resource_arn, actions)
                conditional = bool(p_edge["metadata"].get("conditions"))
                for action in actions:
                    provenance[resource_arn, action].add((policy_name, conditional))

        # Phase 2: Evaluate Risk Rules
        for rule in self.risk_rules.get("risk_rules", []):
            risky_resource = rule["resource_pattern"]
            selector = risky_resource.removeprefix("arn:aws:s3:::")
            grants = dict(user_trie.matching_grants(selector))
            if selector != "*" and "/" not in selector and not selector.startswith("arn:"):
                # A bucket-level risk selector summarizes grants on the bucket and its objects.
                grants.update(user_trie.matching_grants(f"{selector}/*"))
            global_only = rule["require_global_grant"]
            matched_grants = {
                (resource, granted)
                for resource, actions in grants.items()
                if not global_only or not resource.strip("*")
                for granted in actions
                if any(_matches_action(granted, risky, global_only) for risky in rule["risky_actions"])
            }
            if not matched_grants:
                continue

            severity = rule.get("severity", 10)
            total_risk += severity
            violations.append({
                "rule": rule["description"],
                "resource": risky_resource,
                "severity": severity,
                "actual_allowed_actions": sorted({action for _, action in matched_grants}),
                "evidence": [
                    {
                        "policy": policy,
                        "resource": resource,
                        "action": action,
                        "direct": origins[policy].get("direct", False),
                        "groups": origins[policy].get("groups", []),
                        "conditional": conditional,
                    }
                    for resource, action in sorted(matched_grants)
                    for policy, conditional in sorted(provenance[resource, action])
                ],
            })

        # Normalization (0-100 Scale)
        if max_possible_risk == 0:
            normalized_score = 0
        else:
            normalized_score = (total_risk / max_possible_risk) * 100

        return round(normalized_score, 2), violations

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
