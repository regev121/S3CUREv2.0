import json
from collections import defaultdict
from datetime import datetime
from functools import cached_property
from hashlib import sha256
from pathlib import Path
from typing import NamedTuple

from backend.core.graphLoader.conditions import evaluate_conditions, substitute_variables
from backend.core.graphLoader.s3Loader import S3Loader, policy_origins
from backend.core.graphLoader.graph import SecurityGraph, NodeType
from backend.core.graphLoader.policyParser import PolicyParser, as_list, policy_statements, statement_scope
from backend.core.graphLoader.trie import PermissionTrie, has_uncovered_match, patterns_overlap


SCORING_MODEL = "effective-access-v2"

BUCKET_ACTIONS = {
    "s3:ListBucket", "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:PutBucketAcl",
    "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
    "s3:PutLifecycleConfiguration", "s3:PutBucketObjectLockConfiguration",
    "s3:PutReplicationConfiguration",
}
OBJECT_ACTIONS = {
    "s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject",
    "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
    "s3:PutObjectRetention", "s3:PutObjectLegalHold",
}


class Grant(NamedTuple):
    action: str
    resource: str
    policy: str
    decision: bool | None
    excluded_actions: tuple[str, ...] = ()
    excluded_resources: tuple[str, ...] = ()

    @property
    def exceptions(self):
        return (
            *(_pair(action, "*") for action in self.excluded_actions),
            *(_pair("*", resource) for resource in self.excluded_resources),
        )

    def evidence_exceptions(self):
        result = {}
        if self.excluded_actions:
            result["excluded_actions"] = list(self.excluded_actions)
        if self.excluded_resources:
            result["excluded_resources"] = list(self.excluded_resources)
        return result


def _public_rule(rule):
    return rule.get("id") == "R001" or rule["description"] == "CRITICAL: Public Access to Production Data"


def _anonymous_principal(principal):
    if isinstance(principal, dict):
        principal = principal.get("AWS")
    return any(pattern and not pattern.strip("*") for pattern in as_list(principal))


def _pair(action, resource):
    return f"{action}\0{resource}"


def _grants(policy, actions, resources, conditions, not_actions, not_resources, context):
    decision = evaluate_conditions(conditions, context)
    if decision is False:
        return
    excluded_resources = []
    for pattern in not_resources:
        value, missing = substitute_variables(pattern, context, "")
        if missing:
            decision = None
        else:
            excluded_resources.append(value)
    for pattern in resources:
        resource, missing = substitute_variables(pattern, context, "*")
        if not resource:
            continue
        for action in actions:
            yield Grant(action, resource, policy, None if missing else decision,
                        tuple(sorted(not_actions)), tuple(sorted(excluded_resources)))

def _requires_global_grant(rule):
    if rule.get("policy"):
        return False
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


def _fingerprint_rule(rule):
    payload = {"description": rule["description"], "severity": rule.get("severity", 10)}
    if rule.get("policy"):
        statements = []
        for statement in policy_statements(rule["policy"]):
            scope = statement_scope(statement)
            for key in ("actions", "resources", "not_actions", "not_resources"):
                scope[key] = sorted(set(scope[key]))
            statements.append(json.dumps({"effect": statement["Effect"], **scope}, sort_keys=True))
        payload["policy"] = sorted(set(statements))
    else:
        payload.update({
            "resource": rule["resource_pattern"].removeprefix("arn:aws:s3:::"),
            "actions": sorted(set(rule["risky_actions"])),
            "require_global_grant": rule["require_global_grant"],
            "public_access": _public_rule(rule),
        })
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def risk_rule_catalog():
    return json.loads(Path(__file__).with_name("risk_catalog.json").read_text(encoding="utf-8"))


class RiskEngine:
    def __init__(self, loader=None, rules=None):
        self.loader = loader or S3Loader()
        self.graph = SecurityGraph()
        self.parser = PolicyParser(self.graph)
        if rules is None:
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

        effective_rules = [_fingerprint_rule(rule) for rule in self.risk_rules["risk_rules"]]
        fingerprint = json.dumps([SCORING_MODEL, sorted(effective_rules)], separators=(",", ":"))
        self.config_version = sha256(fingerprint.encode("utf-8")).hexdigest()
        self.config_created_at = rules.get("created_at")

    @property
    def config_label(self):
        if self.config_created_at:
            date = datetime.fromisoformat(self.config_created_at)
            return f"CONFIG_Creation_Date:{date:%d/%m/%Y}"
        return "CONFIG (creation date unavailable)"

    @cached_property
    def bucket_policy_snapshot(self):
        read_policies = getattr(self.loader, "get_bucket_policies", None)
        return read_policies() if read_policies else ({}, "unavailable")

    def _evaluate(self, username, policies, origins=None, context=None):
        self.graph.clear()
        self.graph.add_node(f"user:{username}", NodeType.USER)
        origins = origins or {}
        for name, content in sorted(policies.items()):
            self.parser.load_policy_to_graph(username, name, content, origins.get(name))
        return self._calculate_risk_score(username, {
            **(context or {}), "aws:username": username, "aws:userid": username, "aws:principaltype": "User",
        })

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
            "risk_config_version": self.config_version,
            "risk_config_created_at": self.config_created_at,
            "bucket_policy_coverage": self.bucket_policy_snapshot[1],
            "violated_rules": violations,
            "policies_analyzed": sorted(policies),
        }, graph)
        return risk_score, violations, graph

    def compare_simulation(self, username, add_policies=(), remove_policies=(), add_groups=(), remove_groups=(),
                           context=None):
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
        current_score, _ = self._evaluate(username, {name: documents[name] for name in original}, context=context)
        simulated_score, violations = self._evaluate(
            username, {name: documents[name] for name in simulated},
            policy_origins(simulated_direct, simulated_groups), context,
        )
        return current_score, simulated_score, violations

    def simulate_user(self, username, add_policies=(), remove_policies=(), add_groups=(), remove_groups=()):
        _, simulated_score, violations = self.compare_simulation(
            username, add_policies, remove_policies, add_groups, remove_groups
        )
        return simulated_score, violations

    def _identity_permissions(self, username, context):
        user_trie = PermissionTrie()
        allows = defaultdict(set)
        denies = set()
        origins = {}
        for edge in self.graph.get_edges_from(f"user:{username}"):
            policy_id = edge["target"]
            policy_name = policy_id.removeprefix("policy:")
            origins[policy_name] = edge["metadata"]
            for p_edge in self.graph.get_edges_from(policy_id):
                metadata = p_edge["metadata"]
                grants = _grants(
                    policy_name, metadata["actions"], [p_edge["target"].removeprefix("resource:")],
                    metadata["conditions"], metadata["not_actions"], metadata["not_resources"], context,
                )
                allowed = p_edge["type"] == "ALLOWS"
                for grant in grants:
                    if allowed:
                        user_trie.insert(grant.resource, [grant.action])
                        allows[grant.resource, grant.action].add(grant)
                    else:
                        denies.add(grant)
        return user_trie, allows, denies, origins

    @staticmethod
    def _selectors(selector):
        if selector != "*" and "/" not in selector and not selector.startswith("arn:"):
            return selector, f"{selector}/*"
        return (selector,)

    @staticmethod
    def _match(grant, action, resource, denies, global_only=False, scope=None, template_exceptions=()):
        if not patterns_overlap(grant.action, action) or not patterns_overlap(grant.resource, resource):
            return False
        rule_pattern = _pair(action, resource)
        grant_pattern = _pair(grant.action, grant.resource)
        required = (rule_pattern, grant_pattern)
        exceptions = grant.exceptions + template_exceptions
        if action in BUCKET_ACTIONS:
            exceptions += (_pair(action, "*/*"),)
        elif action in OBJECT_ACTIONS and scope is None:
            scope = "?*/?*"
        if scope:
            required += (_pair(action, scope),)

        applicable = [
            deny for deny in denies
            if patterns_overlap(deny.action, action)
            and patterns_overlap(deny.action, grant.action)
            and patterns_overlap(deny.resource, resource)
            and patterns_overlap(deny.resource, grant.resource)
            and (scope is None or patterns_overlap(deny.resource, scope))
        ]
        confirmed = tuple(sorted({(_pair(d.action, d.resource), d.exceptions)
                                  for d in applicable if d.decision is True}))
        possible = tuple(sorted({(_pair(d.action, d.resource), d.exceptions)
                                 for d in applicable if d.decision is None}))
        if global_only:
            if has_uncovered_match((rule_pattern,), ((grant_pattern, grant.exceptions),)):
                return False
            if any(has_uncovered_match((rule_pattern, pattern), exceptions=excluded)
                   for pattern, excluded in confirmed):
                return False
            unknown_deny = any(has_uncovered_match((rule_pattern, pattern), exceptions=excluded)
                               for pattern, excluded in possible)
            return None if grant.decision is None or unknown_deny else True
        if (scope or confirmed or exceptions) and not has_uncovered_match(required, confirmed, exceptions):
            return False
        if grant.decision is None or (possible and not has_uncovered_match(required, confirmed + possible, exceptions)):
            return None
        return True

    def _anonymous_permissions(self, context):
        context = {
            **context, "aws:principaltype": "Anonymous", "aws:username": "", "aws:userid": "",
        }
        permissions = {}
        for bucket, policy in self.bucket_policy_snapshot[0].items():
            allows, denies = set(), set()
            for statement in policy_statements(policy):
                if not _anonymous_principal(statement.get("Principal")):
                    continue
                effect = statement.get("Effect")
                if effect not in ("Allow", "Deny"):
                    continue
                not_actions = as_list(statement.get("NotAction"))
                not_resources = as_list(statement.get("NotResource"))
                actions = as_list(statement.get("Action")) or (["s3:*"] if not_actions else [])
                arns = as_list(statement.get("Resource")) or (["*"] if not_resources else [])
                resources = [arn.removeprefix("arn:aws:s3:::") for arn in arns
                             if arn == "*" or arn.startswith("arn:aws:s3:::")]
                grants = _grants(
                    statement.get("Sid") or "Bucket policy", actions, resources, statement.get("Condition", {}),
                    not_actions, [arn.removeprefix("arn:aws:s3:::") for arn in not_resources], context,
                )
                (allows if effect == "Allow" else denies).update(grants)
            permissions[bucket] = allows, denies
        return permissions

    def _public_evidence(self, rule, anonymous):
        evidence = {}
        selector = rule["resource_pattern"].removeprefix("arn:aws:s3:::")
        for bucket, (allows, denies) in anonymous.items():
            for grant in allows:
                for action, scope in (("s3:ListBucket", bucket), ("s3:GetObject", f"{bucket}/?*")):
                    if not any(patterns_overlap(action, risky) for risky in rule["risky_actions"]):
                        continue
                    for resource in self._selectors(selector):
                        decision = self._match(grant, action, resource, denies, scope=scope)
                        if decision is False:
                            continue
                        key = bucket, grant.policy, action, grant.resource, grant.exceptions
                        conditional = decision is None and evidence.get(key, {}).get("conditional", True)
                        evidence[key] = {
                            "policy": grant.policy, "bucket": bucket, "action": action,
                            "resource": grant.resource, "direct": False, "groups": [],
                            "conditional": conditional,
                            **grant.evidence_exceptions(),
                        }
        return [evidence[key] for key in sorted(evidence)]

    def _rule_selectors(self, rule, context):
        if rule.get("policy"):
            statements = policy_statements(rule["policy"])
            by_effect = defaultdict(set)
            for statement in statements:
                by_effect[statement["Effect"]].update(
                    _grants("", **statement_scope(statement), context=context)
                )
            if any(statement["Effect"] == "Allow" for statement in statements):
                return by_effect["Allow"], by_effect["Deny"]
            return by_effect["Deny"], set()

        selector = rule["resource_pattern"].removeprefix("arn:aws:s3:::")
        resources = ("*",) if rule["require_global_grant"] else self._selectors(selector)
        return {
            Grant(action, resource, "", True) for resource in resources for action in rule["risky_actions"]
        }, set()

    def _identity_evidence(self, rule, trie, allows, denies, origins, context):
        evidence = {}
        selectors, template_denies = self._rule_selectors(rule, context)
        denied = denies | template_denies
        for selector in selectors:
            for pattern, actions in trie.matching_grants(selector.resource):
                for action in actions:
                    for grant in allows[pattern, action]:
                        decision = self._match(
                            grant, selector.action, selector.resource, denied,
                            rule["require_global_grant"], template_exceptions=selector.exceptions,
                        )
                        if decision is False:
                            continue
                        key = pattern, action, grant.policy, grant.exceptions
                        matched_scope = {}
                        if rule.get("policy"):
                            key += (selector.action, selector.resource, selector.exceptions)
                            matched_scope = {"matched_action": selector.action, "matched_resource": selector.resource}
                        conditional = (decision is None or selector.decision is None) and evidence.get(
                            key, {}
                        ).get("conditional", True)
                        evidence[key] = {
                            "policy": grant.policy, "resource": pattern, "action": action,
                            "direct": origins[grant.policy].get("direct", False),
                            "groups": origins[grant.policy].get("groups", []),
                            "conditional": conditional,
                            **grant.evidence_exceptions(),
                            **matched_scope,
                        }
        return [evidence[key] for key in sorted(evidence)]

    def _calculate_risk_score(self, username, context):
        identity = self._identity_permissions(username, context)
        anonymous = self._anonymous_permissions(context)
        violations = []
        rules = self.risk_rules["risk_rules"]
        for rule in rules:
            evidence = (
                self._public_evidence(rule, anonymous) if _public_rule(rule)
                else self._identity_evidence(rule, *identity, context)
            )
            if evidence:
                violations.append({
                    "rule": rule["description"],
                    "resource": rule.get("resource_pattern") or "IAM policy scope",
                    "severity": rule.get("severity", 10),
                    "actual_allowed_actions": sorted({grant["action"] for grant in evidence}),
                    "evidence": evidence,
                })
        total = sum(rule.get("severity", 10) for rule in rules)
        return round(100 * sum(row["severity"] for row in violations) / total, 2) if total else 0, violations

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
