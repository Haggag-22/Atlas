"""
atlas.query.engine
~~~~~~~~~~~~~~~~~~
QueryEngine — BloodHound-style queries over persisted attack graphs.

Loads case from output/<case>/plan/, rebuilds AttackGraph from attack_edges,
and runs path/exposure/hygiene queries.
"""

from __future__ import annotations

from typing import Any

from atlas.core.cases import load_case
from atlas.core.models import AttackEdge
from atlas.core.types import NodeType
from atlas.planner.attack_graph import AttackGraph
from atlas.planner.path_finder import PathFinder


class QueryEngine:
    """Run BloodHound-style queries on a persisted case."""

    def __init__(
        self,
        env_model: Any,
        attack_edges: list[AttackEdge],
        source_identity: str,
    ) -> None:
        self.env_model = env_model
        self.attack_edges = attack_edges
        self.source_identity = source_identity
        self._ag = self._build_graph()

    def _build_graph(self) -> AttackGraph:
        """Rebuild AttackGraph from persisted edges."""
        ag = AttackGraph()
        for edge in self.attack_edges:
            ag.add_edge(edge)
        return ag

    @classmethod
    def from_case(cls, case_name: str) -> QueryEngine:
        """Load a case and build the query engine."""
        data = load_case(case_name)
        return cls(
            env_model=data["env_model"],
            attack_edges=data["attack_edges"],
            source_identity=data.get("source_identity", data["env_model"].metadata.caller_arn),
        )

    @property
    def attack_graph(self) -> AttackGraph:
        return self._ag

    @property
    def root_arn(self) -> str:
        """Account root ARN for this case."""
        account_id = self.env_model.metadata.account_id
        return f"arn:aws:iam::{account_id}:root"

    # -------------------------------------------------------------------------
    # Path queries
    # -------------------------------------------------------------------------

    def who_can_reach_admin(self, max_paths: int = 20) -> list[dict[str, Any]]:
        """Find principals that can reach account root (admin).

        Returns list of {source, path, hops, detection_cost, success_probability}.
        """
        finder = PathFinder(self._ag)
        root = self.root_arn
        if not self._ag.raw.has_node(root):
            return []

        results: list[dict[str, Any]] = []
        sources = set(e.source_arn for e in self.attack_edges)
        for src in sources:
            if src == root:
                continue
            path = finder.quietest_path(src, root)
            if path and path.is_viable:
                results.append({
                    "source": src,
                    "target": root,
                    "hops": path.hop_count,
                    "detection_cost": round(path.total_detection_cost, 4),
                    "success_probability": round(path.total_success_probability, 4),
                    "path_summary": " → ".join(n.split("/")[-1] if "/" in n else n.split(":")[-1] for n in path.nodes),
                    "path_nodes": path.nodes,
                    "path_edges": [(path.nodes[i], path.nodes[i + 1]) for i in range(len(path.nodes) - 1)],
                })

        results.sort(key=lambda r: (r["hops"], r["detection_cost"]))
        return results[:max_paths]

    def shortest_path_to_admin(self, source: str | None = None) -> dict[str, Any] | None:
        """Shortest path from source (or default identity) to root."""
        src = source or self.source_identity
        finder = PathFinder(self._ag)
        root = self.root_arn
        path = finder.shortest_path(src, root)
        if not path or not path.is_viable:
            return None
        return {
            "source": src,
            "target": root,
            "hops": path.hop_count,
            "detection_cost": round(path.total_detection_cost, 4),
            "success_probability": round(path.total_success_probability, 4),
            "path_summary": " → ".join(n.split("/")[-1] if "/" in n else n.split(":")[-1] for n in path.nodes),
            "path_nodes": path.nodes,
            "path_edges": [(path.nodes[i], path.nodes[i + 1]) for i in range(len(path.nodes) - 1)],
        }

    def blast_radius(self, principal: str, max_depth: int = 4) -> list[dict[str, Any]]:
        """What is reachable from principal (exposure query)."""
        finder = PathFinder(self._ag)
        return finder.reachable_targets(principal, max_depth=max_depth)

    # -------------------------------------------------------------------------
    # Hygiene queries (from env_model)
    # -------------------------------------------------------------------------

    def external_trusts(self) -> list[dict[str, Any]]:
        """Roles with trust policies allowing external principals (other accounts or *)."""
        results: list[dict[str, Any]] = []
        account_id = self.env_model.metadata.account_id
        roles = self.env_model.graph.nodes_of_type(NodeType.ROLE)

        for role_arn in roles:
            data = self.env_model.graph.get_node_data(role_arn)
            trust = data.get("trust_policy") or {}
            for stmt in trust.get("Statement", []):
                principals = stmt.get("Principal", {})
                if isinstance(principals, str):
                    principals = {"AWS": principals} if principals == "*" else {}
                for key, val in (principals or {}).items():
                    if key not in ("AWS", "Federated", "Service"):
                        continue
                    vals = val if isinstance(val, list) else [val]
                    for p in vals:
                        if p == "*":
                            results.append({
                                "role_arn": role_arn,
                                "principal": "*",
                                "statement": stmt.get("Sid", "default"),
                            })
                            break
                        if isinstance(p, str) and ":" in p:
                            if key in ("Federated", "Service"):
                                results.append({
                                    "role_arn": role_arn,
                                    "principal": p,
                                    "statement": stmt.get("Sid", "default"),
                                })
                                break
                            if key == "AWS" and account_id not in p:
                                results.append({
                                    "role_arn": role_arn,
                                    "principal": p,
                                    "statement": stmt.get("Sid", "default"),
                                })
                                break

        return results

    def wildcard_permissions(self) -> list[dict[str, Any]]:
        """Identities with wildcard actions or resources in their policies."""
        results: list[dict[str, Any]] = []
        pmap = self.env_model.permission_map

        for arn, profile in pmap._profiles.items():
            # Check allow_statements for wildcards
            for stmt in profile.allow_statements:
                actions = stmt.actions or []
                resources = stmt.resources or []
                if "*" in actions or "iam:*" in actions or any(":*" in str(a) for a in actions):
                    results.append({
                        "identity": arn,
                        "type": "wildcard_action",
                        "actions": actions[:5],
                        "source": "policy",
                    })
                    break
                if "*" in resources:
                    results.append({
                        "identity": arn,
                        "type": "wildcard_resource",
                        "resources": resources[:5],
                        "source": "policy",
                    })
                    break
            else:
                # Check permissions dict
                for action, entry in profile.permissions.items():
                    if "*" in action or "iam:*" in action or ":*" in action:
                        results.append({
                            "identity": arn,
                            "type": "wildcard_action",
                            "actions": [action],
                            "source": entry.source.value if hasattr(entry.source, "value") else str(entry.source),
                        })
                        break
                    if "*" in (entry.resource_arns or []):
                        results.append({
                            "identity": arn,
                            "type": "wildcard_resource",
                            "resources": entry.resource_arns[:5] if entry.resource_arns else ["*"],
                            "source": entry.source.value if hasattr(entry.source, "value") else str(entry.source),
                        })
                        break

        return results

    def privileged_unused_principals(self) -> list[dict[str, Any]]:
        """Principals with privileged permissions (escalation-capable)."""
        results: list[dict[str, Any]] = []
        privileged_actions = {
            "iam:CreateAccessKey", "iam:AttachRolePolicy", "iam:PutRolePolicy",
            "iam:UpdateAssumeRolePolicy", "iam:PassRole", "iam:CreateUser",
        }
        pmap = self.env_model.permission_map

        for arn, profile in pmap._profiles.items():
            has_priv = False
            for action in profile.permissions:
                if action in privileged_actions or action == "iam:*":
                    has_priv = True
                    break
            if not has_priv:
                for stmt in profile.allow_statements:
                    for a in (stmt.actions or []):
                        if a in privileged_actions or a == "iam:*":
                            has_priv = True
                            break
                    if has_priv:
                        break
            if has_priv:
                data = self.env_model.graph.get_node_data(arn) if self.env_model.graph.has_node(arn) else {}
                last_used = data.get("password_last_used") or data.get("create_date") or "unknown"
                results.append({
                    "identity": arn,
                    "last_used": last_used,
                    "note": "Has privilege escalation permissions",
                })

        return results[:50]  # Limit output
