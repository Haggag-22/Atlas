"""
atlas.recon.collectors.trust
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Analyses role trust policies to build CAN_ASSUME / TRUSTS edges.

This collector reads trust policy documents already stored on ROLE nodes
(populated by the identity collector) and creates the graph edges that
the planner uses for role-chain traversal.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from atlas.core.types import EdgeType, NodeType
from atlas.recon.base import BaseCollector

logger = structlog.get_logger(__name__)


class TrustCollector(BaseCollector):
    """Analyze trust policies and build assumption edges."""

    @property
    def collector_id(self) -> str:
        return "trust"

    @property
    def description(self) -> str:
        return "Analyze role trust policies to build CAN_ASSUME edges."

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        stats = {
            "roles_analyzed": 0,
            "trust_edges": 0,
            "wildcard_trusts": 0,
            "cross_account_trusts": 0,
            "service_trusts": 0,
            "federated_trusts": 0,
        }

        role_nodes = self._graph.nodes_of_type(NodeType.ROLE)

        for role_arn in role_nodes:
            data = self._graph.get_node_data(role_arn)
            trust_policy = data.get("trust_policy", {})
            if not trust_policy:
                continue

            stats["roles_analyzed"] += 1
            statements = trust_policy.get("Statement", [])

            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue

                principal = stmt.get("Principal", {})
                conditions = stmt.get("Condition", {})

                edges = self._extract_trust_edges(
                    role_arn, principal, conditions, account_id, stats,
                )
                for source, edge_type, meta in edges:
                    self._graph.add_edge(
                        source, role_arn, edge_type,
                        conditions=meta.get("conditions", {}),
                        metadata=meta,
                    )
                    stats["trust_edges"] += 1

        logger.info("trust_collection_complete", **stats)
        return stats

    # ------------------------------------------------------------------
    # Trust policy parsing
    # ------------------------------------------------------------------
    def _extract_trust_edges(
        self,
        role_arn: str,
        principal: Any,
        conditions: dict[str, Any],
        account_id: str,
        stats: dict[str, int],
    ) -> list[tuple[str, EdgeType, dict[str, Any]]]:
        """Parse a Principal block and return (source, edge_type, metadata) tuples."""
        edges: list[tuple[str, EdgeType, dict[str, Any]]] = []

        if isinstance(principal, str) and principal == "*":
            # Wildcard trust — anyone can assume
            stats["wildcard_trusts"] += 1
            edges.append((
                f"arn:aws:iam::*:root",
                EdgeType.CAN_ASSUME,
                {"trust_type": "wildcard", "conditions": conditions, "risk": "critical"},
            ))
            return edges

        if isinstance(principal, dict):
            # AWS principals
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for p in aws_principals:
                meta: dict[str, Any] = {"conditions": conditions}

                if p == "*":
                    stats["wildcard_trusts"] += 1
                    meta["trust_type"] = "wildcard"
                    meta["risk"] = "critical"
                    edges.append((f"arn:aws:iam::*:root", EdgeType.CAN_ASSUME, meta))
                elif ":root" in p:
                    # Account-level trust (any identity in that account)
                    target_account = self._extract_account_id(p)
                    if target_account and target_account != account_id:
                        stats["cross_account_trusts"] += 1
                        meta["trust_type"] = "cross_account"
                    else:
                        meta["trust_type"] = "same_account_root"
                    edges.append((p, EdgeType.CAN_ASSUME, meta))
                else:
                    # Specific role/user ARN
                    target_account = self._extract_account_id(p)
                    if target_account and target_account != account_id:
                        stats["cross_account_trusts"] += 1
                        meta["trust_type"] = "cross_account_specific"
                    else:
                        meta["trust_type"] = "same_account_specific"
                    # Ensure the trusted principal exists as a node
                    if not self._graph.has_node(p):
                        node_type = NodeType.ROLE if ":role/" in p else NodeType.USER
                        self._graph.add_node(p, node_type, label=p.split("/")[-1])
                    edges.append((p, EdgeType.CAN_ASSUME, meta))

            # Service principals
            service_principals = principal.get("Service", [])
            if isinstance(service_principals, str):
                service_principals = [service_principals]

            for svc in service_principals:
                stats["service_trusts"] += 1
                svc_arn = f"service::{svc}"
                if not self._graph.has_node(svc_arn):
                    self._graph.add_node(svc_arn, NodeType.ACCOUNT, label=svc)
                edges.append((
                    svc_arn, EdgeType.CAN_ASSUME,
                    {"trust_type": "service", "service": svc, "conditions": conditions},
                ))

            # Federated principals
            federated = principal.get("Federated", [])
            if isinstance(federated, str):
                federated = [federated]

            for fed in federated:
                stats["federated_trusts"] += 1
                fed_arn = f"federated::{fed}"
                if not self._graph.has_node(fed_arn):
                    self._graph.add_node(fed_arn, NodeType.ACCOUNT, label=fed)
                edges.append((
                    fed_arn, EdgeType.CAN_ASSUME,
                    {"trust_type": "federated", "provider": fed, "conditions": conditions},
                ))

        return edges

    @staticmethod
    def _extract_account_id(arn: str) -> str | None:
        """Extract 12-digit account ID from an ARN."""
        match = re.search(r":(\d{12}):", arn)
        return match.group(1) if match else None
