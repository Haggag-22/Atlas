"""
atlas.planner.chain_finder
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers multi-hop attack chains through the attack graph.

A chain is an ordered sequence of edges: A → B → C.
Examples:
  - AssumeRole → then from that role, CreateAccessKey for another user
  - AssumeRole → then from that role, AssumeRole to a third role
  - ModifyTrust on RoleX → then AssumeRole to RoleX
  - AttachPolicy to self → then AssumeRole (which was previously blocked)

The ChainFinder uses the PathFinder's graph traversal but returns
structured AttackChain objects that the CLI can display and simulate.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from atlas.core.models import AttackChain, AttackEdge
from atlas.core.types import NoiseLevel
from atlas.planner.attack_graph import AttackGraph

logger = structlog.get_logger(__name__)

# Edge types that represent a credential pivot (you become a new identity)
_PIVOT_TYPES = {
    "can_assume",
    "can_create_key",
    "can_steal_imds_creds",  # IMDS theft gives you the role's credentials
    "can_ssm_session",       # SSM session gives shell + IMDS access to role
}

# Edge types that represent escalation (you gain more power as yourself or via target)
_ESCALATION_TYPES = {
    "can_attach_policy", "can_put_policy", "can_modify_trust",
    "can_passrole", "can_update_lambda", "can_modify_userdata",
}

# Edge types that are terminal (resource access, not identity pivot)
_TERMINAL_TYPES = {
    "can_read_s3", "can_write_s3",
    "can_snapshot_volume",  # volume loot is a terminal action
}


class ChainFinder:
    """Discovers multi-hop attack chains from a source identity."""

    def __init__(
        self,
        attack_graph: AttackGraph,
        *,
        max_depth: int = 4,
        max_chains: int = 50,
    ) -> None:
        self._ag = attack_graph
        self._max_depth = max_depth
        self._max_chains = max_chains

    def find_chains(self, source: str) -> list[AttackChain]:
        """Find all attack chains from *source*, both single-hop and multi-hop.

        Returns chains sorted by total detection cost (quietest first).
        """
        chains: list[AttackChain] = []
        seen_signatures: set[str] = set()

        # Build an edge lookup: source_arn → list[AttackEdge]
        edge_map: dict[str, list[AttackEdge]] = {}
        for e in self._ag.edges:
            edge_map.setdefault(e.source_arn, []).append(e)

        # DFS from source
        self._dfs(
            source=source,
            current_path=[],
            edge_map=edge_map,
            chains=chains,
            seen_signatures=seen_signatures,
            visited=set(),
            depth=0,
        )

        # Sort by detection cost, then hop count
        chains.sort(key=lambda c: (c.total_detection_cost, c.hop_count))

        return chains[:self._max_chains]

    def _dfs(
        self,
        source: str,
        current_path: list[AttackEdge],
        edge_map: dict[str, list[AttackEdge]],
        chains: list[AttackChain],
        seen_signatures: set[str],
        visited: set[str],
        depth: int,
    ) -> None:
        """DFS to discover chains."""
        if depth > self._max_depth:
            return
        if len(chains) >= self._max_chains:
            return

        outgoing = edge_map.get(source, [])
        if not outgoing:
            return

        # Deduplicate outgoing by (edge_type, target) keeping lowest cost
        best: dict[tuple[str, str], AttackEdge] = {}
        for e in outgoing:
            key = (e.edge_type.value, e.target_arn)
            if key not in best or e.detection_cost < best[key].detection_cost:
                best[key] = e

        for edge in best.values():
            if edge.target_arn in visited:
                continue

            new_path = current_path + [edge]
            edge_type = edge.edge_type.value

            # Every path is a valid chain (including single-hop)
            sig = self._chain_signature(new_path)
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                chains.append(self._build_chain(new_path))

            # Continue DFS only through pivot edges (assume role, create key)
            # Because after a pivot, you ARE the new identity and can act from it
            if edge_type in _PIVOT_TYPES and depth + 1 < self._max_depth:
                visited_copy = visited | {edge.target_arn}
                self._dfs(
                    source=edge.target_arn,
                    current_path=new_path,
                    edge_map=edge_map,
                    chains=chains,
                    seen_signatures=seen_signatures,
                    visited=visited_copy,
                    depth=depth + 1,
                )

    @staticmethod
    def _chain_signature(edges: list[AttackEdge]) -> str:
        """Unique signature for a chain to avoid duplicates."""
        parts = []
        for e in edges:
            parts.append(f"{e.edge_type.value}:{e.source_arn}:{e.target_arn}")
        return "|".join(parts)

    @staticmethod
    def _build_chain(edges: list[AttackEdge]) -> AttackChain:
        """Build an AttackChain from a list of edges."""
        total_cost = sum(e.detection_cost for e in edges)
        total_prob = 1.0
        for e in edges:
            total_prob *= e.success_probability

        # Build objective description
        if len(edges) == 1:
            objective = edges[0].notes or edges[0].edge_type.value
        else:
            first = edges[0].source_arn.split("/")[-1]
            last_target = edges[-1].target_arn
            last_name = last_target.split("/")[-1] if "/" in last_target else last_target.split(":")[-1]
            last_type = edges[-1].edge_type.value
            objective = f"{len(edges)}-step chain: {first} → ... → {last_name} ({last_type})"

        return AttackChain(
            chain_id=uuid.uuid4().hex[:8],
            edges=list(edges),
            total_detection_cost=round(total_cost, 4),
            total_success_probability=round(total_prob, 4),
            hop_count=len(edges),
            objective=objective,
        )
