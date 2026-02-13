"""
atlas.planner.path_finder
~~~~~~~~~~~~~~~~~~~~~~~~~
Graph traversal algorithms over the AttackGraph.

Three optimization objectives:
  1. Shortest path      — fewest hops (fastest escalation)
  2. Quietest path      — lowest cumulative detection cost (stealthiest)
  3. Most reliable path — highest product of success probabilities

The planner selects the algorithm based on strategy and noise budget.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import networkx as nx
import structlog

from atlas.core.models import AttackEdge
from atlas.planner.attack_graph import AttackGraph

logger = structlog.get_logger(__name__)


@dataclass
class AttackPath:
    """A scored path through the attack graph."""
    nodes: list[str]
    edges: list[dict[str, Any]]
    total_detection_cost: float = 0.0
    total_success_probability: float = 1.0
    hop_count: int = 0
    noise_levels: list[str] = field(default_factory=list)
    path_type: str = ""  # "shortest" | "quietest" | "most_reliable"

    @property
    def is_viable(self) -> bool:
        return self.hop_count > 0 and self.total_success_probability > 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "path_type": self.path_type,
            "hops": self.hop_count,
            "nodes": self.nodes,
            "detection_cost": round(self.total_detection_cost, 4),
            "success_probability": round(self.total_success_probability, 4),
            "noise_levels": self.noise_levels,
        }


class PathFinder:
    """Find optimal attack paths in the AttackGraph."""

    def __init__(self, attack_graph: AttackGraph) -> None:
        self._ag = attack_graph
        self._g = attack_graph.raw

    # ------------------------------------------------------------------
    # Algorithm 1: Shortest path (fewest hops)
    # ------------------------------------------------------------------
    def shortest_path(self, source: str, target: str) -> AttackPath | None:
        """Find the path with fewest hops (unweighted BFS)."""
        try:
            nodes = nx.shortest_path(self._g, source, target)
            return self._build_path(nodes, "shortest")
        except nx.NetworkXNoPath:
            return None
        except nx.NodeNotFound:
            return None

    # ------------------------------------------------------------------
    # Algorithm 2: Quietest path (lowest detection cost — Dijkstra)
    # ------------------------------------------------------------------
    def quietest_path(self, source: str, target: str) -> AttackPath | None:
        """Find the path with lowest cumulative detection cost."""
        try:
            nodes = nx.dijkstra_path(
                self._g, source, target, weight="detection_cost",
            )
            return self._build_path(nodes, "quietest")
        except nx.NetworkXNoPath:
            return None
        except nx.NodeNotFound:
            return None

    # ------------------------------------------------------------------
    # Algorithm 3: Most reliable path (highest success probability)
    # ------------------------------------------------------------------
    def most_reliable_path(self, source: str, target: str) -> AttackPath | None:
        """Find the path that maximizes the product of success probabilities.

        Since Dijkstra minimizes, we transform: weight = -log(probability).
        Minimizing -log(p) maximizes the product of probabilities.
        """
        try:
            nodes = nx.dijkstra_path(
                self._g, source, target,
                weight=lambda u, v, d: self._reliability_weight(d),
            )
            return self._build_path(nodes, "most_reliable")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    # ------------------------------------------------------------------
    # All paths (for comprehensive analysis)
    # ------------------------------------------------------------------
    def all_paths(
        self,
        source: str,
        target: str,
        *,
        max_depth: int = 6,
        max_paths: int = 20,
    ) -> list[AttackPath]:
        """Find all simple paths, sorted by detection cost (quietest first)."""
        paths: list[AttackPath] = []
        try:
            for node_path in nx.all_simple_paths(self._g, source, target, cutoff=max_depth):
                path = self._build_path(list(node_path), "all")
                if path and path.is_viable:
                    paths.append(path)
                if len(paths) >= max_paths:
                    break
        except nx.NodeNotFound:
            pass

        # Sort by detection cost (quietest first)
        paths.sort(key=lambda p: p.total_detection_cost)
        return paths

    # ------------------------------------------------------------------
    # Find all reachable targets from a source
    # ------------------------------------------------------------------
    def reachable_targets(
        self,
        source: str,
        *,
        max_depth: int = 4,
    ) -> list[dict[str, Any]]:
        """Find all nodes reachable from *source* within *max_depth* hops."""
        if not self._g.has_node(source):
            return []

        results: list[dict[str, Any]] = []
        visited: set[str] = set()

        for target in self._g.nodes():
            if target == source or target in visited:
                continue
            path = self.quietest_path(source, target)
            if path and path.is_viable and path.hop_count <= max_depth:
                visited.add(target)
                results.append({
                    "target": target,
                    "hops": path.hop_count,
                    "detection_cost": round(path.total_detection_cost, 4),
                    "success_probability": round(path.total_success_probability, 4),
                })

        results.sort(key=lambda r: r["detection_cost"])
        return results

    # ------------------------------------------------------------------
    # Path scoring (compare arbitrary paths)
    # ------------------------------------------------------------------
    def score_path(
        self,
        nodes: list[str],
        *,
        noise_budget: float = 10.0,
    ) -> dict[str, Any]:
        """Score an arbitrary path for viability."""
        path = self._build_path(nodes, "custom")
        if not path:
            return {"viable": False, "reason": "Invalid path"}

        within_budget = path.total_detection_cost <= noise_budget

        return {
            "viable": path.is_viable and within_budget,
            "hops": path.hop_count,
            "detection_cost": round(path.total_detection_cost, 4),
            "success_probability": round(path.total_success_probability, 4),
            "within_noise_budget": within_budget,
            "noise_budget_usage": round(path.total_detection_cost / noise_budget, 2) if noise_budget > 0 else 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _build_path(self, nodes: list[str], path_type: str) -> AttackPath | None:
        """Construct an AttackPath from a list of node ARNs."""
        if len(nodes) < 2:
            return None

        edges: list[dict[str, Any]] = []
        total_cost = 0.0
        total_prob = 1.0
        noise_levels: list[str] = []

        for i in range(len(nodes) - 1):
            u, v = nodes[i], nodes[i + 1]
            if not self._g.has_edge(u, v):
                return None
            data = dict(self._g.edges[u, v])
            edges.append(data)
            total_cost += data.get("detection_cost", 0.0)
            total_prob *= data.get("success_probability", 1.0)
            noise_levels.append(data.get("noise_level", "medium"))

        return AttackPath(
            nodes=nodes,
            edges=edges,
            total_detection_cost=total_cost,
            total_success_probability=total_prob,
            hop_count=len(nodes) - 1,
            noise_levels=noise_levels,
            path_type=path_type,
        )

    @staticmethod
    def _reliability_weight(edge_data: dict[str, Any]) -> float:
        """Transform success probability to a Dijkstra-compatible weight."""
        prob = edge_data.get("success_probability", 0.01)
        prob = max(prob, 0.001)  # avoid log(0)
        return -math.log(prob)
