"""
atlas.core.graph
~~~~~~~~~~~~~~~~
Typed wrapper around networkx.DiGraph for the EnvironmentModel.

This is the *single source of truth* for identity/resource relationships.
The Recon layer writes to it.  The Planner layer reads from it.
The Executor layer never touches it directly.

Node attributes:
    - node_type: NodeType
    - arn: str
    - data: dict  (the full model dict for that entity)

Edge attributes:
    - edge_type: EdgeType
    - detection_cost: float
    - success_probability: float
    - conditions: dict
    - metadata: dict
"""

from __future__ import annotations

import json
from typing import Any, Iterator

import networkx as nx

from atlas.core.types import EdgeType, NodeType


class EnvironmentGraph:
    """Typed directed graph representing the AWS account topology.

    Thin wrapper over ``nx.DiGraph`` that enforces node/edge attribute
    conventions so the rest of the codebase can rely on consistent access
    patterns.
    """

    def __init__(self) -> None:
        self._g: nx.DiGraph = nx.DiGraph()

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------
    def add_node(
        self,
        arn: str,
        node_type: NodeType,
        *,
        data: dict[str, Any] | None = None,
        label: str = "",
    ) -> None:
        """Add or update a node.  ``arn`` is the unique node ID."""
        self._g.add_node(
            arn,
            node_type=node_type.value,
            arn=arn,
            label=label or arn.split(":")[-1],
            data=data or {},
        )

    def has_node(self, arn: str) -> bool:
        return self._g.has_node(arn)

    def get_node(self, arn: str) -> dict[str, Any]:
        """Return the attribute dict for *arn*; raises ``KeyError`` if absent."""
        return dict(self._g.nodes[arn])

    def get_node_type(self, arn: str) -> NodeType:
        return NodeType(self._g.nodes[arn]["node_type"])

    def get_node_data(self, arn: str) -> dict[str, Any]:
        return self._g.nodes[arn].get("data", {})

    def nodes_of_type(self, node_type: NodeType) -> list[str]:
        """Return all ARNs whose ``node_type`` matches."""
        return [
            n for n, d in self._g.nodes(data=True)
            if d.get("node_type") == node_type.value
        ]

    @property
    def node_count(self) -> int:
        return self._g.number_of_nodes()

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------
    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        *,
        detection_cost: float = 0.0,
        success_probability: float = 1.0,
        conditions: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a directed edge.  Overwrites if same (source, target) exists."""
        self._g.add_edge(
            source,
            target,
            edge_type=edge_type.value,
            detection_cost=detection_cost,
            success_probability=success_probability,
            conditions=conditions or {},
            metadata=metadata or {},
        )

    def has_edge(self, source: str, target: str) -> bool:
        return self._g.has_edge(source, target)

    def get_edge(self, source: str, target: str) -> dict[str, Any]:
        return dict(self._g.edges[source, target])

    def edges_of_type(self, edge_type: EdgeType) -> list[tuple[str, str, dict[str, Any]]]:
        """Return all edges whose ``edge_type`` matches."""
        return [
            (u, v, dict(d))
            for u, v, d in self._g.edges(data=True)
            if d.get("edge_type") == edge_type.value
        ]

    def outgoing(self, arn: str) -> list[tuple[str, dict[str, Any]]]:
        """All outgoing edges from *arn* as (target, attrs) pairs."""
        return [(v, dict(d)) for _, v, d in self._g.out_edges(arn, data=True)]

    def incoming(self, arn: str) -> list[tuple[str, dict[str, Any]]]:
        """All incoming edges to *arn* as (source, attrs) pairs."""
        return [(u, dict(d)) for u, _, d in self._g.in_edges(arn, data=True)]

    @property
    def edge_count(self) -> int:
        return self._g.number_of_edges()

    # ------------------------------------------------------------------
    # Graph traversal helpers
    # ------------------------------------------------------------------
    def successors(self, arn: str) -> list[str]:
        return list(self._g.successors(arn))

    def predecessors(self, arn: str) -> list[str]:
        return list(self._g.predecessors(arn))

    def all_paths(
        self,
        source: str,
        target: str,
        *,
        max_depth: int = 6,
    ) -> Iterator[list[str]]:
        """Yield all simple paths from *source* to *target*."""
        yield from nx.all_simple_paths(self._g, source, target, cutoff=max_depth)

    def shortest_path(self, source: str, target: str) -> list[str]:
        """Shortest path by hop count; raises ``nx.NetworkXNoPath``."""
        return nx.shortest_path(self._g, source, target)

    def shortest_weighted_path(
        self,
        source: str,
        target: str,
        weight: str = "detection_cost",
    ) -> list[str]:
        """Dijkstra shortest path using *weight* attribute."""
        return nx.dijkstra_path(self._g, source, target, weight=weight)

    def path_weight(self, path: list[str], weight: str = "detection_cost") -> float:
        """Sum of *weight* along a path."""
        total = 0.0
        for i in range(len(path) - 1):
            edge_data = self._g.edges[path[i], path[i + 1]]
            total += edge_data.get(weight, 0.0)
        return total

    # ------------------------------------------------------------------
    # Subgraph extraction
    # ------------------------------------------------------------------
    def identity_subgraph(self) -> EnvironmentGraph:
        """Return a subgraph containing only identity nodes and their edges."""
        identity_types = {NodeType.USER.value, NodeType.ROLE.value, NodeType.GROUP.value}
        nodes = [n for n, d in self._g.nodes(data=True) if d.get("node_type") in identity_types]
        sub = EnvironmentGraph()
        sub._g = self._g.subgraph(nodes).copy()
        return sub

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    @property
    def raw(self) -> nx.DiGraph:
        """Escape hatch for advanced networkx operations."""
        return self._g

    def to_dict(self) -> dict[str, Any]:
        """Export as JSON-serializable dict (for state persistence / replay)."""
        return nx.node_link_data(self._g)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnvironmentGraph:
        """Reconstruct from ``to_dict()`` output."""
        g = cls()
        g._g = nx.node_link_graph(data, directed=True)
        return g

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def __repr__(self) -> str:
        return f"<EnvironmentGraph nodes={self.node_count} edges={self.edge_count}>"
