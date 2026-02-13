"""Tests for atlas.core.graph — EnvironmentGraph."""

from atlas.core.graph import EnvironmentGraph
from atlas.core.types import EdgeType, NodeType


def test_add_and_get_node():
    g = EnvironmentGraph()
    g.add_node("arn:aws:iam::123:user/alice", NodeType.USER, label="alice")
    assert g.has_node("arn:aws:iam::123:user/alice")
    assert g.node_count == 1
    node = g.get_node("arn:aws:iam::123:user/alice")
    assert node["node_type"] == "iam_user"
    assert node["label"] == "alice"


def test_nodes_of_type():
    g = EnvironmentGraph()
    g.add_node("arn:aws:iam::123:user/alice", NodeType.USER)
    g.add_node("arn:aws:iam::123:role/admin", NodeType.ROLE)
    g.add_node("arn:aws:iam::123:user/bob", NodeType.USER)

    users = g.nodes_of_type(NodeType.USER)
    assert len(users) == 2
    roles = g.nodes_of_type(NodeType.ROLE)
    assert len(roles) == 1


def test_add_and_get_edge():
    g = EnvironmentGraph()
    g.add_node("u1", NodeType.USER)
    g.add_node("r1", NodeType.ROLE)
    g.add_edge("u1", "r1", EdgeType.CAN_ASSUME, detection_cost=0.15)

    assert g.has_edge("u1", "r1")
    edge = g.get_edge("u1", "r1")
    assert edge["edge_type"] == "can_assume"
    assert edge["detection_cost"] == 0.15


def test_edges_of_type():
    g = EnvironmentGraph()
    g.add_node("u1", NodeType.USER)
    g.add_node("r1", NodeType.ROLE)
    g.add_node("p1", NodeType.POLICY)
    g.add_edge("u1", "r1", EdgeType.CAN_ASSUME)
    g.add_edge("u1", "p1", EdgeType.HAS_POLICY)

    assume_edges = g.edges_of_type(EdgeType.CAN_ASSUME)
    assert len(assume_edges) == 1
    assert assume_edges[0][0] == "u1"
    assert assume_edges[0][1] == "r1"


def test_serialization_roundtrip():
    g = EnvironmentGraph()
    g.add_node("u1", NodeType.USER, data={"name": "alice"})
    g.add_node("r1", NodeType.ROLE)
    g.add_edge("u1", "r1", EdgeType.CAN_ASSUME, detection_cost=0.2)

    data = g.to_dict()
    g2 = EnvironmentGraph.from_dict(data)
    assert g2.node_count == 2
    assert g2.edge_count == 1
    assert g2.has_edge("u1", "r1")


def test_shortest_path():
    g = EnvironmentGraph()
    g.add_node("a", NodeType.USER)
    g.add_node("b", NodeType.ROLE)
    g.add_node("c", NodeType.ROLE)
    g.add_edge("a", "b", EdgeType.CAN_ASSUME)
    g.add_edge("b", "c", EdgeType.CAN_ASSUME)

    path = g.shortest_path("a", "c")
    assert path == ["a", "b", "c"]


def test_path_weight():
    g = EnvironmentGraph()
    g.add_node("a", NodeType.USER)
    g.add_node("b", NodeType.ROLE)
    g.add_node("c", NodeType.ROLE)
    g.add_edge("a", "b", EdgeType.CAN_ASSUME, detection_cost=0.1)
    g.add_edge("b", "c", EdgeType.CAN_ASSUME, detection_cost=0.3)

    weight = g.path_weight(["a", "b", "c"])
    assert abs(weight - 0.4) < 0.001
