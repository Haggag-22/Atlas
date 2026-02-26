"""
atlas.query
~~~~~~~~~~~
BloodHound-style query engine for persisted attack graphs.

Loads cases from output/<case>/plan/ and runs:
  - Path queries (who can reach admin, shortest path)
  - Exposure queries (blast radius)
  - Hygiene queries (external trusts, wildcards, unused principals)
  - Detection mapping (CloudTrail + GuardDuty per edge)
"""

from atlas.query.engine import QueryEngine
from atlas.query.rulebook import load_edge_rulebook, get_detection_for_edge

__all__ = [
    "QueryEngine",
    "load_edge_rulebook",
    "get_detection_for_edge",
]
