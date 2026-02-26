"""
Atlas v2 — AWS Cloud Attack Path Mapping (BloodHound-style)

Two-layer architecture for attack path discovery and simulation:
  Layer 1 (Recon):   Observe and model the AWS environment (read-only)
  Layer 2 (Planner): Build attack graphs, find paths, simulate — no execution
"""

__version__ = "2.0.0-alpha"
