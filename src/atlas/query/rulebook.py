"""
atlas.query.rulebook
~~~~~~~~~~~~~~~~~~~
Load edge rulebook with evidence + detection mapping.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_DATA_DIR = Path(__file__).parent.parent / "knowledge" / "data"
_RULEBOOK_PATH = _DATA_DIR / "edge_rulebook.yaml"


@lru_cache(maxsize=1)
def load_edge_rulebook() -> list[dict[str, Any]]:
    """Load the consolidated edge rulebook."""
    if not _RULEBOOK_PATH.exists():
        return []
    raw = yaml.safe_load(_RULEBOOK_PATH.read_text())
    return raw.get("rules", [])


def get_detection_for_edge(edge_type: str) -> dict[str, Any]:
    """Return detection mapping for an edge type.

    Returns dict with: cloudtrail_events, guardduty_findings, detection_notes, remediation.
    """
    rules = load_edge_rulebook()
    for r in rules:
        if r.get("edge_type") == edge_type:
            return {
                "cloudtrail_events": r.get("cloudtrail_events", []),
                "guardduty_findings": r.get("guardduty_findings", []),
                "detection_notes": r.get("detection_notes", ""),
                "remediation": r.get("remediation", ""),
                "confidence": r.get("confidence", "unknown"),
                "evidence_fields": r.get("evidence_fields", []),
            }
    return {
        "cloudtrail_events": [],
        "guardduty_findings": [],
        "detection_notes": "",
        "remediation": "",
        "confidence": "unknown",
        "evidence_fields": [],
    }


def get_all_edge_detections() -> dict[str, dict[str, Any]]:
    """Return detection mapping for all edge types in the rulebook."""
    rules = load_edge_rulebook()
    return {r["edge_type"]: get_detection_for_edge(r["edge_type"]) for r in rules}
