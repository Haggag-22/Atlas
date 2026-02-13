"""
atlas.knowledge.api_profiles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Loader for the API detection profiles knowledge base.

Reads ``data/api_detection_profiles.yaml`` and ``data/guardduty_findings.yaml``
and exposes them as typed lookup structures.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from atlas.core.models import DetectionProfile
from atlas.core.types import CloudTrailVisibility, NoiseLevel

_DATA_DIR = Path(__file__).parent / "data"


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def load_api_profiles() -> dict[str, DetectionProfile]:
    """Load all API detection profiles keyed by ``api_action``."""
    path = _DATA_DIR / "api_detection_profiles.yaml"
    raw = yaml.safe_load(path.read_text())
    profiles: dict[str, DetectionProfile] = {}
    for entry in raw.get("profiles", []):
        profile = DetectionProfile(
            api_action=entry["api_action"],
            service=entry.get("service", ""),
            cloudtrail_visibility=CloudTrailVisibility(entry.get("cloudtrail_visibility", "management_write")),
            is_read_only=entry.get("is_read_only", False),
            guardduty_finding_types=entry.get("guardduty_finding_types", []),
            base_detection_score=entry.get("base_detection_score", 0.5),
            noise_level=NoiseLevel(entry.get("noise_level", "medium")),
            is_mutating=entry.get("is_mutating", True),
            behavioral_notes=entry.get("behavioral_notes", ""),
        )
        profiles[profile.api_action] = profile
    return profiles


@lru_cache(maxsize=1)
def load_guardduty_findings() -> dict[str, dict[str, Any]]:
    """Load GuardDuty finding definitions keyed by ``finding_type``."""
    path = _DATA_DIR / "guardduty_findings.yaml"
    raw = yaml.safe_load(path.read_text())
    findings: dict[str, dict[str, Any]] = {}
    for entry in raw.get("findings", []):
        findings[entry["finding_type"]] = entry
    return findings


def get_detection_score(api_action: str) -> float:
    """Quick lookup: return base detection score for an API action.

    Returns 0.5 (medium) for unknown actions — conservative default.
    """
    profiles = load_api_profiles()
    profile = profiles.get(api_action)
    return profile.base_detection_score if profile else 0.5


def get_profile(api_action: str) -> DetectionProfile | None:
    """Return the full ``DetectionProfile`` for an API action, or ``None``."""
    return load_api_profiles().get(api_action)


def get_noise_level(api_action: str) -> NoiseLevel:
    """Return noise level for an API action."""
    profiles = load_api_profiles()
    profile = profiles.get(api_action)
    return profile.noise_level if profile else NoiseLevel.MEDIUM


def is_guardduty_trigger(api_action: str) -> bool:
    """Check if an API action can trigger any GuardDuty finding."""
    profiles = load_api_profiles()
    profile = profiles.get(api_action)
    if not profile:
        return False
    return len(profile.guardduty_finding_types) > 0


def get_all_services() -> list[str]:
    """Return list of unique AWS service names in the knowledge base."""
    profiles = load_api_profiles()
    return sorted({p.service for p in profiles.values() if p.service})
