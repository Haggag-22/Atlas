"""
atlas.planner.detection
~~~~~~~~~~~~~~~~~~~~~~~
Detection cost scoring engine.

Combines static API profiles from the knowledge base with dynamic
adjustments based on the account's actual logging posture.

Example:
  - If CloudTrail is disabled → management event detection scores drop ~60%
  - If GuardDuty is active → actions that trigger GuardDuty findings get a boost
  - If data events are off → S3 GetObject detection drops to near-zero
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.models import DetectionProfile, LoggingState
from atlas.core.types import CloudTrailVisibility, NoiseLevel
from atlas.knowledge.api_profiles import get_profile, load_api_profiles

logger = structlog.get_logger(__name__)


class DetectionScorer:
    """Score the detection risk of AWS API actions.

    Instantiated once per operation with the account's logging posture.
    All detection cost calculations go through this scorer.
    """

    def __init__(self, logging_state: LoggingState) -> None:
        self._logging = logging_state
        self._profiles = load_api_profiles()
        self._adjustments = self._compute_adjustments()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def score(self, api_action: str) -> float:
        """Return the adjusted detection score for *api_action*.

        Returns a value between 0.0 (invisible) and 1.0 (certain detection).
        """
        profile = self._profiles.get(api_action)
        if not profile:
            return 0.5  # conservative default for unknown actions

        base = profile.base_detection_score
        adjusted = base * self._get_multiplier(profile)
        return min(1.0, max(0.0, adjusted))

    def score_action_sequence(self, api_actions: list[str]) -> float:
        """Score a sequence of API actions.  Returns cumulative cost."""
        return sum(self.score(a) for a in api_actions)

    def get_noise_level(self, api_action: str) -> NoiseLevel:
        """Return the noise level after adjustment."""
        score = self.score(api_action)
        if score < 0.05:
            return NoiseLevel.SILENT
        if score < 0.20:
            return NoiseLevel.LOW
        if score < 0.50:
            return NoiseLevel.MEDIUM
        if score < 0.75:
            return NoiseLevel.HIGH
        return NoiseLevel.CRITICAL

    def is_guardduty_risk(self, api_action: str) -> bool:
        """Check if action can trigger GuardDuty when GuardDuty is active."""
        if not self._logging.guardduty.is_enabled:
            return False
        profile = self._profiles.get(api_action)
        if not profile:
            return False
        return len(profile.guardduty_finding_types) > 0

    def get_profile(self, api_action: str) -> DetectionProfile | None:
        """Get the full detection profile for an action."""
        return self._profiles.get(api_action)

    def explain(self, api_action: str) -> dict[str, Any]:
        """Return a human-readable explanation of the detection score."""
        profile = self._profiles.get(api_action)
        if not profile:
            return {
                "api_action": api_action,
                "known": False,
                "score": 0.5,
                "explanation": "Unknown API action — using conservative default score.",
            }

        base = profile.base_detection_score
        multiplier = self._get_multiplier(profile)
        adjusted = min(1.0, max(0.0, base * multiplier))

        factors: list[str] = []
        if not self._logging.has_active_cloudtrail:
            factors.append("CloudTrail is INACTIVE — management event visibility reduced")
        if not self._logging.has_data_events and profile.cloudtrail_visibility in (
            CloudTrailVisibility.DATA_READ, CloudTrailVisibility.DATA_WRITE,
        ):
            factors.append("Data events are OFF — data plane calls have reduced visibility")
        if self._logging.guardduty.is_enabled and profile.guardduty_finding_types:
            factors.append(
                f"GuardDuty is ACTIVE — may trigger: {', '.join(profile.guardduty_finding_types)}"
            )
        if self._logging.security_hub_enabled:
            factors.append("SecurityHub is enabled — aggregated detection correlation")
        if self._logging.access_analyzer_enabled and profile.is_mutating:
            factors.append("Access Analyzer is active — permission changes may be flagged")

        return {
            "api_action": api_action,
            "known": True,
            "base_score": base,
            "multiplier": round(multiplier, 3),
            "adjusted_score": round(adjusted, 4),
            "noise_level": self.get_noise_level(api_action).value,
            "is_read_only": profile.is_read_only,
            "cloudtrail_visibility": profile.cloudtrail_visibility.value,
            "guardduty_risk": self.is_guardduty_risk(api_action),
            "factors": factors,
            "behavioral_notes": profile.behavioral_notes,
        }

    # ------------------------------------------------------------------
    # Internal: compute environment-based multipliers
    # ------------------------------------------------------------------
    def _compute_adjustments(self) -> dict[str, float]:
        """Pre-compute adjustment multipliers based on logging posture."""
        adjustments: dict[str, float] = {}

        # CloudTrail posture
        if self._logging.has_active_cloudtrail:
            adjustments["cloudtrail_management"] = 1.0
        else:
            # No active CloudTrail → management events are less visible
            adjustments["cloudtrail_management"] = 0.4

        if self._logging.has_data_events:
            adjustments["cloudtrail_data"] = 1.0
        else:
            adjustments["cloudtrail_data"] = 0.15

        # GuardDuty posture
        if self._logging.guardduty.is_enabled:
            adjustments["guardduty"] = 1.3  # boost score for GD-triggering actions
        else:
            adjustments["guardduty"] = 0.7  # reduce since GD won't catch it

        # SecurityHub / Config correlation
        if self._logging.security_hub_enabled:
            adjustments["securityhub"] = 1.1
        else:
            adjustments["securityhub"] = 1.0

        # Access Analyzer
        if self._logging.access_analyzer_enabled:
            adjustments["access_analyzer"] = 1.1
        else:
            adjustments["access_analyzer"] = 1.0

        return adjustments

    def _get_multiplier(self, profile: DetectionProfile) -> float:
        """Compute the combined multiplier for a specific profile."""
        multiplier = 1.0

        # CloudTrail visibility adjustment
        visibility = profile.cloudtrail_visibility
        if visibility in (
            CloudTrailVisibility.MANAGEMENT_READ,
            CloudTrailVisibility.MANAGEMENT_WRITE,
        ):
            multiplier *= self._adjustments.get("cloudtrail_management", 1.0)
        elif visibility in (
            CloudTrailVisibility.DATA_READ,
            CloudTrailVisibility.DATA_WRITE,
        ):
            multiplier *= self._adjustments.get("cloudtrail_data", 1.0)
        elif visibility == CloudTrailVisibility.NOT_LOGGED:
            multiplier *= 0.1  # nearly invisible

        # GuardDuty boost for actions that trigger findings
        if profile.guardduty_finding_types:
            multiplier *= self._adjustments.get("guardduty", 1.0)

        # SecurityHub correlation
        if profile.is_mutating:
            multiplier *= self._adjustments.get("securityhub", 1.0)
            multiplier *= self._adjustments.get("access_analyzer", 1.0)

        return multiplier
