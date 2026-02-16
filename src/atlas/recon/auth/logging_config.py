"""
atlas.recon.auth.logging_config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers the account's logging and detection posture:
  - CloudTrail trails and their status
  - GuardDuty detectors
  - AWS Config recorder status
  - SecurityHub enabled standards
  - IAM Access Analyzer

This data directly impacts the Planner's detection cost scoring:
if CloudTrail is disabled, detection costs drop.  If GuardDuty is
active with S3 protection, S3-related attack paths become riskier.
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.models import CloudTrailConfig, GuardDutyConfig, LoggingState
from atlas.knowledge.api_profiles import get_detection_score
from atlas.recon.base import BaseCollector
from atlas.utils.aws import safe_api_call

logger = structlog.get_logger(__name__)


class LoggingConfigCollector(BaseCollector):
    """Discover the account's logging and detection posture."""

    @property
    def collector_id(self) -> str:
        return "logging_config"

    @property
    def description(self) -> str:
        return "Discover CloudTrail, GuardDuty, Config, SecurityHub, Access Analyzer status."

    @property
    def required_permissions(self) -> list[str]:
        return [
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
            "guardduty:ListDetectors",
            "guardduty:GetDetector",
            "config:DescribeConfigurationRecorders",
            "securityhub:GetEnabledStandards",
            "access-analyzer:ListAnalyzers",
        ]

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        logging_state = LoggingState()

        # ── CloudTrail ─────────────────────────────────────────────
        trails = await self._collect_cloudtrail(region)
        logging_state.cloudtrail_trails = trails

        # ── GuardDuty ──────────────────────────────────────────────
        gd_config = await self._collect_guardduty(region)
        logging_state.guardduty = gd_config

        # ── AWS Config ─────────────────────────────────────────────
        logging_state.config_recorder_enabled = await self._check_config_recorder(region)

        # ── SecurityHub ────────────────────────────────────────────
        logging_state.security_hub_enabled = await self._check_security_hub(region)

        # ── Access Analyzer ────────────────────────────────────────
        logging_state.access_analyzer_enabled = await self._check_access_analyzer(region)

        stats = {
            "cloudtrail_trails": len(trails),
            "cloudtrail_active": logging_state.has_active_cloudtrail,
            "cloudtrail_data_events": logging_state.has_data_events,
            "guardduty_enabled": gd_config.is_enabled,
            "config_recorder": logging_state.config_recorder_enabled,
            "security_hub": logging_state.security_hub_enabled,
            "access_analyzer": logging_state.access_analyzer_enabled,
        }

        logger.info("logging_config_collection_complete", **stats)
        return {**stats, "logging_state": logging_state.model_dump()}

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------
    async def _collect_cloudtrail(self, region: str) -> list[CloudTrailConfig]:
        trails: list[CloudTrailConfig] = []
        async with self._session.client("cloudtrail", region_name=region) as ct:
            resp = await safe_api_call(
                ct.describe_trails(),
                default={"trailList": []},
            )
            self._record("cloudtrail:DescribeTrails",
                         detection_cost=get_detection_score("cloudtrail:DescribeTrails"))

            for raw in (resp or {}).get("trailList", []):
                trail_arn = raw.get("TrailARN", "")

                # Get trail status
                status_resp = await safe_api_call(
                    ct.get_trail_status(Name=trail_arn),
                    default={},
                )
                self._record("cloudtrail:GetTrailStatus",
                             detection_cost=get_detection_score("cloudtrail:GetTrailStatus"))
                is_logging = (status_resp or {}).get("IsLogging", False)

                # Get event selectors
                selectors_resp = await safe_api_call(
                    ct.get_event_selectors(TrailName=trail_arn),
                    default={},
                )
                event_selectors = (selectors_resp or {}).get("EventSelectors", [])
                # Also check advanced event selectors
                advanced = (selectors_resp or {}).get("AdvancedEventSelectors", [])
                data_selectors = event_selectors + advanced

                trails.append(CloudTrailConfig(
                    trail_name=raw.get("Name", ""),
                    trail_arn=trail_arn,
                    is_multi_region=raw.get("IsMultiRegionTrail", False),
                    is_organization_trail=raw.get("IsOrganizationTrail", False),
                    is_logging=is_logging,
                    has_log_file_validation=raw.get("LogFileValidationEnabled", False),
                    s3_bucket_name=raw.get("S3BucketName"),
                    cloudwatch_log_group_arn=raw.get("CloudWatchLogsLogGroupArn"),
                    include_management_events=True,  # default for most trails
                    data_event_selectors=data_selectors,
                ))

        return trails

    # ------------------------------------------------------------------
    # GuardDuty
    # ------------------------------------------------------------------
    async def _collect_guardduty(self, region: str) -> GuardDutyConfig:
        async with self._session.client("guardduty", region_name=region) as gd:
            list_resp = await safe_api_call(
                gd.list_detectors(),
                default={"DetectorIds": []},
            )
            self._record("guardduty:ListDetectors",
                         detection_cost=get_detection_score("guardduty:ListDetectors"))

            detector_ids = (list_resp or {}).get("DetectorIds", [])
            if not detector_ids:
                return GuardDutyConfig()

            detector_id = detector_ids[0]
            detail_resp = await safe_api_call(
                gd.get_detector(DetectorId=detector_id),
                default={},
            )
            self._record("guardduty:GetDetector",
                         detection_cost=get_detection_score("guardduty:GetDetector"))

            if not detail_resp:
                return GuardDutyConfig(detector_id=detector_id)

            # Check feature statuses
            features = detail_resp.get("Features", [])
            s3_protection = any(
                f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED"
                for f in features
            )
            eks_protection = any(
                f.get("Name") in ("EKS_AUDIT_LOGS", "EKS_RUNTIME_MONITORING")
                and f.get("Status") == "ENABLED"
                for f in features
            )
            malware_protection = any(
                f.get("Name") == "EBS_MALWARE_PROTECTION" and f.get("Status") == "ENABLED"
                for f in features
            )

            return GuardDutyConfig(
                detector_id=detector_id,
                is_enabled=detail_resp.get("Status") == "ENABLED",
                s3_protection=s3_protection,
                eks_protection=eks_protection,
                malware_protection=malware_protection,
            )

    # ------------------------------------------------------------------
    # AWS Config
    # ------------------------------------------------------------------
    async def _check_config_recorder(self, region: str) -> bool:
        async with self._session.client("config", region_name=region) as cfg:
            resp = await safe_api_call(
                cfg.describe_configuration_recorders(),
                default={"ConfigurationRecorders": []},
            )
            self._record("config:DescribeConfigurationRecorders",
                         detection_cost=get_detection_score("config:DescribeConfigurationRecorders"))
            recorders = (resp or {}).get("ConfigurationRecorders", [])
            return len(recorders) > 0

    # ------------------------------------------------------------------
    # SecurityHub
    # ------------------------------------------------------------------
    async def _check_security_hub(self, region: str) -> bool:
        async with self._session.client("securityhub", region_name=region) as sh:
            resp = await safe_api_call(
                sh.get_enabled_standards(),
                default=None,
            )
            self._record("securityhub:GetEnabledStandards",
                         detection_cost=get_detection_score("securityhub:GetEnabledStandards"))
            if resp is None:
                return False
            return len(resp.get("StandardsSubscriptions", [])) > 0

    # ------------------------------------------------------------------
    # Access Analyzer
    # ------------------------------------------------------------------
    async def _check_access_analyzer(self, region: str) -> bool:
        async with self._session.client("accessanalyzer", region_name=region) as aa:
            resp = await safe_api_call(
                aa.list_analyzers(),
                default={"analyzers": []},
            )
            self._record("access-analyzer:ListAnalyzers",
                         detection_cost=get_detection_score("access-analyzer:ListAnalyzers"))
            analyzers = (resp or {}).get("analyzers", [])
            return len(analyzers) > 0
