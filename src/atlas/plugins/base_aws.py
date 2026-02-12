"""Base helpers for AWS technique plugins: session, safety, telemetry."""

import random
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from atlas.core.config import AtlasConfig
from atlas.core.safety import check_account_allowed, check_region_allowed
from atlas.telemetry.recorder import get_recorder


def get_boto_session(config: AtlasConfig) -> boto3.Session:
    """Build boto3 session from config (profile, region)."""
    return boto3.Session(
        profile_name=config.aws_profile,
        region_name=config.aws_region,
    )


def get_caller_identity(session: boto3.Session) -> dict[str, Any] | None:
    """Get current caller identity; returns None on failure."""
    try:
        sts = session.client("sts")
        return sts.get_caller_identity()
    except ClientError:
        return None


def ensure_safe_account_and_region(
    config: AtlasConfig,
    account_id: str,
    region: str,
) -> tuple[bool, str]:
    """Return (True, '') if allowed; else (False, reason)."""
    if not check_account_allowed(account_id, config.safety):
        return False, f"Account {account_id} not in allowlist"
    if not check_region_allowed(region, config.safety):
        return False, f"Region {region} not in allowlist"
    return True, ""


def record_telemetry(
    actor: str,
    aws_api: str,
    *,
    service: str = "",
    resource_arn: str | None = None,
    region: str | None = None,
    result: str = "success",
    error: str | None = None,
) -> None:
    get_recorder().record(
        actor=actor,
        aws_api=aws_api,
        service=service,
        resource_arn=resource_arn,
        region=region,
        result=result,
        error=error,
    )


def apply_rate_limit(config: AtlasConfig) -> None:
    """Sleep for rate limit + jitter (call between API calls)."""
    rate = config.safety.rate_limit_per_second
    jitter = config.safety.jitter_seconds
    time.sleep(1.0 / rate + random.uniform(0, jitter))
