"""
atlas.utils.aws
~~~~~~~~~~~~~~~
Shared AWS helpers: async session factory, paginator wrapper, error handling.

All AWS SDK interaction flows through here -- no direct boto3 imports in
the recon collectors or executor actions.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aioboto3
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

import structlog

from atlas.core.config import AWSConfig

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# User agent — identify Atlas in CloudTrail / request logs
# ---------------------------------------------------------------------------
def _get_atlas_user_agent() -> str:
    """Return Atlas user agent string for API requests."""
    try:
        from importlib.metadata import version
        v = version("atlas-redteam")
        return f"Atlas/{v}"
    except Exception:
        return "Atlas/2.0.0"


def _apply_atlas_user_agent(
    session: boto3.Session | aioboto3.Session,
    user_agent_extra: str | None = None,
) -> None:
    """Set user agent on session so all clients use it.

    Args:
        session: boto3 or aioboto3 session
        user_agent_extra: Override from config. None = use Atlas default;
            '' = stealth mode (no extra, avoid GuardDuty Pentest findings);
            non-empty = use as-is.
    """
    if user_agent_extra is not None and user_agent_extra == "":
        # Stealth mode: don't add Atlas identifier (avoids GuardDuty Pentest
        # findings for tool signatures; see hackingthe.cloud/guardduty-pentest)
        return
    extra = user_agent_extra if user_agent_extra is not None else _get_atlas_user_agent()
    botocore_session = getattr(session, "_session", None)
    if botocore_session and hasattr(botocore_session, "set_default_client_config"):
        config = Config(user_agent_extra=extra)
        botocore_session.set_default_client_config(config)


# ---------------------------------------------------------------------------
# Session factories
# ---------------------------------------------------------------------------
def create_sync_session(config: AWSConfig) -> boto3.Session:
    """Create a synchronous boto3 session from config."""
    kwargs: dict[str, Any] = {}
    if config.profile:
        kwargs["profile_name"] = config.profile
    if config.region:
        kwargs["region_name"] = config.region
    if config.access_key_id and config.secret_access_key:
        kwargs["aws_access_key_id"] = config.access_key_id
        kwargs["aws_secret_access_key"] = config.secret_access_key
        if config.session_token:
            kwargs["aws_session_token"] = config.session_token
    session = boto3.Session(**kwargs)
    _apply_atlas_user_agent(session, getattr(config, "user_agent_extra", None))
    return session


def create_async_session(config: AWSConfig) -> aioboto3.Session:
    """Create an async aioboto3 session from config."""
    kwargs: dict[str, Any] = {}
    if config.profile:
        kwargs["profile_name"] = config.profile
    if config.region:
        kwargs["region_name"] = config.region
    if config.access_key_id and config.secret_access_key:
        kwargs["aws_access_key_id"] = config.access_key_id
        kwargs["aws_secret_access_key"] = config.secret_access_key
        if config.session_token:
            kwargs["aws_session_token"] = config.session_token
    session = aioboto3.Session(**kwargs)
    _apply_atlas_user_agent(session, getattr(config, "user_agent_extra", None))
    return session


# ---------------------------------------------------------------------------
# Caller identity
# ---------------------------------------------------------------------------
async def get_caller_identity(session: aioboto3.Session) -> dict[str, str] | None:
    """Async: get STS caller identity.  Returns None on failure."""
    try:
        async with session.client("sts") as sts:
            resp = await sts.get_caller_identity()
            return {
                "Account": resp["Account"],
                "Arn": resp["Arn"],
                "UserId": resp["UserId"],
            }
    except (ClientError, NoCredentialsError) as exc:
        logger.warning("caller_identity_failed", error=str(exc))
        return None


# ---------------------------------------------------------------------------
# Async paginator helper
# ---------------------------------------------------------------------------
async def async_paginate(
    client: Any,
    method: str,
    result_key: str,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Paginate an AWS API and return all items under *result_key*.

    Usage::

        async with session.client("iam") as iam:
            users = await async_paginate(iam, "list_users", "Users")
    """
    items: list[dict[str, Any]] = []
    paginator = client.get_paginator(method)
    async for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


# ---------------------------------------------------------------------------
# Safe API call wrapper
# ---------------------------------------------------------------------------
async def safe_api_call(
    coro: Any,
    *,
    default: Any = None,
    error_msg: str = "API call failed",
) -> Any:
    """Await *coro* and return result; on ClientError return *default*."""
    try:
        return await coro
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        logger.debug(error_msg, error_code=error_code, error=str(exc))
        return default
    except NoCredentialsError:
        logger.error("no_credentials")
        return default
