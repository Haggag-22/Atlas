"""
atlas.executor.actions.sts
~~~~~~~~~~~~~~~~~~~~~~~~~~
STS actions: AssumeRole, GetSessionToken.

These are the lowest-noise privilege transition actions.
The planner preferentially routes through role assumption chains
because they generate minimal detection signal.
"""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

import structlog

from atlas.core.models import ActionResult, PlannedAction
from atlas.core.types import ActionStatus, Layer
from atlas.executor.base import BaseAction

logger = structlog.get_logger(__name__)


class AssumeRoleAction(BaseAction):
    """Execute sts:AssumeRole to pivot to a target role."""

    @property
    def action_type(self) -> str:
        return "assume_role"

    @property
    def description(self) -> str:
        return "Assume an IAM role via STS."

    @property
    def is_mutating(self) -> bool:
        return False  # AssumeRole doesn't modify state

    async def execute(self, planned: PlannedAction) -> ActionResult:
        start = time.monotonic()
        target_role_arn = planned.target_arn
        session_name = planned.parameters.get("session_name", "atlas-session")
        duration = planned.parameters.get("duration_seconds", 3600)
        external_id = planned.parameters.get("external_id")

        try:
            async with self._session.client("sts") as sts:
                kwargs: dict[str, Any] = {
                    "RoleArn": target_role_arn,
                    "RoleSessionName": session_name,
                    "DurationSeconds": duration,
                }
                if external_id:
                    kwargs["ExternalId"] = external_id

                resp = await sts.assume_role(**kwargs)

                self._recorder.record(
                    layer=Layer.EXECUTOR,
                    event_type="api_call",
                    action="sts:AssumeRole",
                    source_arn=planned.source_arn,
                    target_arn=target_role_arn,
                    status="success",
                    detection_cost=planned.detection_cost,
                )

                credentials = resp.get("Credentials", {})
                assumed_identity = resp.get("AssumedRoleUser", {})

                return ActionResult(
                    action_id=planned.action_id,
                    status=ActionStatus.SUCCESS.value,
                    message=f"Assumed role {target_role_arn}",
                    outputs={
                        "assumed_role_arn": assumed_identity.get("Arn", ""),
                        "assumed_role_id": assumed_identity.get("AssumedRoleId", ""),
                        "access_key_id": credentials.get("AccessKeyId", ""),
                        "secret_access_key": credentials.get("SecretAccessKey", ""),
                        "session_token": credentials.get("SessionToken", ""),
                        "expiration": str(credentials.get("Expiration", "")),
                    },
                    new_discoveries=[{
                        "type": "assumed_role",
                        "arn": assumed_identity.get("Arn", ""),
                        "role_arn": target_role_arn,
                    }],
                    actual_detection_cost=planned.detection_cost,
                    duration_seconds=time.monotonic() - start,
                )

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            error_msg = exc.response.get("Error", {}).get("Message", str(exc))

            self._recorder.record(
                layer=Layer.EXECUTOR,
                event_type="api_call",
                action="sts:AssumeRole",
                source_arn=planned.source_arn,
                target_arn=target_role_arn,
                status="failure",
                error=error_msg,
                detection_cost=planned.detection_cost,
            )

            status = ActionStatus.PERMISSION_DENIED if error_code == "AccessDenied" else ActionStatus.FAILURE

            return ActionResult(
                action_id=planned.action_id,
                status=status.value,
                message=f"Failed to assume {target_role_arn}",
                error=f"{error_code}: {error_msg}",
                actual_detection_cost=planned.detection_cost,
                duration_seconds=time.monotonic() - start,
            )
