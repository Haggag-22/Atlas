"""Identity discovery: list users, roles, account info (T1078 - Cloud accounts)."""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from atlas.core.plugin import TechniquePlugin, TechniqueResult
from atlas.core.state import CampaignState
from atlas.plugins.base_aws import (
    apply_rate_limit,
    ensure_safe_account_and_region,
    get_boto_session,
    get_caller_identity,
    record_telemetry,
)


class IdentityDiscoveryPlugin(TechniquePlugin):
    """Discover IAM users and current account identity."""

    @property
    def id(self) -> str:
        return "identity_discovery"

    @property
    def name(self) -> str:
        return "Identity Discovery"

    @property
    def description(self) -> str:
        return "List IAM users and get caller identity for the current account."

    @property
    def mitre_technique(self) -> str:
        return "T1078"

    @property
    def required_permissions(self) -> list[str]:
        return ["iam:ListUsers", "iam:GetUser", "sts:GetCallerIdentity"]

    def execute(
        self,
        state: CampaignState,
        parameters: dict[str, Any],
        config: Any = None,
    ) -> TechniqueResult:
        if not config:
            return TechniqueResult(success=False, error="Config required")
        session = get_boto_session(config)
        region = config.aws_region
        identity = get_caller_identity(session)
        if not identity:
            record_telemetry("identity_discovery", "sts:GetCallerIdentity", result="failure", error="Failed")
            return TechniqueResult(success=False, error="Could not get caller identity")
        account_id = identity.get("Account", "")
        ok, msg = ensure_safe_account_and_region(config, account_id, region)
        if not ok:
            return TechniqueResult(success=False, error=msg)
        record_telemetry("identity_discovery", "sts:GetCallerIdentity", service="sts", region=region, result="success")
        apply_rate_limit(config)
        iam = session.client("iam")
        users: list[dict[str, Any]] = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for u in page.get("Users", []):
                    apply_rate_limit(config)
                    record_telemetry(
                        "identity_discovery",
                        "iam:ListUsers",
                        service="iam",
                        resource_arn=u.get("Arn"),
                        result="success",
                    )
                    users.append({
                        "user_name": u.get("UserName"),
                        "user_id": u.get("UserId"),
                        "arn": u.get("Arn"),
                        "create_date": u.get("CreateDate", "").isoformat() if u.get("CreateDate") else None,
                    })
        except ClientError as e:
            record_telemetry("identity_discovery", "iam:ListUsers", result="failure", error=str(e))
            return TechniqueResult(
                success=False,
                error=str(e),
                outputs={"caller_identity": identity, "account_id": account_id, "users": users},
            )
        account_alias = _get_account_alias(iam, config)
        return TechniqueResult(
            success=True,
            message=f"Discovered {len(users)} users in account {account_id}",
            outputs={
                "caller_identity": identity,
                "account_id": account_id,
                "account_alias": account_alias,
                "users": users,
                "accounts": [{
                    "account_id": account_id,
                    "account_alias": account_alias,
                    "source": "identity_discovery",
                }],
            },
            resources=[{"resource_type": "iam_user", "identifier": u.get("UserName", ""), "arn": u.get("Arn")} for u in users],
        )


def _get_account_alias(iam: Any, config: Any) -> str | None:
    try:
        apply_rate_limit(config)
        aliases = iam.list_account_aliases().get("AccountAliases", [])
        return aliases[0] if aliases else None
    except ClientError:
        return None
