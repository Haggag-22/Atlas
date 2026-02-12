"""Permission enumeration: list attached policies for users/roles (T1069)."""

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


class PermissionEnumerationPlugin(TechniquePlugin):
    """Enumerate IAM policies attached to users and roles."""

    @property
    def id(self) -> str:
        return "permission_enumeration"

    @property
    def name(self) -> str:
        return "Permission Enumeration"

    @property
    def description(self) -> str:
        return "List managed and inline policies attached to IAM users and roles."

    @property
    def mitre_technique(self) -> str:
        return "T1069"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "iam:ListUsers",
            "iam:ListRoles",
            "iam:ListAttachedUserPolicies",
            "iam:ListAttachedRolePolicies",
            "iam:ListUserPolicies",
            "iam:ListRolePolicies",
            "sts:GetCallerIdentity",
        ]

    def get_input_schema(self) -> dict[str, Any]:
        return {"role_prefix": {"type": "string", "description": "Optional filter by role name prefix"}}

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
            return TechniqueResult(success=False, error="Could not get caller identity")
        account_id = identity.get("Account", "")
        ok, msg = ensure_safe_account_and_region(config, account_id, region)
        if not ok:
            return TechniqueResult(success=False, error=msg)
        role_prefix = (parameters.get("role_prefix") or "").strip() or None
        iam = session.client("iam")
        result_data: dict[str, Any] = {"users": [], "roles": []}
        # Users
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for u in page.get("Users", []):
                    apply_rate_limit(config)
                    attached = iam.list_attached_user_policies(UserName=u["UserName"])
                    inline = iam.list_user_policies(UserName=u["UserName"])
                    record_telemetry("permission_enumeration", "iam:ListAttachedUserPolicies", service="iam", resource_arn=u.get("Arn"))
                    result_data["users"].append({
                        "user_name": u["UserName"],
                        "arn": u["Arn"],
                        "attached_policies": [p["PolicyName"] for p in attached.get("AttachedPolicies", [])],
                        "inline_policies": inline.get("PolicyNames", []),
                    })
        except ClientError as e:
            return TechniqueResult(success=False, error=str(e), outputs=result_data)
        # Roles
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for r in page.get("Roles", []):
                    if role_prefix and not r["RoleName"].startswith(role_prefix):
                        continue
                    apply_rate_limit(config)
                    attached = iam.list_attached_role_policies(RoleName=r["RoleName"])
                    inline = iam.list_role_policies(RoleName=r["RoleName"])
                    record_telemetry("permission_enumeration", "iam:ListAttachedRolePolicies", service="iam", resource_arn=r.get("Arn"))
                    result_data["roles"].append({
                        "role_name": r["RoleName"],
                        "arn": r["Arn"],
                        "attached_policies": [p["PolicyName"] for p in attached.get("AttachedPolicies", [])],
                        "inline_policies": inline.get("PolicyNames", []),
                    })
        except ClientError as e:
            return TechniqueResult(success=False, error=str(e), outputs=result_data)
        return TechniqueResult(
            success=True,
            message=f"Enumerated permissions for {len(result_data['users'])} users and {len(result_data['roles'])} roles",
            outputs=result_data,
        )
