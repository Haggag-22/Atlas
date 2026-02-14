"""
atlas.recon.collectors.identity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers IAM users, roles, groups, and instance profiles.

Populates:
  - USER, ROLE, GROUP nodes in the graph
  - MEMBER_OF edges (user → group)
  - CREDENTIAL_FOR edges (access key → user)
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

import structlog

from atlas.core.graph import EnvironmentGraph
from atlas.core.models import IAMGroup, IAMRole, IAMUser
from atlas.core.types import EdgeType, NodeType
from atlas.knowledge.api_profiles import get_detection_score
from atlas.recon.base import BaseCollector
from atlas.utils.aws import async_paginate, safe_api_call
from atlas.utils.key_decoder import classify_key

logger = structlog.get_logger(__name__)


class IdentityCollector(BaseCollector):
    """Discover IAM identities and their relationships."""

    @property
    def collector_id(self) -> str:
        return "identity"

    @property
    def description(self) -> str:
        return "Discover IAM users, roles, groups, and access keys."

    @property
    def required_permissions(self) -> list[str]:
        return [
            "iam:ListUsers", "iam:ListRoles", "iam:ListGroups",
            "iam:ListAccessKeys", "iam:ListMFADevices",
            "iam:ListGroupsForUser", "iam:GetUser", "iam:GetRole",
        ]

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        stats = {"users": 0, "roles": 0, "groups": 0, "access_keys": 0}

        async with self._session.client("iam") as iam:
            # ── Users ──────────────────────────────────────────────
            raw_users = await async_paginate(iam, "list_users", "Users")
            self._record("iam:ListUsers", detection_cost=get_detection_score("iam:ListUsers"))

            for raw in raw_users:
                user = await self._enrich_user(iam, raw, account_id)
                self._add_user_to_graph(user)
                stats["users"] += 1
                stats["access_keys"] += len(user.access_key_ids)

            # ── Roles ──────────────────────────────────────────────
            raw_roles = await async_paginate(iam, "list_roles", "Roles")
            self._record("iam:ListRoles", detection_cost=get_detection_score("iam:ListRoles"))

            for raw in raw_roles:
                role = self._parse_role(raw, account_id)
                self._add_role_to_graph(role)
                stats["roles"] += 1

            # ── Groups ─────────────────────────────────────────────
            raw_groups = await async_paginate(iam, "list_groups", "Groups")
            self._record("iam:ListGroups", detection_cost=get_detection_score("iam:ListGroups"))

            for raw in raw_groups:
                group = await self._enrich_group(iam, raw, account_id)
                self._add_group_to_graph(group)
                stats["groups"] += 1

        logger.info(
            "identity_collection_complete",
            **stats,
        )
        return stats

    # ------------------------------------------------------------------
    # User enrichment
    # ------------------------------------------------------------------
    async def _enrich_user(
        self, iam: Any, raw: dict[str, Any], account_id: str,
    ) -> IAMUser:
        user_name = raw["UserName"]

        # Access keys
        access_keys: list[str] = []
        ak_resp = await safe_api_call(
            iam.list_access_keys(UserName=user_name),
            default={"AccessKeyMetadata": []},
        )
        if ak_resp:
            access_keys = [k["AccessKeyId"] for k in ak_resp.get("AccessKeyMetadata", [])]
            self._record("iam:ListAccessKeys", target_arn=raw.get("Arn", ""),
                         detection_cost=get_detection_score("iam:ListAccessKeys"))

        # MFA
        has_mfa = False
        mfa_resp = await safe_api_call(
            iam.list_mfa_devices(UserName=user_name),
            default={"MFADevices": []},
        )
        if mfa_resp:
            has_mfa = len(mfa_resp.get("MFADevices", [])) > 0
            self._record("iam:ListMFADevices", target_arn=raw.get("Arn", ""),
                         detection_cost=get_detection_score("iam:ListMFADevices"))

        # Groups
        group_names: list[str] = []
        grp_resp = await safe_api_call(
            iam.list_groups_for_user(UserName=user_name),
            default={"Groups": []},
        )
        if grp_resp:
            group_names = [g["GroupName"] for g in grp_resp.get("Groups", [])]

        # Inline policies
        inline_resp = await safe_api_call(
            iam.list_user_policies(UserName=user_name),
            default={"PolicyNames": []},
        )
        inline_names = inline_resp.get("PolicyNames", []) if inline_resp else []
        self._record("iam:ListUserPolicies", target_arn=raw.get("Arn", ""),
                     detection_cost=get_detection_score("iam:ListUserPolicies"))

        # Attached policies
        attached_resp = await safe_api_call(
            iam.list_attached_user_policies(UserName=user_name),
            default={"AttachedPolicies": []},
        )
        attached_arns = [
            p["PolicyArn"] for p in (attached_resp or {}).get("AttachedPolicies", [])
        ]
        self._record("iam:ListAttachedUserPolicies", target_arn=raw.get("Arn", ""),
                     detection_cost=get_detection_score("iam:ListAttachedUserPolicies"))

        # Permission boundary
        pb = raw.get("PermissionsBoundary", {})
        pb_arn = pb.get("PermissionsBoundaryArn") if pb else None

        return IAMUser(
            arn=raw["Arn"],
            user_name=user_name,
            user_id=raw["UserId"],
            account_id=account_id,
            path=raw.get("Path", "/"),
            create_date=str(raw.get("CreateDate", "")),
            password_last_used=str(raw.get("PasswordLastUsed", "")) if raw.get("PasswordLastUsed") else None,
            has_console_access=raw.get("PasswordLastUsed") is not None,
            has_mfa=has_mfa,
            access_key_ids=access_keys,
            inline_policy_names=inline_names,
            attached_policy_arns=attached_arns,
            group_names=group_names,
            permission_boundary_arn=pb_arn,
            tags={t["Key"]: t["Value"] for t in raw.get("Tags", [])},
        )

    # ------------------------------------------------------------------
    # Role parsing
    # ------------------------------------------------------------------
    def _parse_role(self, raw: dict[str, Any], account_id: str) -> IAMRole:
        pb = raw.get("PermissionsBoundary", {})
        pb_arn = pb.get("PermissionsBoundaryArn") if pb else None

        return IAMRole(
            arn=raw["Arn"],
            role_name=raw["RoleName"],
            role_id=raw["RoleId"],
            account_id=account_id,
            path=raw.get("Path", "/"),
            trust_policy=raw.get("AssumeRolePolicyDocument", {}),
            permission_boundary_arn=pb_arn,
            max_session_duration=raw.get("MaxSessionDuration", 3600),
            is_service_linked=raw.get("Path", "").startswith("/aws-service-role/"),
            tags={t["Key"]: t["Value"] for t in raw.get("Tags", [])},
        )

    # ------------------------------------------------------------------
    # Group enrichment
    # ------------------------------------------------------------------
    async def _enrich_group(
        self, iam: Any, raw: dict[str, Any], account_id: str,
    ) -> IAMGroup:
        group_name = raw["GroupName"]

        members_resp = await safe_api_call(
            iam.get_group(GroupName=group_name),
            default={"Users": []},
        )
        member_arns = [u["Arn"] for u in (members_resp or {}).get("Users", [])]

        inline_resp = await safe_api_call(
            iam.list_group_policies(GroupName=group_name),
            default={"PolicyNames": []},
        )
        inline_names = (inline_resp or {}).get("PolicyNames", [])

        attached_resp = await safe_api_call(
            iam.list_attached_group_policies(GroupName=group_name),
            default={"AttachedPolicies": []},
        )
        attached_arns = [
            p["PolicyArn"] for p in (attached_resp or {}).get("AttachedPolicies", [])
        ]

        return IAMGroup(
            arn=raw["Arn"],
            group_name=group_name,
            group_id=raw["GroupId"],
            path=raw.get("Path", "/"),
            inline_policy_names=inline_names,
            attached_policy_arns=attached_arns,
            member_user_arns=member_arns,
        )

    # ------------------------------------------------------------------
    # Graph population
    # ------------------------------------------------------------------
    def _add_user_to_graph(self, user: IAMUser) -> None:
        self._graph.add_node(
            user.arn, NodeType.USER,
            data=user.model_dump(), label=user.user_name,
        )
        # User → Group membership edges
        for gname in user.group_names:
            group_arn = f"arn:aws:iam::{user.account_id}:group/{gname}"
            self._graph.add_edge(
                user.arn, group_arn, EdgeType.MEMBER_OF,
            )
        # Access key → User credential edges (with offline account ID decoding)
        for ak_id in user.access_key_ids:
            cred_arn = f"credential::{ak_id}"
            key_info = classify_key(ak_id)
            self._graph.add_node(
                cred_arn, NodeType.CREDENTIAL,
                label=ak_id,
                data={
                    "access_key_id": ak_id,
                    "prefix": key_info.prefix,
                    "prefix_description": key_info.prefix_description,
                    "decoded_account_id": key_info.account_id,
                    "is_temporary": key_info.is_temporary,
                    "is_long_lived": key_info.is_long_lived,
                    "is_new_format": key_info.is_new_format,
                    "owner_arn": user.arn,
                    "owner_account_id": user.account_id,
                    "is_cross_account": (
                        key_info.account_id is not None
                        and key_info.account_id != user.account_id
                    ),
                },
            )
            self._graph.add_edge(cred_arn, user.arn, EdgeType.CREDENTIAL_FOR)
        # Permission boundary edge
        if user.permission_boundary_arn:
            self._graph.add_edge(
                user.arn, user.permission_boundary_arn,
                EdgeType.HAS_PERMISSION_BOUNDARY,
            )

    def _add_role_to_graph(self, role: IAMRole) -> None:
        self._graph.add_node(
            role.arn, NodeType.ROLE,
            data=role.model_dump(), label=role.role_name,
        )
        if role.permission_boundary_arn:
            self._graph.add_edge(
                role.arn, role.permission_boundary_arn,
                EdgeType.HAS_PERMISSION_BOUNDARY,
            )

    def _add_group_to_graph(self, group: IAMGroup) -> None:
        self._graph.add_node(
            group.arn, NodeType.GROUP,
            data=group.model_dump(), label=group.group_name,
        )
        # Ensure member edges exist (may duplicate user-side, that's OK)
        for member_arn in group.member_user_arns:
            self._graph.add_edge(member_arn, group.arn, EdgeType.MEMBER_OF)
