"""
atlas.recon.collectors.policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers IAM policies (managed + inline) and their documents.

Populates:
  - POLICY nodes in the graph
  - HAS_POLICY / HAS_INLINE_POLICY edges (identity → policy)
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.models import IAMPolicy
from atlas.core.types import EdgeType, NodeType
from atlas.knowledge.api_profiles import get_detection_score
from atlas.recon.base import BaseCollector
from atlas.utils.aws import async_paginate, safe_api_call

logger = structlog.get_logger(__name__)


class PolicyCollector(BaseCollector):
    """Discover IAM policies and their documents."""

    @property
    def collector_id(self) -> str:
        return "policy"

    @property
    def description(self) -> str:
        return "Discover managed and inline IAM policies."

    @property
    def required_permissions(self) -> list[str]:
        return [
            "iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
            "iam:GetUserPolicy", "iam:GetRolePolicy", "iam:GetGroupPolicy",
        ]

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        stats = {
            "managed_policies": 0, "aws_managed_policies": 0,
            "inline_policies": 0, "policy_documents": 0,
        }

        # Track all attached policy ARNs so we can fetch AWS-managed docs
        attached_policy_arns: set[str] = set()

        async with self._session.client("iam") as iam:
            # ── Customer-managed policies ──────────────────────────
            raw_policies = await async_paginate(
                iam, "list_policies", "Policies", Scope="Local",
            )
            self._record("iam:ListPolicies", detection_cost=get_detection_score("iam:ListPolicies"))

            for raw in raw_policies:
                policy = await self._enrich_managed_policy(iam, raw)
                if policy:
                    self._add_policy_to_graph(policy)
                    stats["managed_policies"] += 1
                    if policy.policy_document:
                        stats["policy_documents"] += 1

            # ── Inline policies on users ───────────────────────────
            user_nodes = self._graph.nodes_of_type(NodeType.USER)
            for user_arn in user_nodes:
                data = self._graph.get_node_data(user_arn)
                user_name = data.get("user_name", "")
                for pname in data.get("inline_policy_names", []):
                    doc = await self._get_inline_policy(iam, "user", user_name, pname)
                    if doc is not None:
                        policy = IAMPolicy(
                            policy_name=pname,
                            policy_document=doc,
                            is_inline=True,
                            attached_to=user_arn,
                        )
                        self._add_inline_policy(policy, user_arn)
                        stats["inline_policies"] += 1

                # Collect attached ARNs for later AWS-managed policy fetching
                for pa in data.get("attached_policy_arns", []):
                    attached_policy_arns.add(pa)
                    self._graph.add_edge(user_arn, pa, EdgeType.HAS_POLICY)

            # ── Inline policies on roles + attached policies ───────
            role_nodes = self._graph.nodes_of_type(NodeType.ROLE)
            for role_arn in role_nodes:
                data = self._graph.get_node_data(role_arn)
                role_name = data.get("role_name", "")

                # Inline policies for roles
                inline_resp = await safe_api_call(
                    iam.list_role_policies(RoleName=role_name),
                    default={"PolicyNames": []},
                )
                self._record("iam:ListRolePolicies", target_arn=role_arn,
                             detection_cost=get_detection_score("iam:ListRolePolicies"))
                inline_names = (inline_resp or {}).get("PolicyNames", [])

                for pname in inline_names:
                    doc = await self._get_inline_policy(iam, "role", role_name, pname)
                    if doc is not None:
                        policy = IAMPolicy(
                            policy_name=pname,
                            policy_document=doc,
                            is_inline=True,
                            attached_to=role_arn,
                        )
                        self._add_inline_policy(policy, role_arn)
                        stats["inline_policies"] += 1

                # Attached policies for roles
                attached_resp = await safe_api_call(
                    iam.list_attached_role_policies(RoleName=role_name),
                    default={"AttachedPolicies": []},
                )
                self._record("iam:ListAttachedRolePolicies", target_arn=role_arn,
                             detection_cost=get_detection_score("iam:ListAttachedRolePolicies"))
                for ap in (attached_resp or {}).get("AttachedPolicies", []):
                    pa = ap["PolicyArn"]
                    attached_policy_arns.add(pa)
                    self._graph.add_edge(role_arn, pa, EdgeType.HAS_POLICY)

            # ── Group attached policies ────────────────────────────
            group_nodes = self._graph.nodes_of_type(NodeType.GROUP)
            for group_arn in group_nodes:
                data = self._graph.get_node_data(group_arn)
                for pa in data.get("attached_policy_arns", []):
                    attached_policy_arns.add(pa)
                    self._graph.add_edge(group_arn, pa, EdgeType.HAS_POLICY)

            # ── Fetch documents for AWS-managed policies ───────────
            # This is critical: without the policy document, the planner
            # can't determine what permissions an identity actually has.
            for policy_arn in attached_policy_arns:
                # Skip if we already have a proper node with a document
                if self._graph.has_node(policy_arn):
                    existing = self._graph.get_node_data(policy_arn)
                    if existing.get("policy_document"):
                        continue

                # Fetch the policy metadata + default version document
                policy = await self._fetch_policy_document(iam, policy_arn)
                if policy:
                    self._add_policy_to_graph(policy)
                    stats["aws_managed_policies"] += 1
                    if policy.policy_document:
                        stats["policy_documents"] += 1

        logger.info("policy_collection_complete", **stats)
        return stats

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def _fetch_policy_document(
        self, iam: Any, policy_arn: str,
    ) -> IAMPolicy | None:
        """Fetch the document for any policy by ARN (including AWS-managed)."""
        # Get policy metadata to find the default version
        meta_resp = await safe_api_call(
            iam.get_policy(PolicyArn=policy_arn),
            default=None,
        )
        self._record("iam:GetPolicy", target_arn=policy_arn,
                     detection_cost=get_detection_score("iam:GetPolicy"))
        if not meta_resp:
            return None

        raw = meta_resp.get("Policy", {})
        version_id = raw.get("DefaultVersionId", "v1")
        is_aws = policy_arn.startswith("arn:aws:iam::aws:policy/")

        # Fetch the actual policy document
        doc_resp = await safe_api_call(
            iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id),
            default=None,
        )
        self._record("iam:GetPolicyVersion", target_arn=policy_arn,
                     detection_cost=get_detection_score("iam:GetPolicyVersion"))

        doc = {}
        if doc_resp:
            doc = doc_resp.get("PolicyVersion", {}).get("Document", {})

        return IAMPolicy(
            arn=policy_arn,
            policy_name=raw.get("PolicyName", policy_arn.split("/")[-1]),
            policy_document=doc,
            is_aws_managed=is_aws,
            version_id=version_id,
        )

    async def _enrich_managed_policy(
        self, iam: Any, raw: dict[str, Any],
    ) -> IAMPolicy | None:
        policy_arn = raw["Arn"]
        version_id = raw.get("DefaultVersionId", "v1")

        doc_resp = await safe_api_call(
            iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id),
            default=None,
            error_msg=f"Failed to get policy version for {policy_arn}",
        )
        self._record("iam:GetPolicyVersion", target_arn=policy_arn,
                     detection_cost=get_detection_score("iam:GetPolicyVersion"))

        doc = {}
        if doc_resp:
            doc = doc_resp.get("PolicyVersion", {}).get("Document", {})

        return IAMPolicy(
            arn=policy_arn,
            policy_name=raw.get("PolicyName", ""),
            policy_document=doc,
            is_aws_managed=False,
            version_id=version_id,
        )

    async def _get_inline_policy(
        self, iam: Any, entity_type: str, entity_name: str, policy_name: str,
    ) -> dict[str, Any] | None:
        method = {
            "user": "get_user_policy",
            "role": "get_role_policy",
            "group": "get_group_policy",
        }.get(entity_type)
        if not method:
            return None

        param_key = {
            "user": "UserName",
            "role": "RoleName",
            "group": "GroupName",
        }[entity_type]

        getter = getattr(iam, method)
        resp = await safe_api_call(
            getter(**{param_key: entity_name, "PolicyName": policy_name}),
            default=None,
        )
        api_action = f"iam:Get{entity_type.title()}Policy"
        self._record(api_action, detection_cost=get_detection_score(api_action))

        if resp:
            return resp.get("PolicyDocument", {})
        return None

    def _add_policy_to_graph(self, policy: IAMPolicy) -> None:
        if policy.arn:
            self._graph.add_node(
                policy.arn, NodeType.POLICY,
                data=policy.model_dump(), label=policy.policy_name,
            )

    def _add_inline_policy(self, policy: IAMPolicy, entity_arn: str) -> None:
        """Inline policies get a synthetic ARN for graph representation."""
        synthetic_arn = f"inline-policy::{entity_arn}::{policy.policy_name}"
        self._graph.add_node(
            synthetic_arn, NodeType.POLICY,
            data=policy.model_dump(), label=f"inline:{policy.policy_name}",
        )
        self._graph.add_edge(entity_arn, synthetic_arn, EdgeType.HAS_INLINE_POLICY)
