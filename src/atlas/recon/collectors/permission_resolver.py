"""
atlas.recon.collectors.permission_resolver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Permission Mapping & Attack Surface Analysis.

This collector is the LAST recon collector to run.  It consumes data
from all earlier collectors (identity, policy, trust, resource, etc.)
and builds the authoritative PermissionMap that every downstream layer
(Planner, Executor) uses.

Full IAM evaluation chain implemented:
  1. Explicit Deny (from identity or SCP)
  2. SCP allowlist (Organization-level)
  3. Permission boundary intersection
  4. Session policy intersection (assumed roles)
  5. Identity-based Allow
  6. Resource-based policy grants
  7. Condition key awareness (lower confidence)
  8. NotAction / NotResource support
  9. Cross-account principal resolution

Three-tier resolution strategy (cheapest/quietest first):

  Tier 1 — POLICY DOCUMENT ANALYSIS
    Walk the environment graph's policy edges and parse JSON documents.
    Cost: 0 additional API calls (already fetched by PolicyCollector).

  Tier 2 — iam:GetAccountAuthorizationDetails
    Single API call returns ALL users, roles, groups, and their full
    policy documents.  Cost: 1 API call.

  Tier 3 — SENTINEL PROBE
    Try ~10-15 representative read-only APIs (one per service family).
    Cost: 10-15 API calls.

  Bonus — IMPLICIT TRACKING (0 API calls)
  Bonus — OPERATOR HINTS (0 API calls)
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

import structlog

from atlas.core.permission_map import (
    IdentityPermissionProfile,
    PermissionConfidence,
    PermissionEntry,
    PermissionMap,
    PermissionSource,
    PolicyStatement,
)
from atlas.core.types import EdgeType, NodeType
from atlas.knowledge.api_profiles import get_detection_score
from atlas.recon.base import BaseCollector

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Sentinel probes: one read-only API per service family
# ---------------------------------------------------------------------------
SENTINEL_PROBES: list[dict[str, Any]] = [
    {
        "service": "iam",
        "action": "iam:ListUsers",
        "method": "list_users",
        "client": "iam",
        "kwargs": {"MaxItems": 1},
        "result_key": "Users",
        "inferred_permissions": [
            "iam:ListUsers", "iam:ListRoles", "iam:ListGroups",
            "iam:GetUser", "iam:GetRole",
        ],
    },
    {
        "service": "ec2",
        "action": "ec2:DescribeInstances",
        "method": "describe_instances",
        "client": "ec2",
        "kwargs": {"MaxResults": 5},
        "result_key": "Reservations",
        "inferred_permissions": [
            "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
            "ec2:DescribeVpcs", "ec2:DescribeSubnets",
            "ec2:DescribeSnapshots", "ec2:DescribeInstanceAttribute",
        ],
    },
    {
        "service": "s3",
        "action": "s3:ListBuckets",
        "method": "list_buckets",
        "client": "s3",
        "kwargs": {},
        "result_key": "Buckets",
        "inferred_permissions": [
            "s3:ListBuckets", "s3:ListAllMyBuckets",
            "s3:GetBucketLocation", "s3:GetBucketPolicy",
        ],
    },
    {
        "service": "lambda",
        "action": "lambda:ListFunctions",
        "method": "list_functions",
        "client": "lambda",
        "kwargs": {"MaxItems": 1},
        "result_key": "Functions",
        "inferred_permissions": [
            "lambda:ListFunctions", "lambda:GetFunction",
            "lambda:GetPolicy",
        ],
    },
    {
        "service": "sts",
        "action": "sts:GetCallerIdentity",
        "method": "get_caller_identity",
        "client": "sts",
        "kwargs": {},
        "result_key": "Account",
        "inferred_permissions": [
            "sts:GetCallerIdentity", "sts:GetAccessKeyInfo",
        ],
    },
    {
        "service": "rds",
        "action": "rds:DescribeDBInstances",
        "method": "describe_db_instances",
        "client": "rds",
        "kwargs": {"MaxRecords": 20},
        "result_key": "DBInstances",
        "inferred_permissions": [
            "rds:DescribeDBInstances", "rds:DescribeDBClusters",
            "rds:DescribeDBSnapshots",
        ],
    },
    {
        "service": "kms",
        "action": "kms:ListKeys",
        "method": "list_keys",
        "client": "kms",
        "kwargs": {"Limit": 1},
        "result_key": "Keys",
        "inferred_permissions": [
            "kms:ListKeys", "kms:DescribeKey", "kms:ListAliases",
        ],
    },
    {
        "service": "secretsmanager",
        "action": "secretsmanager:ListSecrets",
        "method": "list_secrets",
        "client": "secretsmanager",
        "kwargs": {"MaxResults": 1},
        "result_key": "SecretList",
        "inferred_permissions": [
            "secretsmanager:ListSecrets",
            "secretsmanager:DescribeSecret",
        ],
    },
    {
        "service": "ssm",
        "action": "ssm:DescribeParameters",
        "method": "describe_parameters",
        "client": "ssm",
        "kwargs": {"MaxResults": 1},
        "result_key": "Parameters",
        "inferred_permissions": [
            "ssm:DescribeParameters", "ssm:GetParameter",
        ],
    },
    {
        "service": "cloudformation",
        "action": "cloudformation:DescribeStacks",
        "method": "describe_stacks",
        "client": "cloudformation",
        "kwargs": {},
        "result_key": "Stacks",
        "inferred_permissions": [
            "cloudformation:DescribeStacks",
            "cloudformation:ListStacks",
        ],
    },
    {
        "service": "backup",
        "action": "backup:ListProtectedResources",
        "method": "list_protected_resources",
        "client": "backup",
        "kwargs": {"MaxResults": 1},
        "result_key": "Results",
        "inferred_permissions": [
            "backup:ListProtectedResources",
            "backup:ListBackupPlans",
            "backup:ListBackupVaults",
        ],
    },
    {
        "service": "dynamodb",
        "action": "dynamodb:ListTables",
        "method": "list_tables",
        "client": "dynamodb",
        "kwargs": {"Limit": 1},
        "result_key": "TableNames",
        "inferred_permissions": [
            "dynamodb:ListTables", "dynamodb:DescribeTable",
        ],
    },
    {
        "service": "sns",
        "action": "sns:ListTopics",
        "method": "list_topics",
        "client": "sns",
        "kwargs": {},
        "result_key": "Topics",
        "inferred_permissions": [
            "sns:ListTopics", "sns:GetTopicAttributes",
            "sns:ListSubscriptions",
        ],
    },
    {
        "service": "sqs",
        "action": "sqs:ListQueues",
        "method": "list_queues",
        "client": "sqs",
        "kwargs": {"MaxResults": 1},
        "result_key": "QueueUrls",
        "inferred_permissions": [
            "sqs:ListQueues", "sqs:GetQueueAttributes",
        ],
    },
]


# Well-known admin-like policy ARNs (for detection)
_ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

# TRUE admin — unrestricted.  PowerUserAccess has built-in denies and
# should NOT be treated as unrestricted admin.
_TRUE_ADMIN_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
}

# Services that commonly have resource-based policies
_RESOURCE_POLICY_SERVICES = {
    "s3", "kms", "lambda", "sqs", "sns", "secretsmanager",
    "ecr", "glacier", "es", "opensearch",
}


class PermissionResolverCollector(BaseCollector):
    """Permission Mapping & Attack Surface Analysis.

    Runs AFTER all other collectors.  Builds the PermissionMap by
    trying three resolution tiers in order, stopping at the first
    tier that produces useful data.

    Also processes:
      - SCPs from GuardrailState
      - Permission boundaries
      - Resource-based policies
      - Caller identity mapping
      - Cross-account trust relationships
    """

    @property
    def collector_id(self) -> str:
        return "permission_resolver"

    @property
    def description(self) -> str:
        return (
            "Build centralized PermissionMap via policy analysis, "
            "GetAccountAuthorizationDetails, and sentinel probing."
        )

    @property
    def required_permissions(self) -> list[str]:
        return [
            "iam:GetAccountAuthorizationDetails",  # Tier 2
        ]

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        """Build the PermissionMap using the three-tier strategy."""
        pmap = PermissionMap()
        stats: dict[str, Any] = {
            "tier_used": "none",
            "policy_docs_available": False,
            "account_auth_details_available": False,
            "sentinel_probes_run": 0,
            "sentinel_probes_succeeded": 0,
            "implicit_permissions_tracked": 0,
            "operator_hints_loaded": 0,
            "identities_mapped": 0,
            "total_permissions": 0,
            "scps_loaded": 0,
            "permission_boundaries_applied": 0,
            "resource_policies_analyzed": 0,
            "condition_gated_permissions": 0,
        }

        # Get all identities from the graph
        identities = (
            self._graph.nodes_of_type(NodeType.USER)
            + self._graph.nodes_of_type(NodeType.ROLE)
        )

        # ── Step 0: Identify the caller ──────────────────────────────
        caller_arn = self._resolve_caller_identity(pmap, account_id)
        if caller_arn:
            pmap.set_caller_arn(caller_arn)

        # ── Step 1: Load SCPs from GuardrailState ────────────────────
        scps_loaded = self._load_scps(pmap)
        stats["scps_loaded"] = scps_loaded

        # ── Step 2: Load permission boundaries ───────────────────────
        boundaries_loaded = self._load_permission_boundaries(
            pmap, identities,
        )
        stats["permission_boundaries_applied"] = boundaries_loaded

        # ── Step 3: Load operator hints (always, costs nothing) ──────
        operator_hints = self._config.recon.known_permissions
        if operator_hints:
            self._load_operator_hints(pmap, identities, operator_hints)
            stats["operator_hints_loaded"] = len(operator_hints)
            logger.info(
                "operator_hints_loaded",
                count=len(operator_hints),
                hints=operator_hints,
            )

        # ── Tier 1: Policy document analysis ─────────────────────────
        tier1_success = self._resolve_from_policy_documents(
            pmap, identities, account_id,
        )
        if tier1_success:
            stats["tier_used"] = "policy_document"
            stats["policy_docs_available"] = True
            logger.info(
                "permission_resolution_tier1",
                message="Policy documents available — full resolution",
            )
        else:
            # ── Tier 2: GetAccountAuthorizationDetails ───────────────
            logger.info(
                "permission_resolution_tier1_failed",
                message="Policy documents unavailable — trying Tier 2",
            )
            tier2_success = await self._resolve_from_account_auth_details(
                pmap, account_id, region,
            )
            if tier2_success:
                stats["tier_used"] = "account_auth_details"
                stats["account_auth_details_available"] = True
                logger.info(
                    "permission_resolution_tier2",
                    message="GetAccountAuthorizationDetails succeeded",
                )
            else:
                # ── Tier 3: Sentinel probes ──────────────────────────
                logger.info(
                    "permission_resolution_tier2_failed",
                    message="GetAccountAuthorizationDetails denied — "
                            "falling back to sentinel probes",
                )
                if self._config.recon.enable_sentinel_probes:
                    probe_results = await self._run_sentinel_probes(
                        pmap, account_id, region,
                    )
                    stats["sentinel_probes_run"] = probe_results["total"]
                    stats["sentinel_probes_succeeded"] = probe_results[
                        "succeeded"
                    ]
                    if probe_results["succeeded"] > 0:
                        stats["tier_used"] = "sentinel_probe"
                    else:
                        stats["tier_used"] = "blind"
                    logger.info(
                        "permission_resolution_tier3",
                        succeeded=probe_results["succeeded"],
                        total=probe_results["total"],
                    )
                else:
                    stats["tier_used"] = "blind"
                    logger.warning(
                        "permission_resolution_blind",
                        message="All tiers failed and sentinel probes "
                                "are disabled. Permission model is UNKNOWN.",
                    )

        # ── Resource-based policies ──────────────────────────────────
        rp_count = self._load_resource_policies(pmap, account_id)
        stats["resource_policies_analyzed"] = rp_count

        # ── Assumed role detection ───────────────────────────────────
        self._detect_assumed_roles(pmap)

        # ── Track implicit permissions from collector successes ───────
        implicit_count = self._track_implicit_permissions(pmap, account_id)
        stats["implicit_permissions_tracked"] = implicit_count

        # ── Count condition-gated permissions ─────────────────────────
        cond_count = 0
        for identity_arn in pmap.all_identities():
            profile = pmap.get_profile(identity_arn)
            if profile:
                cond_count += sum(
                    1 for e in profile.permissions.values()
                    if e.has_conditions
                )
        stats["condition_gated_permissions"] = cond_count

        # ── Finalize stats ───────────────────────────────────────────
        stats["identities_mapped"] = len(pmap.all_identities())
        stats["total_permissions"] = sum(
            len(p.permissions)
            for p in [pmap.get_profile(a) for a in pmap.all_identities()]
            if p
        )
        pmap.update_summary(**stats)

        # Store the PermissionMap in stats for the engine to extract
        stats["_permission_map"] = pmap

        logger.info("permission_resolution_complete", **{
            k: v for k, v in stats.items() if not k.startswith("_")
        })
        return stats

    # ==================================================================
    # Caller identity resolution
    # ==================================================================
    def _resolve_caller_identity(
        self, pmap: PermissionMap, account_id: str,
    ) -> str:
        """Determine the caller identity ARN from the graph.

        Uses sts:GetCallerIdentity data if available, otherwise
        falls back to the first user/role in the graph.
        """
        # Check for caller identity stored by IdentityCollector
        # Look for a node with caller_identity metadata
        for node_id in self._graph.nodes_of_type(NodeType.USER):
            data = self._graph.get_node_data(node_id)
            if data.get("is_caller", False):
                logger.info(
                    "caller_identity_resolved",
                    caller_arn=node_id,
                    source="caller_flag",
                )
                return node_id

        for node_id in self._graph.nodes_of_type(NodeType.ROLE):
            data = self._graph.get_node_data(node_id)
            if data.get("is_caller", False):
                logger.info(
                    "caller_identity_resolved",
                    caller_arn=node_id,
                    source="caller_flag",
                )
                return node_id

        # Fallback: first user or role
        all_identities = (
            self._graph.nodes_of_type(NodeType.USER)
            + self._graph.nodes_of_type(NodeType.ROLE)
        )
        if all_identities:
            logger.info(
                "caller_identity_resolved",
                caller_arn=all_identities[0],
                source="fallback_first_identity",
            )
            return all_identities[0]

        return ""

    # ==================================================================
    # SCP loading from GuardrailState
    # ==================================================================
    def _load_scps(self, pmap: PermissionMap) -> int:
        """Load Service Control Policies from the environment graph.

        SCPs are stored in the graph by the GuardrailCollector as
        GuardrailState nodes with SCP data.
        """
        count = 0
        # Search for guardrail state nodes
        for node_id in self._graph.all_nodes():
            data = self._graph.get_node_data(node_id)
            if not data.get("scps"):
                continue

            scps_data = data["scps"]
            if isinstance(scps_data, list):
                pmap.load_scps(scps_data)
                count += len(scps_data)
                logger.info("scps_loaded", count=len(scps_data))

        return count

    # ==================================================================
    # Permission boundary loading
    # ==================================================================
    def _load_permission_boundaries(
        self,
        pmap: PermissionMap,
        identities: list[str],
    ) -> int:
        """Load permission boundaries for each identity.

        Permission boundaries restrict the maximum effective permissions.
        Effective = identity_policies INTERSECT boundary.
        """
        count = 0
        for identity_arn in identities:
            data = self._graph.get_node_data(identity_arn)
            boundary_arn = data.get("permission_boundary_arn")
            if not boundary_arn:
                continue

            # Try to find the boundary policy document
            boundary_data = self._graph.get_node_data(boundary_arn)
            boundary_doc = boundary_data.get("policy_document", {})
            if boundary_doc and boundary_doc.get("Statement"):
                pmap.load_permission_boundary(identity_arn, boundary_doc)
                count += 1
                logger.debug(
                    "permission_boundary_loaded",
                    identity=identity_arn,
                    boundary_arn=boundary_arn,
                )

        return count

    # ==================================================================
    # Resource-based policy loading
    # ==================================================================
    def _load_resource_policies(
        self, pmap: PermissionMap, account_id: str,
    ) -> int:
        """Load resource-based policies from S3, KMS, Lambda, etc.

        Resource-based policies grant access independently of identity
        policies.  They can allow cross-account access.
        """
        count = 0

        # S3 bucket policies
        for bucket_arn in self._graph.nodes_of_type(NodeType.S3_BUCKET):
            data = self._graph.get_node_data(bucket_arn)
            policy_doc = data.get("bucket_policy", {})
            if policy_doc and policy_doc.get("Statement"):
                pmap.load_resource_policy(
                    bucket_arn, policy_doc, account_id,
                )
                count += 1

        # KMS key policies
        for key_arn in self._graph.nodes_of_type(NodeType.KMS_KEY):
            data = self._graph.get_node_data(key_arn)
            policy_doc = data.get("key_policy", {})
            if policy_doc and policy_doc.get("Statement"):
                pmap.load_resource_policy(
                    key_arn, policy_doc, account_id,
                )
                count += 1

        # Lambda function policies
        for fn_arn in self._graph.nodes_of_type(NodeType.LAMBDA_FUNCTION):
            data = self._graph.get_node_data(fn_arn)
            policy_doc = data.get("resource_policy", {})
            if policy_doc and policy_doc.get("Statement"):
                pmap.load_resource_policy(
                    fn_arn, policy_doc, account_id,
                )
                count += 1

        if count > 0:
            logger.info(
                "resource_policies_loaded",
                count=count,
            )

        return count

    # ==================================================================
    # Assumed role detection
    # ==================================================================
    def _detect_assumed_roles(self, pmap: PermissionMap) -> None:
        """Detect assumed-role sessions and flag their profiles.

        Assumed-role sessions may have session policies that further
        restrict permissions beyond the role's identity policies.
        """
        for node_id in self._graph.nodes_of_type(NodeType.ROLE):
            data = self._graph.get_node_data(node_id)
            profile = pmap.get_profile(node_id)
            if not profile:
                continue

            # Check if this is an assumed-role session
            if data.get("is_assumed_role") or ":assumed-role/" in node_id:
                profile.is_assumed_role = True

            # Check for session policy data
            session_policy = data.get("session_policy", {})
            if session_policy and session_policy.get("Statement"):
                profile.is_assumed_role = True
                for raw_stmt in session_policy["Statement"]:
                    stmt = PolicyStatement(
                        effect=raw_stmt.get("Effect", "Deny"),
                        actions=_ensure_list(raw_stmt.get("Action", [])),
                        not_actions=_ensure_list(
                            raw_stmt.get("NotAction", [])
                        ),
                        resources=_ensure_list(
                            raw_stmt.get("Resource", ["*"])
                        ),
                        not_resources=_ensure_list(
                            raw_stmt.get("NotResource", [])
                        ),
                        conditions=raw_stmt.get("Condition", {}),
                    )
                    profile.session_policy_statements.append(stmt)

    # ==================================================================
    # Tier 0: Operator hints
    # ==================================================================
    def _load_operator_hints(
        self,
        pmap: PermissionMap,
        identities: list[str],
        hints: list[str],
    ) -> None:
        """Load operator-provided permission hints for the caller identity."""
        caller_arn = pmap.caller_arn
        if not caller_arn:
            # Fallback to first identity
            caller_arns = (
                self._graph.nodes_of_type(NodeType.USER)[:1]
                or self._graph.nodes_of_type(NodeType.ROLE)[:1]
            )
            if not caller_arns:
                return
            caller_arn = caller_arns[0]

        profile = pmap.get_or_create_profile(caller_arn)
        for hint in hints:
            profile.add_permission(PermissionEntry(
                action=hint,
                allowed=True,
                confidence=PermissionConfidence.INFERRED,
                source=PermissionSource.OPERATOR_HINT,
                notes="Operator-provided permission hint",
            ))

    # ==================================================================
    # Tier 1: Policy document analysis
    # ==================================================================
    def _resolve_from_policy_documents(
        self,
        pmap: PermissionMap,
        identities: list[str],
        account_id: str,
    ) -> bool:
        """Resolve permissions from IAM policy documents in the graph.

        Now stores full PolicyStatements for proper evaluation of
        NotAction, NotResource, Conditions, and explicit Deny.

        Returns True if meaningful policy documents were found.
        """
        policies_found = 0

        for identity_arn in identities:
            profile = pmap.get_or_create_profile(identity_arn)
            identity_policies_found = 0

            # Walk direct policy edges
            outgoing = self._graph.outgoing(identity_arn)
            for target_arn, edge_data in outgoing:
                edge_type = edge_data.get("edge_type", "")
                if edge_type not in (
                    EdgeType.HAS_POLICY.value,
                    EdgeType.HAS_INLINE_POLICY.value,
                ):
                    continue

                # Check for admin policy (FP-2: record which ARN)
                if target_arn in _ADMIN_POLICY_ARNS:
                    profile.is_admin = True
                    profile.admin_policy_arn = target_arn
                    profile.policy_documents_available = True
                    identity_policies_found += 1
                    continue

                policy_data = self._graph.get_node_data(target_arn)
                doc = policy_data.get("policy_document", {})
                if not doc or not doc.get("Statement"):
                    continue

                identity_policies_found += 1
                self._extract_permissions_from_document(
                    profile, doc, PermissionSource.POLICY_DOCUMENT,
                )

            # Walk group memberships
            for target_arn, edge_data in outgoing:
                if edge_data.get("edge_type") != EdgeType.MEMBER_OF.value:
                    continue
                group_outgoing = self._graph.outgoing(target_arn)
                for policy_arn, pedge in group_outgoing:
                    if pedge.get("edge_type") not in (
                        EdgeType.HAS_POLICY.value,
                        EdgeType.HAS_INLINE_POLICY.value,
                    ):
                        continue
                    if policy_arn in _ADMIN_POLICY_ARNS:
                        profile.is_admin = True
                        profile.admin_policy_arn = policy_arn
                        profile.policy_documents_available = True
                        identity_policies_found += 1
                        continue
                    policy_data = self._graph.get_node_data(policy_arn)
                    doc = policy_data.get("policy_document", {})
                    if not doc or not doc.get("Statement"):
                        continue
                    identity_policies_found += 1
                    self._extract_permissions_from_document(
                        profile, doc, PermissionSource.POLICY_DOCUMENT,
                    )

            if identity_policies_found > 0:
                profile.policy_documents_available = True
                profile.resolution_tier = "policy_document"
                policies_found += identity_policies_found

        return policies_found > 0

    def _extract_permissions_from_document(
        self,
        profile: IdentityPermissionProfile,
        doc: dict[str, Any],
        source: PermissionSource,
    ) -> None:
        """Extract permissions from an IAM policy document.

        False-positive prevention:
          FP-3: Conditions with MFA/IP/VPC are flagged as blocking
          FP-4: NotAction+Allow does NOT create a phantom '*' entry.
                Evaluation goes through PolicyStatement only.
          FP-2: Admin detection records the specific policy ARN.
        """
        for raw_stmt in doc.get("Statement", []):
            effect = raw_stmt.get("Effect", "")
            conditions = raw_stmt.get("Condition", {})
            has_conditions = bool(conditions)

            # Build full PolicyStatement for proper evaluation
            stmt = PolicyStatement(
                effect=effect,
                actions=_ensure_list(raw_stmt.get("Action", [])),
                not_actions=_ensure_list(raw_stmt.get("NotAction", [])),
                resources=_ensure_list(raw_stmt.get("Resource", ["*"])),
                not_resources=_ensure_list(raw_stmt.get("NotResource", [])),
                conditions=conditions,
                source=source,
            )
            profile.add_statement(stmt)

            actions = _ensure_list(raw_stmt.get("Action", []))
            not_actions = _ensure_list(raw_stmt.get("NotAction", []))

            resources = _ensure_list(raw_stmt.get("Resource", ["*"]))

            is_allowed = effect == "Allow"

            # Handle Action-based entries
            if actions:
                for action in actions:
                    profile.add_permission(PermissionEntry(
                        action=action,
                        allowed=is_allowed,
                        confidence=PermissionConfidence.CONFIRMED,
                        source=source,
                        resource_arn=resources[0] if resources else "*",
                        resource_arns=resources,
                        conditions=conditions,
                        has_conditions=has_conditions,
                    ))
                    # Mark admin if we see "*" with Allow on "*" resource
                    if action == "*" and is_allowed:
                        if resources == ["*"] or resources[0] == "*":
                            profile.is_admin = True
                            # Record as inline admin (no specific policy ARN)
                            if not profile.admin_policy_arn:
                                profile.admin_policy_arn = (
                                    "arn:aws:iam::aws:policy/"
                                    "AdministratorAccess"
                                )

            # FP-4: NotAction+Allow — DO NOT create a phantom '*' entry.
            # The PolicyStatement stored above handles the correct
            # "everything except these actions" evaluation.  Adding a
            # '*' entry to the permissions dict causes PowerUserAccess
            # to appear to grant iam:* (which it explicitly denies).
            # Instead, we only record the Deny side of NotAction.
            if not_actions and not is_allowed:
                # NotAction + Deny: everything NOT in the list is denied.
                # Store as a PolicyStatement (already done above).
                # Also add explicit deny entries for common excluded actions
                # so the deny dict can catch them quickly.
                pass  # Deny statements handled by add_statement above

    # ==================================================================
    # Tier 2: iam:GetAccountAuthorizationDetails
    # ==================================================================
    async def _resolve_from_account_auth_details(
        self,
        pmap: PermissionMap,
        account_id: str,
        region: str,
    ) -> bool:
        """Try GetAccountAuthorizationDetails — one call returns everything.

        Also extracts permission boundaries from the response.
        Returns True if the call succeeded and permissions were extracted.
        """
        try:
            async with self._session.client("iam") as iam:
                all_details: dict[str, list[Any]] = {
                    "UserDetailList": [],
                    "RoleDetailList": [],
                    "GroupDetailList": [],
                    "Policies": [],
                }

                paginator = iam.get_paginator(
                    "get_account_authorization_details"
                )
                async for page in paginator.paginate():
                    for key in all_details:
                        all_details[key].extend(page.get(key, []))

                self._record(
                    "iam:GetAccountAuthorizationDetails",
                    detection_cost=get_detection_score(
                        "iam:GetAccountAuthorizationDetails"
                    ),
                )

            # Build managed policy doc lookup
            policy_doc_map: dict[str, dict[str, Any]] = {}
            for pol in all_details["Policies"]:
                pol_arn = pol.get("Arn", "")
                for version in pol.get("PolicyVersionList", []):
                    if version.get("IsDefaultVersion"):
                        policy_doc_map[pol_arn] = version.get(
                            "Document", {}
                        )

            # Process user details
            for user_detail in all_details["UserDetailList"]:
                user_arn = user_detail.get("Arn", "")
                if not user_arn:
                    continue
                profile = pmap.get_or_create_profile(user_arn)
                profile.resolution_tier = "account_auth_details"
                profile.policy_documents_available = True

                # Permission boundary
                pb = user_detail.get("PermissionsBoundary", {})
                pb_arn = pb.get("PermissionsBoundaryArn", "")
                if pb_arn:
                    pb_doc = policy_doc_map.get(pb_arn, {})
                    if pb_doc:
                        pmap.load_permission_boundary(user_arn, pb_doc)

                # Inline policies
                for inline in user_detail.get("UserPolicyList", []):
                    doc = inline.get("PolicyDocument", {})
                    if doc:
                        self._extract_permissions_from_document(
                            profile, doc,
                            PermissionSource.ACCOUNT_AUTH_DETAILS,
                        )

                # Attached managed policies
                for attached in user_detail.get(
                    "AttachedManagedPolicies", []
                ):
                    pa = attached.get("PolicyArn", "")
                    if pa in _ADMIN_POLICY_ARNS:
                        profile.is_admin = True
                        profile.admin_policy_arn = pa
                    doc = policy_doc_map.get(pa, {})
                    if doc:
                        self._extract_permissions_from_document(
                            profile, doc,
                            PermissionSource.ACCOUNT_AUTH_DETAILS,
                        )

                # Group memberships
                for group_name in user_detail.get("GroupList", []):
                    for grp in all_details["GroupDetailList"]:
                        if grp.get("GroupName") == group_name:
                            for inline in grp.get("GroupPolicyList", []):
                                doc = inline.get("PolicyDocument", {})
                                if doc:
                                    self._extract_permissions_from_document(
                                        profile, doc,
                                        PermissionSource.ACCOUNT_AUTH_DETAILS,
                                    )
                            for attached in grp.get(
                                "AttachedManagedPolicies", []
                            ):
                                pa = attached.get("PolicyArn", "")
                                if pa in _ADMIN_POLICY_ARNS:
                                    profile.is_admin = True
                                    profile.admin_policy_arn = pa
                                doc = policy_doc_map.get(pa, {})
                                if doc:
                                    self._extract_permissions_from_document(
                                        profile, doc,
                                        PermissionSource.ACCOUNT_AUTH_DETAILS,
                                    )

            # Process role details
            for role_detail in all_details["RoleDetailList"]:
                role_arn = role_detail.get("Arn", "")
                if not role_arn:
                    continue
                profile = pmap.get_or_create_profile(role_arn)
                profile.resolution_tier = "account_auth_details"
                profile.policy_documents_available = True

                # Permission boundary
                pb = role_detail.get("PermissionsBoundary", {})
                pb_arn = pb.get("PermissionsBoundaryArn", "")
                if pb_arn:
                    pb_doc = policy_doc_map.get(pb_arn, {})
                    if pb_doc:
                        pmap.load_permission_boundary(role_arn, pb_doc)

                # Mark assumed roles
                assume_doc = role_detail.get(
                    "AssumeRolePolicyDocument", {}
                )
                if assume_doc:
                    profile.is_assumed_role = True

                for inline in role_detail.get("RolePolicyList", []):
                    doc = inline.get("PolicyDocument", {})
                    if doc:
                        self._extract_permissions_from_document(
                            profile, doc,
                            PermissionSource.ACCOUNT_AUTH_DETAILS,
                        )

                for attached in role_detail.get(
                    "AttachedManagedPolicies", []
                ):
                    pa = attached.get("PolicyArn", "")
                    if pa in _ADMIN_POLICY_ARNS:
                        profile.is_admin = True
                        profile.admin_policy_arn = pa
                    doc = policy_doc_map.get(pa, {})
                    if doc:
                        self._extract_permissions_from_document(
                            profile, doc,
                            PermissionSource.ACCOUNT_AUTH_DETAILS,
                        )

            total_identities = (
                len(all_details["UserDetailList"])
                + len(all_details["RoleDetailList"])
            )
            logger.info(
                "account_auth_details_parsed",
                users=len(all_details["UserDetailList"]),
                roles=len(all_details["RoleDetailList"]),
                groups=len(all_details["GroupDetailList"]),
                policies=len(all_details["Policies"]),
            )
            return total_identities > 0

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            logger.info(
                "account_auth_details_denied",
                error_code=error_code,
            )
            self._record(
                "iam:GetAccountAuthorizationDetails",
                status="denied",
                error=error_code,
            )
            return False
        except Exception as exc:
            logger.warning(
                "account_auth_details_failed",
                error=str(exc),
            )
            return False

    # ==================================================================
    # Tier 3: Sentinel probes
    # ==================================================================
    async def _run_sentinel_probes(
        self,
        pmap: PermissionMap,
        account_id: str,
        region: str,
    ) -> dict[str, int]:
        """Run sentinel probes to empirically discover permissions.

        Tests one read-only API per service family.  Results applied
        to the CALLER identity.
        """
        results = {"total": 0, "succeeded": 0, "denied": 0, "errors": 0}

        # Use the resolved caller ARN
        caller_arn = pmap.caller_arn
        if not caller_arn:
            caller_identities = (
                self._graph.nodes_of_type(NodeType.USER)
                + self._graph.nodes_of_type(NodeType.ROLE)
            )
            if not caller_identities:
                return results
            caller_arn = caller_identities[0]

        profile = pmap.get_or_create_profile(caller_arn)
        profile.resolution_tier = "sentinel_probe"

        for probe in SENTINEL_PROBES:
            results["total"] += 1
            service = probe["service"]
            action = probe["action"]
            method = probe["method"]
            client_name = probe["client"]
            kwargs = dict(probe.get("kwargs", {}))

            try:
                async with self._session.client(
                    client_name, region_name=region
                ) as client:
                    api_method = getattr(client, method)
                    await api_method(**kwargs)

                # Success — this permission is confirmed
                results["succeeded"] += 1
                self._record(
                    action,
                    detection_cost=get_detection_score(action),
                )

                profile.add_permission(PermissionEntry(
                    action=action,
                    allowed=True,
                    confidence=PermissionConfidence.CONFIRMED,
                    source=PermissionSource.SENTINEL_PROBE,
                    notes=f"Sentinel probe succeeded for {service}",
                ))

                for inferred_action in probe.get(
                    "inferred_permissions", []
                ):
                    if inferred_action != action:
                        profile.add_permission(PermissionEntry(
                            action=inferred_action,
                            allowed=True,
                            confidence=PermissionConfidence.INFERRED,
                            source=PermissionSource.SENTINEL_PROBE,
                            notes=(
                                f"Inferred from successful {action} probe"
                            ),
                        ))

                logger.debug(
                    "sentinel_probe_success",
                    service=service,
                    action=action,
                )

            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in (
                    "AccessDenied", "UnauthorizedAccess",
                    "AccessDeniedException", "AuthorizationError",
                ):
                    results["denied"] += 1
                    profile.add_permission(PermissionEntry(
                        action=action,
                        allowed=False,
                        confidence=PermissionConfidence.CONFIRMED,
                        source=PermissionSource.DENY_CONFIRMED,
                        notes=f"Sentinel probe denied: {error_code}",
                    ))
                    logger.debug(
                        "sentinel_probe_denied",
                        service=service,
                        action=action,
                        error_code=error_code,
                    )
                else:
                    results["errors"] += 1
                    logger.debug(
                        "sentinel_probe_error",
                        service=service,
                        action=action,
                        error_code=error_code,
                    )

            except Exception as exc:
                results["errors"] += 1
                logger.debug(
                    "sentinel_probe_exception",
                    service=service,
                    action=action,
                    error=str(exc),
                )

        logger.info("sentinel_probes_complete", **results)
        return results

    # ==================================================================
    # Implicit permission tracking
    # ==================================================================
    def _track_implicit_permissions(
        self,
        pmap: PermissionMap,
        account_id: str,
    ) -> int:
        """Track permissions implicitly confirmed by earlier collectors."""
        implicit_count = 0
        implicit_map: list[tuple[str, str]] = []

        if self._graph.nodes_of_type(NodeType.USER):
            implicit_map.append(("has_users", "iam:ListUsers"))
            implicit_map.append(("has_users", "iam:GetUser"))
        if self._graph.nodes_of_type(NodeType.ROLE):
            implicit_map.append(("has_roles", "iam:ListRoles"))
            implicit_map.append(("has_roles", "iam:GetRole"))
        if self._graph.nodes_of_type(NodeType.GROUP):
            implicit_map.append(("has_groups", "iam:ListGroups"))
        if self._graph.nodes_of_type(NodeType.POLICY):
            implicit_map.append(("has_policies", "iam:ListPolicies"))
            implicit_map.append(("has_policies", "iam:GetPolicyVersion"))
        if self._graph.nodes_of_type(NodeType.S3_BUCKET):
            implicit_map.append(("has_s3", "s3:ListBuckets"))
            implicit_map.append(("has_s3", "s3:ListAllMyBuckets"))
        if self._graph.nodes_of_type(NodeType.EC2_INSTANCE):
            implicit_map.append(("has_ec2", "ec2:DescribeInstances"))
        if self._graph.nodes_of_type(NodeType.LAMBDA_FUNCTION):
            implicit_map.append(("has_lambda", "lambda:ListFunctions"))
        if self._graph.nodes_of_type(NodeType.RDS_INSTANCE):
            implicit_map.append(("has_rds", "rds:DescribeDBInstances"))
        if self._graph.nodes_of_type(NodeType.KMS_KEY):
            implicit_map.append(("has_kms", "kms:ListKeys"))
        if self._graph.nodes_of_type(NodeType.SECRETS_MANAGER):
            implicit_map.append((
                "has_secrets", "secretsmanager:ListSecrets"
            ))
        if self._graph.nodes_of_type(NodeType.SSM_PARAMETER):
            implicit_map.append(("has_ssm", "ssm:DescribeParameters"))
        if self._graph.nodes_of_type(NodeType.CLOUDFORMATION_STACK):
            implicit_map.append((
                "has_cfn", "cloudformation:DescribeStacks"
            ))
        if self._graph.nodes_of_type(NodeType.BACKUP_PLAN):
            implicit_map.append((
                "has_backup", "backup:ListProtectedResources"
            ))
        if self._graph.nodes_of_type(NodeType.EBS_SNAPSHOT):
            implicit_map.append(("has_ebs", "ec2:DescribeSnapshots"))

        if not implicit_map:
            return 0

        # Use the resolved caller ARN
        caller_arn = pmap.caller_arn
        if not caller_arn:
            caller_identities = (
                self._graph.nodes_of_type(NodeType.USER)
                + self._graph.nodes_of_type(NodeType.ROLE)
            )
            if not caller_identities:
                return 0
            caller_arn = caller_identities[0]

        profile = pmap.get_or_create_profile(caller_arn)

        for _, action in implicit_map:
            profile.add_permission(PermissionEntry(
                action=action,
                allowed=True,
                confidence=PermissionConfidence.CONFIRMED,
                source=PermissionSource.IMPLICIT,
                notes="Confirmed by successful recon collector execution",
            ))
            implicit_count += 1

        return implicit_count


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ensure_list(value: Any) -> list[str]:
    """Ensure a value is a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []
