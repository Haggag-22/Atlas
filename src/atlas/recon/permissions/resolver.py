"""
atlas.recon.permissions.resolver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
            "s3:GetObject", "s3:ListBucket",
            "s3:GetBucketAcl", "s3:GetBucketPublicAccessBlock",
        ],
        # Permissions that MAY exist but can't be confirmed without writes
        "speculative_permissions": [
            "s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy",
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

# ======================================================================
# Brute-force error code classification
# ======================================================================
#
# When a brute-force probe gets a ClientError, the error code tells us
# whether the request was denied by IAM or rejected for other reasons.

# Category 1: DENY — these error codes prove IAM denied the request.
_DENY_ERROR_CODES: frozenset[str] = frozenset({
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedAccess",
    "UnauthorizedOperation",
    "AuthorizationError",
    "AuthorizationErrorException",
    "Client.UnauthorizedAccess",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "MissingAuthenticationToken",
    "IncompleteSignature",
    "ExpiredToken",
    "ExpiredTokenException",
})

# Category 2: RESOURCE NOT FOUND — the request passed auth but the
# resource doesn't exist.  This PROVES we have the IAM permission.
_RESOURCE_NOT_FOUND_CODES: frozenset[str] = frozenset({
    # S3
    "NoSuchBucket", "NoSuchKey", "NoSuchUpload",
    # IAM
    "NoSuchEntity", "NoSuchEntityException",
    # EC2
    "InvalidInstanceID.NotFound", "InvalidGroupId.NotFound",
    "InvalidSnapshot.NotFound", "InvalidVolumeID.NotFound",
    "InvalidSubnetID.NotFound",
    # Lambda / KMS / SecretsManager / DynamoDB / Logs / Backup
    "ResourceNotFoundException",
    # KMS
    "NotFoundException",
    # CloudFormation
    "StackNotFoundException",
    # RDS
    "DBInstanceNotFoundFault", "DBSnapshotNotFoundFault",
    # SSM
    "ParameterNotFound",
    # SQS
    "QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue",
    # SNS
    "NotFound",
    # ECS / EKS
    "ClusterNotFoundException",
    # Glue
    "EntityNotFoundException",
    # ElastiCache
    "CacheClusterNotFoundFault",
    # Redshift
    "ClusterNotFoundFault",
    # ECR
    "RepositoryNotFoundException",
    # CodeCommit
    "RepositoryDoesNotExistException",
})

# Category 3: AMBIGUOUS — service-level errors that do NOT prove IAM
# access.  The service rejected the request for non-auth reasons
# (subscription required, org setup, region unsupported, etc.).
_AMBIGUOUS_ERROR_CODES: frozenset[str] = frozenset({
    # Subscription / service not enabled
    "SubscriptionRequiredException",
    "AWSOrganizationsNotInUseException",
    "OptInRequired",
    "InvalidClientException",
    # Region / service unavailable
    "UnsupportedOperation",
    "UnsupportedOperationException",
    "InvalidAction",
    "UnknownOperationException",
    # Org / account setup issues
    "ForbiddenException",           # Chime, WorkMail — org-level block
    "AccountNotManagementAccountException",
    "OrganizationAccessDeniedException",
    # Throttling (not auth-related)
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    # Service-specific non-auth
    "AuthorizationAlreadyExistsFault",   # ElastiCache — misleading name
    "WAFNonexistentItemException",
})

# Category 4: PARAM ERRORS — the request passed auth but had invalid
# parameters.  AWS validates auth BEFORE parameters in most services,
# so these strongly indicate we have the IAM permission.
_PARAM_ERROR_CODES: frozenset[str] = frozenset({
    "ValidationError",
    "ValidationException",
    "InvalidParameterValue",
    "InvalidParameterException",
    "InvalidParameterCombination",
    "MissingParameter",
    "MissingParameterException",
    "MissingRequiredParameter",
    "InvalidInput",
    "InvalidInputException",
    "InvalidRequestException",
    "MalformedPolicyDocument",
    "InvalidIdentityToken",
    "InvalidArgument",
    "InvalidArgumentException",
    "SerializationException",
    "MalformedQueryString",
})


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

    def _emit_tier_progress(self, tier_name: str, status: str, detail: str = "") -> None:
        """Notify the live UI about a sub-tier transition."""
        cb = getattr(self, "_bf_progress_cb", None)
        if cb:
            cb("permission_resolver", "tier_progress", {
                "tier": tier_name,
                "status": status,
                "detail": detail,
            })

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        """Build the PermissionMap using the multi-tier strategy.

        Resolution cascade (cheapest / quietest first):
          Tier 1 — Policy document analysis       (0 API calls)
          Tier 2 — GetAccountAuthorizationDetails  (1 API call)
          Tier 3 — SimulatePrincipalPolicy         (few API calls, very precise)
          Tier 4 — Piecemeal policy assembly       (several API calls)
          Tier 5 — Service Last Accessed           (2 API calls, historical)
          Tier 6 — Brute-force API enumeration     (~800 API calls)
        """
        pmap = PermissionMap()
        stats: dict[str, Any] = {
            "tier_used": "none",
            "policy_docs_available": False,
            "account_auth_details_available": False,
            "simulate_principal_used": False,
            "simulate_actions_tested": 0,
            "simulate_actions_allowed": 0,
            "piecemeal_policies_fetched": 0,
            "service_last_accessed_services": 0,
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
        self._emit_tier_progress("policy_docs", "running")
        tier1_success = self._resolve_from_policy_documents(
            pmap, identities, account_id,
        )
        if tier1_success:
            stats["tier_used"] = "policy_document"
            stats["policy_docs_available"] = True
            self._emit_tier_progress("policy_docs", "ok", "Full resolution from policy docs")
            # Skip remaining tiers
            for t in ("auth_details", "simulate", "piecemeal", "last_accessed", "bruteforce"):
                self._emit_tier_progress(t, "skipped")
            logger.info(
                "permission_resolution_tier1",
                message="Policy documents available — full resolution",
            )
        else:
            self._emit_tier_progress("policy_docs", "denied")

            # ── Tier 2: GetAccountAuthorizationDetails ───────────────
            self._emit_tier_progress("auth_details", "running")
            tier2_success = await self._resolve_from_account_auth_details(
                pmap, account_id, region,
            )
            if tier2_success:
                stats["tier_used"] = "account_auth_details"
                stats["account_auth_details_available"] = True
                self._emit_tier_progress("auth_details", "ok", "Full policy data")
                for t in ("simulate", "piecemeal", "last_accessed", "bruteforce"):
                    self._emit_tier_progress(t, "skipped")
                logger.info(
                    "permission_resolution_tier2",
                    message="GetAccountAuthorizationDetails succeeded",
                )
            else:
                self._emit_tier_progress("auth_details", "denied")

                # ── Tier 3: SimulatePrincipalPolicy ──────────────────
                self._emit_tier_progress("simulate", "running")
                sim_results = await self._resolve_from_simulate_policy(
                    pmap, account_id, region, caller_arn or "",
                )
                stats["simulate_actions_tested"] = sim_results.get("tested", 0)
                stats["simulate_actions_allowed"] = sim_results.get("allowed", 0)
                if sim_results.get("success"):
                    stats["simulate_principal_used"] = True
                    stats["tier_used"] = "simulate_principal"
                    self._emit_tier_progress(
                        "simulate", "ok",
                        f"{sim_results['allowed']}/{sim_results['tested']} allowed",
                    )
                    for t in ("piecemeal", "last_accessed", "bruteforce"):
                        self._emit_tier_progress(t, "skipped")
                else:
                    self._emit_tier_progress("simulate", "denied")

                    # ── Tier 4: Piecemeal policy assembly ────────────
                    self._emit_tier_progress("piecemeal", "running")
                    piece_results = await self._resolve_from_piecemeal_policies(
                        pmap, account_id, region, caller_arn or "",
                    )
                    stats["piecemeal_policies_fetched"] = piece_results.get("policies_fetched", 0)
                    if piece_results.get("success"):
                        stats["tier_used"] = "piecemeal_policy"
                        self._emit_tier_progress(
                            "piecemeal", "ok",
                            f"{piece_results['policies_fetched']} policies",
                        )
                        for t in ("last_accessed", "bruteforce"):
                            self._emit_tier_progress(t, "skipped")
                    else:
                        self._emit_tier_progress("piecemeal", "denied")

                    # ── Tier 5: Service Last Accessed (always try) ───
                    # Cheap (2 API calls) and complements brute-force
                    # with historical service-level evidence.
                    if not piece_results.get("success"):
                        self._emit_tier_progress("last_accessed", "running")
                        sla_results = await self._resolve_from_service_last_accessed(
                            pmap, account_id, region, caller_arn or "",
                        )
                        stats["service_last_accessed_services"] = sla_results.get("services_found", 0)
                        if sla_results.get("success"):
                            self._emit_tier_progress(
                                "last_accessed", "ok",
                                f"{sla_results['services_found']} services accessed",
                            )
                        else:
                            self._emit_tier_progress("last_accessed", "denied")

                    # ── Tier 6: Brute-force (always try when no full
                    #    policy docs were found) ──────────────────────
                    if not piece_results.get("success"):
                        if self._config.recon.enable_sentinel_probes:
                            self._emit_tier_progress("bruteforce", "running")
                            probe_results = await self._run_sentinel_probes(
                                pmap, account_id, region,
                            )
                            stats["sentinel_probes_run"] = probe_results["total"]
                            stats["sentinel_probes_succeeded"] = probe_results[
                                "succeeded"
                            ]
                            if probe_results["succeeded"] > 0:
                                if not stats["tier_used"] or stats["tier_used"] == "none":
                                    stats["tier_used"] = "sentinel_probe"
                                self._emit_tier_progress(
                                    "bruteforce", "ok",
                                    f"{probe_results['succeeded']}/{probe_results['total']} succeeded",
                                )
                            else:
                                if not stats["tier_used"] or stats["tier_used"] == "none":
                                    stats["tier_used"] = "blind"
                                self._emit_tier_progress("bruteforce", "done")
                        else:
                            if not stats["tier_used"] or stats["tier_used"] == "none":
                                stats["tier_used"] = "blind"
                            self._emit_tier_progress("bruteforce", "skipped")

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
        for node_id in list(self._graph._g.nodes):
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
    # Tier 3: iam:SimulatePrincipalPolicy
    # ==================================================================
    #
    # The most powerful discovery method after full policy docs.
    # We ask AWS directly "can principal X perform action Y on resource Z?"
    # for hundreds of actions in a single API call — zero side effects,
    # zero CloudTrail noise on target services.

    # Actions we care about for attack-graph construction, grouped by
    # service so we can batch them efficiently.
    _SIMULATE_ACTIONS: list[str] = [
        # IAM
        "iam:CreateUser", "iam:CreateRole", "iam:CreatePolicy",
        "iam:AttachUserPolicy", "iam:AttachRolePolicy",
        "iam:PutUserPolicy", "iam:PutRolePolicy",
        "iam:CreateAccessKey", "iam:CreateLoginProfile",
        "iam:UpdateAssumeRolePolicy", "iam:PassRole",
        "iam:AddUserToGroup", "iam:ListUsers", "iam:ListRoles",
        "iam:ListPolicies", "iam:GetUser", "iam:GetRole",
        "iam:GetPolicy", "iam:GetPolicyVersion",
        "iam:ListAttachedUserPolicies", "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies", "iam:ListRolePolicies",
        "iam:ListGroupsForUser", "iam:SimulatePrincipalPolicy",
        "iam:GetAccountAuthorizationDetails",
        # STS
        "sts:AssumeRole", "sts:GetCallerIdentity",
        "sts:GetSessionToken", "sts:GetFederationToken",
        # S3
        "s3:ListAllMyBuckets", "s3:ListBucket",
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
        "s3:GetBucketPolicy", "s3:PutBucketPolicy",
        "s3:GetBucketAcl", "s3:PutBucketAcl",
        "s3:GetBucketPublicAccessBlock",
        # EC2
        "ec2:DescribeInstances", "ec2:RunInstances",
        "ec2:TerminateInstances", "ec2:DescribeSecurityGroups",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:DescribeSnapshots", "ec2:CreateSnapshot",
        "ec2:ModifySnapshotAttribute", "ec2:DescribeImages",
        "ec2:DescribeVpcs", "ec2:DescribeSubnets",
        # Lambda
        "lambda:ListFunctions", "lambda:GetFunction",
        "lambda:CreateFunction", "lambda:InvokeFunction",
        "lambda:UpdateFunctionCode", "lambda:AddPermission",
        "lambda:GetPolicy",
        # Secrets Manager
        "secretsmanager:ListSecrets", "secretsmanager:GetSecretValue",
        "secretsmanager:CreateSecret", "secretsmanager:PutSecretValue",
        # SSM
        "ssm:GetParameter", "ssm:GetParameters",
        "ssm:DescribeParameters", "ssm:PutParameter",
        "ssm:SendCommand",
        # KMS
        "kms:ListKeys", "kms:DescribeKey", "kms:Decrypt",
        "kms:Encrypt", "kms:CreateGrant",
        # CloudFormation
        "cloudformation:ListStacks", "cloudformation:DescribeStacks",
        "cloudformation:CreateStack", "cloudformation:UpdateStack",
        # RDS
        "rds:DescribeDBInstances", "rds:DescribeDBSnapshots",
        "rds:CreateDBSnapshot", "rds:ModifyDBSnapshotAttribute",
        # CloudTrail
        "cloudtrail:DescribeTrails", "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail", "cloudtrail:LookupEvents",
        # GuardDuty
        "guardduty:ListDetectors", "guardduty:DeleteDetector",
        # Organizations
        "organizations:ListAccounts", "organizations:DescribeOrganization",
        # ECS / EKS
        "ecs:ListClusters", "ecs:DescribeClusters",
        "eks:ListClusters", "eks:DescribeCluster",
        # SNS / SQS
        "sns:ListTopics", "sns:Publish",
        "sqs:ListQueues", "sqs:SendMessage",
        # DynamoDB
        "dynamodb:ListTables", "dynamodb:DescribeTable",
        "dynamodb:GetItem", "dynamodb:PutItem",
        # Logs
        "logs:DescribeLogGroups", "logs:GetLogEvents",
        "logs:CreateLogGroup",
        # ECR
        "ecr:DescribeRepositories", "ecr:GetAuthorizationToken",
        # Glue
        "glue:GetDatabases", "glue:GetConnections",
        # Redshift
        "redshift:DescribeClusters",
        # ElastiCache
        "elasticache:DescribeCacheClusters",
        # Backup
        "backup:ListProtectedResources",
        "backup:ListBackupPlans",
    ]

    # Resource ARNs to test in Tier 3 SimulatePrincipalPolicy.
    # Maps actions that are resource-scoped to ARN patterns.
    _SIMULATE_RESOURCE_ARNS: dict[str, list[str]] = {
        "s3:GetObject": ["arn:aws:s3:::*/*"],
        "s3:PutObject": ["arn:aws:s3:::*/*"],
        "s3:DeleteObject": ["arn:aws:s3:::*/*"],
        "s3:ListBucket": ["arn:aws:s3:::*"],
        "s3:GetBucketPolicy": ["arn:aws:s3:::*"],
        "s3:PutBucketPolicy": ["arn:aws:s3:::*"],
        "lambda:InvokeFunction": [
            f"arn:aws:lambda:*:*:function:*",
        ],
        "lambda:UpdateFunctionCode": [
            f"arn:aws:lambda:*:*:function:*",
        ],
        "secretsmanager:GetSecretValue": [
            "arn:aws:secretsmanager:*:*:secret:*",
        ],
        "kms:Decrypt": ["arn:aws:kms:*:*:key/*"],
        "kms:Encrypt": ["arn:aws:kms:*:*:key/*"],
        "ssm:GetParameter": ["arn:aws:ssm:*:*:parameter/*"],
        "ssm:PutParameter": ["arn:aws:ssm:*:*:parameter/*"],
        "dynamodb:GetItem": ["arn:aws:dynamodb:*:*:table/*"],
        "dynamodb:PutItem": ["arn:aws:dynamodb:*:*:table/*"],
    }

    async def _resolve_from_simulate_policy(
        self,
        pmap: PermissionMap,
        account_id: str,
        region: str,
        caller_arn: str,
    ) -> dict[str, Any]:
        """Tier 3: Use iam:SimulatePrincipalPolicy to test permissions.

        Sends batches of actions to the IAM policy simulator and records
        each result as CONFIRMED allow/deny.  For resource-scoped actions,
        we additionally pass ResourceArns so the simulator evaluates
        resource-based policies correctly.

        Returns dict with: success, tested, allowed, denied.
        """
        results: dict[str, Any] = {
            "success": False,
            "tested": 0,
            "allowed": 0,
            "denied": 0,
        }

        if not caller_arn:
            return results

        BATCH_SIZE = 50
        profile = pmap.get_or_create_profile(caller_arn)

        # Split actions: wildcard-resource (can batch) vs resource-scoped
        wildcard_actions: list[str] = []
        resource_scoped: list[tuple[str, list[str]]] = []
        for action in self._SIMULATE_ACTIONS:
            if action in self._SIMULATE_RESOURCE_ARNS:
                resource_scoped.append(
                    (action, self._SIMULATE_RESOURCE_ARNS[action]),
                )
            else:
                wildcard_actions.append(action)

        def _record_eval(action: str, decision: str) -> None:
            """Record a single SimulatePrincipalPolicy evaluation."""
            results["tested"] += 1
            if decision == "allowed":
                results["allowed"] += 1
                profile.add_permission(PermissionEntry(
                    action=action,
                    allowed=True,
                    confidence=PermissionConfidence.CONFIRMED,
                    source=PermissionSource.SIMULATE_PRINCIPAL,
                    notes=f"SimulatePrincipalPolicy: {decision}",
                ))
            elif decision in ("explicitDeny", "implicitDeny"):
                results["denied"] += 1
                profile.add_permission(PermissionEntry(
                    action=action,
                    allowed=False,
                    confidence=PermissionConfidence.CONFIRMED,
                    source=PermissionSource.DENY_CONFIRMED,
                    notes=f"SimulatePrincipalPolicy: {decision}",
                ))

        try:
            async with self._session.client("iam") as iam:
                # Phase A: batch wildcard-resource actions
                for i in range(0, len(wildcard_actions), BATCH_SIZE):
                    batch = wildcard_actions[i : i + BATCH_SIZE]
                    try:
                        resp = await iam.simulate_principal_policy(
                            PolicySourceArn=caller_arn,
                            ActionNames=batch,
                        )
                    except ClientError as exc:
                        code = exc.response.get("Error", {}).get("Code", "")
                        if code in (
                            "AccessDenied", "AccessDeniedException",
                            "UnauthorizedAccess",
                        ):
                            logger.info("simulate_principal_denied", error=code)
                            return results
                        if code == "NoSuchEntity":
                            logger.info("simulate_principal_nosuchentity", arn=caller_arn)
                            return results
                        raise

                    for eval_result in resp.get("EvaluationResults", []):
                        _record_eval(
                            eval_result.get("EvalActionName", ""),
                            eval_result.get("EvalDecision", ""),
                        )

                    self._record(
                        "iam:SimulatePrincipalPolicy",
                        detection_cost=get_detection_score(
                            "iam:SimulatePrincipalPolicy"
                        ),
                        details={"batch_size": len(batch), "offset": i},
                    )

                # Phase B: resource-scoped actions (one per call)
                for action, resource_arns in resource_scoped:
                    try:
                        resp = await iam.simulate_principal_policy(
                            PolicySourceArn=caller_arn,
                            ActionNames=[action],
                            ResourceArns=resource_arns,
                        )
                    except ClientError as exc:
                        code = exc.response.get("Error", {}).get("Code", "")
                        if code in (
                            "AccessDenied", "AccessDeniedException",
                            "UnauthorizedAccess",
                        ):
                            continue
                        if code == "NoSuchEntity":
                            continue
                        raise

                    for eval_result in resp.get("EvaluationResults", []):
                        _record_eval(
                            eval_result.get("EvalActionName", ""),
                            eval_result.get("EvalDecision", ""),
                        )

                    self._record(
                        "iam:SimulatePrincipalPolicy",
                        detection_cost=get_detection_score(
                            "iam:SimulatePrincipalPolicy"
                        ),
                        details={
                            "action": action,
                            "resource_arns": resource_arns,
                        },
                    )

            results["success"] = True
            logger.info(
                "simulate_principal_complete",
                tested=results["tested"],
                allowed=results["allowed"],
                denied=results["denied"],
            )
            return results

        except Exception as exc:
            logger.info("simulate_principal_failed", error=str(exc))
            return results

    # ==================================================================
    # Tier 4: Piecemeal policy assembly
    # ==================================================================
    #
    # When SimulatePrincipalPolicy is denied, try to read individual
    # policy documents by:
    #   1. iam:ListAttachedUserPolicies / ListAttachedRolePolicies
    #   2. iam:GetPolicy + iam:GetPolicyVersion for each
    #   3. iam:ListUserPolicies / ListRolePolicies (inline names)
    #   4. iam:GetUserPolicy / GetRolePolicy (inline docs)
    #   5. iam:ListGroupsForUser + group policies

    async def _resolve_from_piecemeal_policies(
        self,
        pmap: PermissionMap,
        account_id: str,
        region: str,
        caller_arn: str,
    ) -> dict[str, Any]:
        """Tier 4: Assemble policies by reading them individually.

        Unlike GetAccountAuthorizationDetails (which reads ALL policies),
        this only reads the caller's own policies — often allowed even
        with restricted IAM access.
        """
        results: dict[str, Any] = {
            "success": False,
            "policies_fetched": 0,
        }

        if not caller_arn:
            return results

        is_user = ":user/" in caller_arn
        is_role = ":role/" in caller_arn or ":assumed-role/" in caller_arn
        entity_name = caller_arn.split("/")[-1] if "/" in caller_arn else ""

        if not entity_name:
            return results

        # Normalize assumed-role ARN to role ARN
        if ":assumed-role/" in caller_arn:
            role_arn = f"arn:aws:iam::{account_id}:role/{entity_name}"
        else:
            role_arn = caller_arn

        profile = pmap.get_or_create_profile(role_arn if is_role else caller_arn)
        any_success = False

        try:
            async with self._session.client("iam") as iam:

                # ── Attached managed policies ────────────────────────
                attached_arns: list[str] = []
                try:
                    if is_user:
                        resp = await iam.list_attached_user_policies(
                            UserName=entity_name,
                        )
                        attached_arns = [
                            p["PolicyArn"]
                            for p in resp.get("AttachedPolicies", [])
                        ]
                        self._record("iam:ListAttachedUserPolicies")
                    elif is_role:
                        resp = await iam.list_attached_role_policies(
                            RoleName=entity_name,
                        )
                        attached_arns = [
                            p["PolicyArn"]
                            for p in resp.get("AttachedPolicies", [])
                        ]
                        self._record("iam:ListAttachedRolePolicies")
                    any_success = True
                except ClientError:
                    pass

                # Fetch each managed policy document
                for pol_arn in attached_arns:
                    try:
                        pol_resp = await iam.get_policy(PolicyArn=pol_arn)
                        default_ver = pol_resp["Policy"].get(
                            "DefaultVersionId", "v1",
                        )
                        ver_resp = await iam.get_policy_version(
                            PolicyArn=pol_arn,
                            VersionId=default_ver,
                        )
                        doc = ver_resp.get("PolicyVersion", {}).get(
                            "Document", {},
                        )
                        if doc:
                            self._extract_permissions_from_document(
                                profile, doc,
                                PermissionSource.PIECEMEAL_POLICY,
                            )
                            results["policies_fetched"] += 1
                        self._record("iam:GetPolicyVersion")
                    except ClientError:
                        pass

                # ── Inline policies ──────────────────────────────────
                try:
                    if is_user:
                        resp = await iam.list_user_policies(
                            UserName=entity_name,
                        )
                        policy_names = resp.get("PolicyNames", [])
                        for pname in policy_names:
                            try:
                                pr = await iam.get_user_policy(
                                    UserName=entity_name,
                                    PolicyName=pname,
                                )
                                doc = pr.get("PolicyDocument", {})
                                if doc:
                                    self._extract_permissions_from_document(
                                        profile, doc,
                                        PermissionSource.PIECEMEAL_POLICY,
                                    )
                                    results["policies_fetched"] += 1
                            except ClientError:
                                pass
                        self._record("iam:ListUserPolicies")
                        any_success = True
                    elif is_role:
                        resp = await iam.list_role_policies(
                            RoleName=entity_name,
                        )
                        policy_names = resp.get("PolicyNames", [])
                        for pname in policy_names:
                            try:
                                pr = await iam.get_role_policy(
                                    RoleName=entity_name,
                                    PolicyName=pname,
                                )
                                doc = pr.get("PolicyDocument", {})
                                if doc:
                                    self._extract_permissions_from_document(
                                        profile, doc,
                                        PermissionSource.PIECEMEAL_POLICY,
                                    )
                                    results["policies_fetched"] += 1
                            except ClientError:
                                pass
                        self._record("iam:ListRolePolicies")
                        any_success = True
                except ClientError:
                    pass

                # ── Group policies (users only) ──────────────────────
                if is_user:
                    try:
                        resp = await iam.list_groups_for_user(
                            UserName=entity_name,
                        )
                        for grp in resp.get("Groups", []):
                            grp_name = grp.get("GroupName", "")
                            # Attached group policies
                            try:
                                grp_attached = await iam.list_attached_group_policies(
                                    GroupName=grp_name,
                                )
                                for gp in grp_attached.get(
                                    "AttachedPolicies", [],
                                ):
                                    gp_arn = gp["PolicyArn"]
                                    try:
                                        gpr = await iam.get_policy(
                                            PolicyArn=gp_arn,
                                        )
                                        dv = gpr["Policy"].get(
                                            "DefaultVersionId", "v1",
                                        )
                                        gvr = await iam.get_policy_version(
                                            PolicyArn=gp_arn,
                                            VersionId=dv,
                                        )
                                        doc = gvr.get(
                                            "PolicyVersion", {},
                                        ).get("Document", {})
                                        if doc:
                                            self._extract_permissions_from_document(
                                                profile, doc,
                                                PermissionSource.PIECEMEAL_POLICY,
                                            )
                                            results["policies_fetched"] += 1
                                    except ClientError:
                                        pass
                            except ClientError:
                                pass
                            # Inline group policies
                            try:
                                gip = await iam.list_group_policies(
                                    GroupName=grp_name,
                                )
                                for gpname in gip.get("PolicyNames", []):
                                    try:
                                        gipr = await iam.get_group_policy(
                                            GroupName=grp_name,
                                            PolicyName=gpname,
                                        )
                                        doc = gipr.get(
                                            "PolicyDocument", {},
                                        )
                                        if doc:
                                            self._extract_permissions_from_document(
                                                profile, doc,
                                                PermissionSource.PIECEMEAL_POLICY,
                                            )
                                            results["policies_fetched"] += 1
                                    except ClientError:
                                        pass
                            except ClientError:
                                pass
                        self._record("iam:ListGroupsForUser")
                        any_success = True
                    except ClientError:
                        pass

            if any_success and results["policies_fetched"] > 0:
                results["success"] = True
                profile.resolution_tier = "piecemeal_policy"
                profile.policy_documents_available = True

            logger.info(
                "piecemeal_policy_complete",
                policies_fetched=results["policies_fetched"],
                success=results["success"],
            )
            return results

        except Exception as exc:
            logger.info("piecemeal_policy_failed", error=str(exc))
            return results

    # ==================================================================
    # Tier 5: Service Last Accessed (historical usage data)
    # ==================================================================
    #
    # iam:GenerateServiceLastAccessedDetails + GetServiceLastAccessedDetails
    # reveals which services a principal has actually used recently.
    # This gives HEURISTIC confidence (we know the service was used but
    # not which specific actions).

    async def _resolve_from_service_last_accessed(
        self,
        pmap: PermissionMap,
        account_id: str,
        region: str,
        caller_arn: str,
    ) -> dict[str, Any]:
        """Tier 5: Use Service Last Accessed data for historical evidence.

        If a principal accessed S3 last week, they definitely have some
        S3 permissions.  This doesn't tell us exactly which actions, but
        it narrows the search space and provides HEURISTIC-confidence
        entries.
        """
        import asyncio as _aio

        results: dict[str, Any] = {
            "success": False,
            "services_found": 0,
        }

        if not caller_arn:
            return results

        # Normalize assumed-role to role ARN
        if ":assumed-role/" in caller_arn:
            entity_name = caller_arn.split("/")[1] if "/" in caller_arn else ""
            arn_for_api = f"arn:aws:iam::{account_id}:role/{entity_name}"
        else:
            arn_for_api = caller_arn

        profile = pmap.get_or_create_profile(arn_for_api)

        # Service namespace → representative actions to record
        _SVC_ACTIONS: dict[str, list[str]] = {
            "s3": ["s3:ListAllMyBuckets", "s3:GetObject", "s3:ListBucket"],
            "ec2": ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"],
            "iam": ["iam:ListUsers", "iam:ListRoles", "iam:GetUser"],
            "lambda": ["lambda:ListFunctions", "lambda:GetFunction"],
            "sts": ["sts:AssumeRole", "sts:GetCallerIdentity"],
            "kms": ["kms:ListKeys", "kms:DescribeKey"],
            "secretsmanager": ["secretsmanager:ListSecrets"],
            "ssm": ["ssm:DescribeParameters", "ssm:GetParameter"],
            "dynamodb": ["dynamodb:ListTables"],
            "rds": ["rds:DescribeDBInstances"],
            "sns": ["sns:ListTopics"],
            "sqs": ["sqs:ListQueues"],
            "logs": ["logs:DescribeLogGroups"],
            "cloudformation": ["cloudformation:ListStacks"],
            "cloudtrail": ["cloudtrail:DescribeTrails"],
            "ecr": ["ecr:DescribeRepositories"],
            "ecs": ["ecs:ListClusters"],
            "eks": ["eks:ListClusters"],
            "elasticache": ["elasticache:DescribeCacheClusters"],
            "redshift": ["redshift:DescribeClusters"],
            "glue": ["glue:GetDatabases"],
            "backup": ["backup:ListProtectedResources"],
        }

        try:
            async with self._session.client("iam") as iam:
                # Step 1: Generate the report
                gen_resp = await iam.generate_service_last_accessed_details(
                    Arn=arn_for_api,
                )
                job_id = gen_resp.get("JobId", "")
                if not job_id:
                    return results

                self._record("iam:GenerateServiceLastAccessedDetails")

                # Step 2: Poll until the job completes (max ~30s)
                for _ in range(15):
                    await _aio.sleep(2)
                    try:
                        details_resp = await iam.get_service_last_accessed_details(
                            JobId=job_id,
                        )
                    except ClientError:
                        return results

                    status = details_resp.get("JobStatus", "")
                    if status == "COMPLETED":
                        break
                    if status == "FAILED":
                        return results
                else:
                    # Timed out
                    return results

                self._record("iam:GetServiceLastAccessedDetails")

                # Step 3: Process results
                for svc_detail in details_resp.get(
                    "ServicesLastAccessed", [],
                ):
                    namespace = svc_detail.get("ServiceNamespace", "")
                    last_auth = svc_detail.get(
                        "LastAuthenticated",
                    )  # datetime or None

                    if last_auth is not None and namespace:
                        results["services_found"] += 1

                        # Record representative actions at HEURISTIC confidence
                        actions = _SVC_ACTIONS.get(namespace, [])
                        if not actions:
                            # Generic fallback
                            actions = [f"{namespace}:*"]

                        for action in actions:
                            profile.add_permission(PermissionEntry(
                                action=action,
                                allowed=True,
                                confidence=PermissionConfidence.HEURISTIC,
                                source=PermissionSource.SERVICE_LAST_ACCESSED,
                                notes=f"Service {namespace} last accessed: {last_auth}",
                            ))

            if results["services_found"] > 0:
                results["success"] = True
                if not profile.resolution_tier or profile.resolution_tier == "none":
                    profile.resolution_tier = "service_last_accessed"

            logger.info(
                "service_last_accessed_complete",
                services_found=results["services_found"],
            )
            return results

        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            logger.info("service_last_accessed_denied", error=code)
            return results
        except Exception as exc:
            logger.info("service_last_accessed_failed", error=str(exc))
            return results

    # ==================================================================
    # Tier 6: IAM permission brute-force
    # ==================================================================

    _THROTTLE_CODES: frozenset[str] = frozenset({
        "Throttling", "ThrottlingException",
        "RequestLimitExceeded", "TooManyRequestsException",
    })

    async def _run_sentinel_probes(
        self,
        pmap: PermissionMap,
        account_id: str,
        region: str,
    ) -> dict[str, int]:
        """Brute-force IAM permissions by trying every read-only API.

        Improvements over naive enumerate-iam:
          - Probes batched by service (one client per service, not per probe)
          - Exponential backoff retry on throttled probes (up to 2 retries)
          - Resource-scoped follow-up probes for discovered S3 buckets
        """
        from atlas.recon.permissions.bruteforce import build_merged_probes
        BRUTEFORCE_PROBES = build_merged_probes()
        import asyncio as _asyncio

        results = {"total": 0, "succeeded": 0, "denied": 0, "errors": 0,
                   "throttle_retries": 0}
        _bf_total_probes = len(BRUTEFORCE_PROBES) + 1
        _bf_cb = getattr(self, "_bf_progress_cb", None)

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
        profile.resolution_tier = "bruteforce"

        caller_username = caller_arn.split("/")[-1] if "/" in caller_arn else ""

        # Phase 1a: s3:ListBuckets — get bucket names for S3 sub-probes
        discovered_buckets: list[str] = []
        first_bucket: str = ""
        first_trail: str = ""
        try:
            async with self._session.client("s3", region_name=region) as s3:
                resp = await s3.list_buckets()
                buckets = resp.get("Buckets", [])
                discovered_buckets = [b["Name"] for b in buckets]
                if discovered_buckets:
                    first_bucket = discovered_buckets[0]
                profile.add_permission(PermissionEntry(
                    action="s3:ListBuckets",
                    allowed=True,
                    confidence=PermissionConfidence.CONFIRMED,
                    source=PermissionSource.SENTINEL_PROBE,
                    notes="Brute-force: s3:ListBuckets succeeded",
                ))
                results["succeeded"] += 1
                results["total"] += 1
        except Exception:
            profile.add_permission(PermissionEntry(
                action="s3:ListBuckets",
                allowed=False,
                confidence=PermissionConfidence.CONFIRMED,
                source=PermissionSource.DENY_CONFIRMED,
                notes="Brute-force: s3:ListBuckets denied",
            ))
            results["denied"] += 1
            results["total"] += 1

        if _bf_cb:
            _bf_cb("permission_resolver", "bf_progress", {
                "done": results["total"],
                "total": _bf_total_probes,
                "succeeded": results["succeeded"],
                "last_allowed": "s3:ListBuckets" if results["succeeded"] > 0 else None,
            })

        # Phase 1b: cloudtrail:DescribeTrails — get trail name
        try:
            async with self._session.client(
                "cloudtrail", region_name=region,
            ) as ct:
                resp = await ct.describe_trails()
                trails = resp.get("trailList", [])
                if trails:
                    first_trail = trails[0].get("Name", "")
        except Exception:
            pass

        # ── Error classification helper ───────────────────────────────
        def _classify_error(
            error_code: str, http_status: int,
        ) -> tuple[str, bool]:
            """Classify a ClientError → (category, is_allowed)."""
            if error_code in _DENY_ERROR_CODES:
                return ("deny", False)
            if error_code in _RESOURCE_NOT_FOUND_CODES:
                return ("allowed_resource_missing", True)
            if error_code in self._THROTTLE_CODES:
                return ("throttle", False)
            if error_code in _AMBIGUOUS_ERROR_CODES:
                return ("ambiguous", False)
            if http_status == 403:
                return ("deny", False)
            if http_status in (400, 404, 409) and error_code in _PARAM_ERROR_CODES:
                return ("allowed_post_auth", True)
            return ("unknown", False)

        # ── Retry wrapper for throttled calls ─────────────────────────
        async def _call_with_retry(
            client: Any, method: str, kwargs: dict[str, Any],
            max_retries: int = 2,
        ) -> Any:
            for attempt in range(max_retries + 1):
                try:
                    api_method = getattr(client, method)
                    return await api_method(**kwargs)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code in self._THROTTLE_CODES and attempt < max_retries:
                        wait = (2 ** attempt) + (0.5 * attempt)
                        results["throttle_retries"] += 1
                        logger.debug(
                            "bf_throttle_retry",
                            method=method, attempt=attempt + 1, wait=wait,
                        )
                        await _asyncio.sleep(wait)
                        continue
                    raise

        # Phase 2: run probes batched by service
        sem = _asyncio.Semaphore(self._config.recon.bruteforce_concurrency)

        async def _probe_one(
            client: Any, client_name: str, method: str,
            kwargs: dict[str, Any], action: str,
        ) -> None:
            """Execute a single probe using a shared service client."""
            if action == "s3:ListBuckets":
                return

            resolved_kwargs = dict(kwargs)
            needs_bucket = any(
                v == "__FIRST_BUCKET__" for v in resolved_kwargs.values()
            )
            needs_trail = any(
                v == "__FIRST_TRAIL__" for v in resolved_kwargs.values()
            )
            needs_caller = any(
                v == "__CALLER__" for v in resolved_kwargs.values()
            )

            if needs_bucket and not first_bucket:
                return
            if needs_trail and not first_trail:
                return
            if needs_caller and not caller_username:
                return

            for k, v in resolved_kwargs.items():
                if v == "__FIRST_BUCKET__":
                    resolved_kwargs[k] = first_bucket
                elif v == "__FIRST_TRAIL__":
                    resolved_kwargs[k] = first_trail
                elif v == "__CALLER__":
                    resolved_kwargs[k] = caller_username

            async with sem:
                _this_allowed: str | None = None
                try:
                    await _call_with_retry(client, method, resolved_kwargs)

                    results["succeeded"] += 1
                    _this_allowed = action
                    profile.add_permission(PermissionEntry(
                        action=action,
                        allowed=True,
                        confidence=PermissionConfidence.CONFIRMED,
                        source=PermissionSource.SENTINEL_PROBE,
                        notes=f"Brute-force: {action} succeeded",
                    ))
                    logger.debug("bf_probe_ok", action=action)

                except ClientError as exc:
                    error_code = exc.response.get(
                        "Error", {},
                    ).get("Code", "")
                    http_status = exc.response.get(
                        "ResponseMetadata", {},
                    ).get("HTTPStatusCode", 0)

                    category, is_allowed = _classify_error(
                        error_code, http_status,
                    )

                    if is_allowed:
                        results["succeeded"] += 1
                        _this_allowed = action
                        profile.add_permission(PermissionEntry(
                            action=action,
                            allowed=True,
                            confidence=PermissionConfidence.CONFIRMED,
                            source=PermissionSource.SENTINEL_PROBE,
                            notes=f"Brute-force: {error_code} ({category})",
                        ))
                    elif category == "deny":
                        results["denied"] += 1
                        profile.add_permission(PermissionEntry(
                            action=action,
                            allowed=False,
                            confidence=PermissionConfidence.CONFIRMED,
                            source=PermissionSource.DENY_CONFIRMED,
                            notes=f"Brute-force: {error_code}",
                        ))
                    else:
                        results["errors"] += 1

                    logger.debug(
                        "bf_probe_result",
                        action=action, category=category,
                        error_code=error_code, http=http_status,
                    )

                except Exception as exc:
                    results["errors"] += 1
                    logger.debug(
                        "bf_probe_exception",
                        action=action, error=str(exc),
                    )

                results["total"] += 1
                if _bf_cb:
                    _bf_cb(
                        "permission_resolver",
                        "bf_progress",
                        {
                            "done": results["total"],
                            "total": _bf_total_probes,
                            "succeeded": results["succeeded"],
                            "last_allowed": _this_allowed,
                        },
                    )

        # Group probes by service for client batching
        service_probes: dict[str, list[tuple[str, dict[str, Any], str]]] = {}
        for client_name, method, kwargs, action in BRUTEFORCE_PROBES:
            if action == "s3:ListBuckets":
                continue
            service_probes.setdefault(client_name, []).append(
                (method, kwargs, action),
            )

        async def _run_service_batch(
            client_name: str,
            probes: list[tuple[str, dict[str, Any], str]],
        ) -> None:
            """Create one client per service and run all its probes."""
            try:
                async with self._session.client(
                    client_name, region_name=region,
                ) as client:
                    tasks = [
                        _probe_one(client, client_name, m, kw, act)
                        for m, kw, act in probes
                    ]
                    await _asyncio.gather(*tasks)
            except Exception as exc:
                for _m, _kw, _act in probes:
                    results["errors"] += 1
                    results["total"] += 1
                logger.debug(
                    "bf_service_client_failed",
                    service=client_name,
                    probe_count=len(probes),
                    error=str(exc),
                )

        await _asyncio.gather(*[
            _run_service_batch(svc, probes)
            for svc, probes in service_probes.items()
        ])

        logger.info(
            "bruteforce_probes_complete",
            total=results["total"],
            succeeded=results["succeeded"],
            denied=results["denied"],
            errors=results["errors"],
            throttle_retries=results["throttle_retries"],
        )

        # ── Infer write permissions from confirmed read clusters ──────
        self._infer_write_from_read_cluster(profile, results)

        # ── Resource-scoped follow-up probes ──────────────────────────
        await self._probe_resource_scoped(
            profile, region, discovered_buckets=discovered_buckets,
        )

        return results

    # ==================================================================
    # Resource-scoped permission probing
    # ==================================================================
    async def _probe_resource_scoped(
        self,
        profile: IdentityPermissionProfile,
        region: str,
        discovered_buckets: list[str] | None = None,
    ) -> None:
        """Test permissions against specific discovered resources.

        After brute-force confirms general S3 access, this tests each
        discovered bucket for read/write to build a per-resource
        permission matrix for the attack graph.
        """
        if not discovered_buckets:
            discovered_buckets = []

        # Also add buckets discovered by earlier collectors
        for bucket_arn in self._graph.nodes_of_type(NodeType.S3_BUCKET):
            bucket_name = bucket_arn.split(":::")[-1] if ":::" in bucket_arn else ""
            if bucket_name and bucket_name not in discovered_buckets:
                discovered_buckets.append(bucket_name)

        if not discovered_buckets:
            return

        has_any_s3 = any(
            e.allowed and e.confidence == PermissionConfidence.CONFIRMED
            for a, e in profile.permissions.items()
            if a.startswith("s3:")
        )
        if not has_any_s3:
            return

        probed = 0
        for bucket_name in discovered_buckets[:10]:
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            try:
                async with self._session.client("s3", region_name=region) as s3:
                    # ListObjectsV2 → s3:ListBucket on this bucket
                    try:
                        await s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                        profile.add_permission(PermissionEntry(
                            action="s3:ListBucket",
                            allowed=True,
                            confidence=PermissionConfidence.CONFIRMED,
                            source=PermissionSource.SENTINEL_PROBE,
                            resource_arn=bucket_arn,
                            resource_arns=[bucket_arn, f"{bucket_arn}/*"],
                            notes=f"Resource probe: ListObjectsV2 on {bucket_name}",
                        ))
                    except ClientError:
                        pass

                    # HeadObject with fake key → 404 proves s3:GetObject
                    try:
                        await s3.head_object(
                            Bucket=bucket_name,
                            Key="__atlas_probe_nonexistent__",
                        )
                    except ClientError as exc:
                        code = exc.response.get("Error", {}).get("Code", "")
                        if code in ("404", "NoSuchKey"):
                            profile.add_permission(PermissionEntry(
                                action="s3:GetObject",
                                allowed=True,
                                confidence=PermissionConfidence.CONFIRMED,
                                source=PermissionSource.SENTINEL_PROBE,
                                resource_arn=f"{bucket_arn}/*",
                                resource_arns=[f"{bucket_arn}/*"],
                                notes=f"Resource probe: HeadObject 404 on {bucket_name}",
                            ))
                        elif code in _DENY_ERROR_CODES:
                            profile.add_permission(PermissionEntry(
                                action="s3:GetObject",
                                allowed=False,
                                confidence=PermissionConfidence.CONFIRMED,
                                source=PermissionSource.DENY_CONFIRMED,
                                resource_arn=f"{bucket_arn}/*",
                                resource_arns=[f"{bucket_arn}/*"],
                                notes=f"Resource probe: GetObject denied on {bucket_name}",
                            ))

                    probed += 1
            except Exception:
                pass

        if probed:
            logger.info("resource_scoped_probes_complete", buckets_probed=probed)

    # ==================================================================
    # Write inference from confirmed read clusters
    # ==================================================================
    _WRITE_INFERENCE_RULES: list[tuple[list[str], int, list[str]]] = [
        # (confirmed_read_actions, min_threshold, inferred_write_actions)
        # S3: 4+ read probes → infer write access
        (
            [
                "s3:ListBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
                "s3:GetBucketLocation", "s3:GetPublicAccessBlock",
                "s3:ListBucket", "s3:HeadBucket",
            ],
            4,
            [
                "s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy",
                "s3:GetObject",
            ],
        ),
        # EC2: 5+ describe → infer modify
        (
            [
                "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs", "ec2:DescribeSubnets",
                "ec2:DescribeSnapshots", "ec2:DescribeVolumes",
                "ec2:DescribeImages", "ec2:DescribeAddresses",
                "ec2:DescribeKeyPairs", "ec2:DescribeNetworkInterfaces",
            ],
            5,
            [
                "ec2:RunInstances", "ec2:StartInstances",
                "ec2:ModifyInstanceAttribute",
                "ec2:CreateSnapshot", "ec2:ModifySnapshotAttribute",
            ],
        ),
        # IAM: 5+ read → infer write
        (
            [
                "iam:ListUsers", "iam:ListRoles", "iam:ListGroups",
                "iam:ListPolicies", "iam:ListAccessKeys",
                "iam:GetAccountAuthorizationDetails",
                "iam:GetAccountSummary",
            ],
            5,
            [
                "iam:CreateAccessKey", "iam:AttachUserPolicy",
                "iam:AttachRolePolicy", "iam:PutUserPolicy",
                "iam:PutRolePolicy", "iam:CreateRole",
                "iam:UpdateAssumeRolePolicy",
            ],
        ),
        # Lambda: 2+ list → infer invoke/update
        (
            [
                "lambda:ListFunctions", "lambda:ListLayers",
                "lambda:ListEventSourceMappings",
            ],
            2,
            [
                "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
                "lambda:CreateFunction",
            ],
        ),
        # Secrets Manager: 1+ read → infer read secret values
        (
            ["secretsmanager:ListSecrets"],
            1,
            [
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
            ],
        ),
        # KMS: 2+ read → infer key usage
        (
            ["kms:ListKeys", "kms:ListAliases"],
            2,
            ["kms:DescribeKey", "kms:Decrypt", "kms:Encrypt"],
        ),
        # SSM: 1+ read → infer parameter access
        (
            ["ssm:DescribeParameters", "ssm:DescribeInstanceInformation"],
            1,
            ["ssm:GetParameter", "ssm:GetParameters", "ssm:PutParameter"],
        ),
        # RDS: 2+ read → infer snapshot ops
        (
            [
                "rds:DescribeDBInstances", "rds:DescribeDBClusters",
                "rds:DescribeDBSnapshots",
            ],
            2,
            [
                "rds:CreateDBSnapshot", "rds:ModifyDBSnapshotAttribute",
                "rds:CopyDBSnapshot",
            ],
        ),
        # DynamoDB: 1+ read → infer table access
        (
            ["dynamodb:ListTables"],
            1,
            [
                "dynamodb:DescribeTable", "dynamodb:GetItem",
                "dynamodb:PutItem", "dynamodb:Scan",
            ],
        ),
        # CloudFormation: 2+ read → infer stack ops
        (
            ["cloudformation:DescribeStacks", "cloudformation:ListStacks"],
            2,
            [
                "cloudformation:CreateStack",
                "cloudformation:UpdateStack",
                "cloudformation:GetTemplate",
            ],
        ),
        # SNS/SQS: 1+ read → infer publish/send
        (
            ["sns:ListTopics", "sns:ListSubscriptions"],
            1,
            ["sns:Publish", "sns:Subscribe"],
        ),
        (
            ["sqs:ListQueues"],
            1,
            ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:GetQueueAttributes"],
        ),
        # Logs: 1+ read → infer log access
        (
            ["logs:DescribeLogGroups"],
            1,
            ["logs:GetLogEvents", "logs:FilterLogEvents"],
        ),
    ]

    def _infer_write_from_read_cluster(
        self,
        profile: "IdentityPermissionProfile",
        results: dict[str, Any],
    ) -> None:
        """Infer write permissions when a cluster of reads is confirmed.

        When brute-force confirms many read-only actions for a service
        (e.g. 5+ S3 read probes succeed), it strongly suggests the
        identity has broad access (e.g. AmazonS3FullAccess / s3:*).
        In that case, add write permissions with INFERRED confidence
        so the attack graph can build write edges.
        """
        confirmed_actions = {
            a for a, e in profile.permissions.items()
            if e.allowed and e.confidence == PermissionConfidence.CONFIRMED
        }

        inferred_count = 0
        for read_actions, threshold, write_actions in self._WRITE_INFERENCE_RULES:
            matches = sum(1 for a in read_actions if a in confirmed_actions)
            if matches >= threshold:
                for w_action in write_actions:
                    # Don't override if already confirmed denied
                    existing = profile.permissions.get(w_action)
                    if existing and not existing.allowed:
                        continue  # respect confirmed denies
                    if existing and existing.allowed:
                        continue  # already confirmed allowed
                    profile.add_permission(PermissionEntry(
                        action=w_action,
                        allowed=True,
                        confidence=PermissionConfidence.INFERRED,
                        source=PermissionSource.SENTINEL_PROBE,
                        notes=(
                            f"Inferred from {matches}/{len(read_actions)} "
                            f"confirmed read probes for this service"
                        ),
                    ))
                    inferred_count += 1

        if inferred_count:
            logger.info(
                "write_permissions_inferred",
                inferred_count=inferred_count,
                confirmed_reads=len(confirmed_actions),
            )

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
