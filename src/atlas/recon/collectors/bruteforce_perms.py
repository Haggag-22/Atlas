"""
atlas.recon.collectors.bruteforce_perms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
IAM permission brute-force enumeration.

When policy documents and GetAccountAuthorizationDetails are unavailable,
this module tries every read-only API call we care about and records
which ones succeed vs get AccessDenied.

Integrates Andres Riancho's enumerate-iam probe list (1100+ API calls
across 130+ services) with Atlas's own curated probes (which carry
optimized kwargs and dynamic placeholders).

Each probe is a *safe, read-only* API call with minimal side effects.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Comprehensive brute-force probe list
# Each entry: (client, method, kwargs, iam_action)
# All calls are read-only / non-mutating.
# ---------------------------------------------------------------------------
BRUTEFORCE_PROBES: list[tuple[str, str, dict[str, Any], str]] = [
    # ── STS ────────────────────────────────────────────────────────────
    ("sts", "get_caller_identity", {}, "sts:GetCallerIdentity"),
    ("sts", "get_session_token", {}, "sts:GetSessionToken"),

    # ── IAM ────────────────────────────────────────────────────────────
    ("iam", "list_users", {"MaxItems": 1}, "iam:ListUsers"),
    ("iam", "list_roles", {"MaxItems": 1}, "iam:ListRoles"),
    ("iam", "list_groups", {"MaxItems": 1}, "iam:ListGroups"),
    ("iam", "list_policies", {"MaxItems": 1, "Scope": "Local"}, "iam:ListPolicies"),
    ("iam", "list_access_keys", {}, "iam:ListAccessKeys"),
    ("iam", "list_mfa_devices", {}, "iam:ListMFADevices"),
    ("iam", "list_account_aliases", {}, "iam:ListAccountAliases"),
    ("iam", "get_account_authorization_details", {"MaxItems": 1}, "iam:GetAccountAuthorizationDetails"),
    ("iam", "get_credential_report", {}, "iam:GetCredentialReport"),
    ("iam", "get_account_summary", {}, "iam:GetAccountSummary"),
    ("iam", "get_account_password_policy", {}, "iam:GetAccountPasswordPolicy"),
    ("iam", "list_attached_user_policies", {"UserName": "__CALLER__"}, "iam:ListAttachedUserPolicies"),
    ("iam", "list_user_policies", {"UserName": "__CALLER__"}, "iam:ListUserPolicies"),
    ("iam", "list_groups_for_user", {"UserName": "__CALLER__"}, "iam:ListGroupsForUser"),

    # ── S3 ─────────────────────────────────────────────────────────────
    ("s3", "list_buckets", {}, "s3:ListBuckets"),
    ("s3", "get_bucket_location", {"Bucket": "__FIRST_BUCKET__"}, "s3:GetBucketLocation"),
    ("s3", "get_bucket_policy", {"Bucket": "__FIRST_BUCKET__"}, "s3:GetBucketPolicy"),
    ("s3", "get_bucket_acl", {"Bucket": "__FIRST_BUCKET__"}, "s3:GetBucketAcl"),
    ("s3", "get_public_access_block", {"Bucket": "__FIRST_BUCKET__"}, "s3:GetPublicAccessBlock"),
    ("s3", "list_objects_v2", {"Bucket": "__FIRST_BUCKET__", "MaxKeys": 1}, "s3:ListBucket"),
    ("s3", "head_bucket", {"Bucket": "__FIRST_BUCKET__"}, "s3:HeadBucket"),

    # ── EC2 ────────────────────────────────────────────────────────────
    ("ec2", "describe_instances", {"MaxResults": 5}, "ec2:DescribeInstances"),
    ("ec2", "describe_security_groups", {"MaxResults": 5}, "ec2:DescribeSecurityGroups"),
    ("ec2", "describe_vpcs", {"MaxResults": 5}, "ec2:DescribeVpcs"),
    ("ec2", "describe_subnets", {"MaxResults": 5}, "ec2:DescribeSubnets"),
    ("ec2", "describe_snapshots", {"OwnerIds": ["self"], "MaxResults": 5}, "ec2:DescribeSnapshots"),
    ("ec2", "describe_volumes", {"MaxResults": 5}, "ec2:DescribeVolumes"),
    ("ec2", "describe_images", {"Owners": ["self"], "MaxResults": 5}, "ec2:DescribeImages"),
    ("ec2", "describe_addresses", {}, "ec2:DescribeAddresses"),
    ("ec2", "describe_key_pairs", {}, "ec2:DescribeKeyPairs"),
    ("ec2", "describe_network_interfaces", {"MaxResults": 5}, "ec2:DescribeNetworkInterfaces"),
    ("ec2", "describe_route_tables", {"MaxResults": 5}, "ec2:DescribeRouteTables"),
    ("ec2", "describe_internet_gateways", {"MaxResults": 5}, "ec2:DescribeInternetGateways"),
    ("ec2", "describe_nat_gateways", {"MaxResults": 5}, "ec2:DescribeNatGateways"),

    # ── Lambda ─────────────────────────────────────────────────────────
    ("lambda", "list_functions", {"MaxItems": 1}, "lambda:ListFunctions"),
    ("lambda", "list_layers", {"MaxItems": 1}, "lambda:ListLayers"),
    ("lambda", "list_event_source_mappings", {"MaxItems": 1}, "lambda:ListEventSourceMappings"),

    # ── RDS ─────────────────────────────────────────────────────────────
    ("rds", "describe_db_instances", {"MaxRecords": 20}, "rds:DescribeDBInstances"),
    ("rds", "describe_db_clusters", {"MaxRecords": 20}, "rds:DescribeDBClusters"),
    ("rds", "describe_db_snapshots", {"MaxRecords": 20}, "rds:DescribeDBSnapshots"),

    # ── KMS ─────────────────────────────────────────────────────────────
    ("kms", "list_keys", {"Limit": 1}, "kms:ListKeys"),
    ("kms", "list_aliases", {"Limit": 1}, "kms:ListAliases"),

    # ── Secrets Manager ────────────────────────────────────────────────
    ("secretsmanager", "list_secrets", {"MaxResults": 1}, "secretsmanager:ListSecrets"),

    # ── SSM ────────────────────────────────────────────────────────────
    ("ssm", "describe_parameters", {"MaxResults": 1}, "ssm:DescribeParameters"),
    ("ssm", "describe_instance_information", {"MaxResults": 5}, "ssm:DescribeInstanceInformation"),

    # ── CloudFormation ─────────────────────────────────────────────────
    ("cloudformation", "describe_stacks", {}, "cloudformation:DescribeStacks"),
    ("cloudformation", "list_stacks", {}, "cloudformation:ListStacks"),

    # ── CloudTrail ─────────────────────────────────────────────────────
    ("cloudtrail", "describe_trails", {}, "cloudtrail:DescribeTrails"),
    ("cloudtrail", "get_trail_status", {"Name": "__FIRST_TRAIL__"}, "cloudtrail:GetTrailStatus"),

    # ── GuardDuty ──────────────────────────────────────────────────────
    ("guardduty", "list_detectors", {}, "guardduty:ListDetectors"),

    # ── Config ─────────────────────────────────────────────────────────
    ("config", "describe_configuration_recorders", {}, "config:DescribeConfigurationRecorders"),
    ("config", "describe_compliance_by_config_rule", {}, "config:DescribeComplianceByConfigRule"),

    # ── Organizations ──────────────────────────────────────────────────
    ("organizations", "describe_organization", {}, "organizations:DescribeOrganization"),
    ("organizations", "list_accounts", {}, "organizations:ListAccounts"),

    # ── IAM Access Analyzer ────────────────────────────────────────────
    ("accessanalyzer", "list_analyzers", {}, "access-analyzer:ListAnalyzers"),

    # ── Security Hub ───────────────────────────────────────────────────
    ("securityhub", "get_enabled_standards", {}, "securityhub:GetEnabledStandards"),

    # ── SNS ────────────────────────────────────────────────────────────
    ("sns", "list_topics", {}, "sns:ListTopics"),
    ("sns", "list_subscriptions", {}, "sns:ListSubscriptions"),

    # ── SQS ────────────────────────────────────────────────────────────
    ("sqs", "list_queues", {"MaxResults": 1}, "sqs:ListQueues"),

    # ── DynamoDB ───────────────────────────────────────────────────────
    ("dynamodb", "list_tables", {"Limit": 1}, "dynamodb:ListTables"),

    # ── ECS ────────────────────────────────────────────────────────────
    ("ecs", "list_clusters", {"maxResults": 1}, "ecs:ListClusters"),
    ("ecs", "list_task_definitions", {"maxResults": 1}, "ecs:ListTaskDefinitions"),

    # ── EKS ────────────────────────────────────────────────────────────
    ("eks", "list_clusters", {"maxResults": 1}, "eks:ListClusters"),

    # ── ECR ────────────────────────────────────────────────────────────
    ("ecr", "describe_repositories", {"maxResults": 1}, "ecr:DescribeRepositories"),

    # ── CloudWatch ─────────────────────────────────────────────────────
    ("cloudwatch", "list_metrics", {"RecentlyActive": "PT3H"}, "cloudwatch:ListMetrics"),
    ("logs", "describe_log_groups", {"limit": 1}, "logs:DescribeLogGroups"),

    # ── Backup ─────────────────────────────────────────────────────────
    ("backup", "list_backup_plans", {"MaxResults": 1}, "backup:ListBackupPlans"),
    ("backup", "list_protected_resources", {"MaxResults": 1}, "backup:ListProtectedResources"),
    ("backup", "list_backup_vaults", {"MaxResults": 1}, "backup:ListBackupVaults"),

    # ── Elastic Load Balancing ─────────────────────────────────────────
    ("elbv2", "describe_load_balancers", {"PageSize": 1}, "elasticloadbalancing:DescribeLoadBalancers"),

    # ── Route53 ────────────────────────────────────────────────────────
    ("route53", "list_hosted_zones", {"MaxItems": "1"}, "route53:ListHostedZones"),

    # ── ACM ────────────────────────────────────────────────────────────
    ("acm", "list_certificates", {"MaxItems": 1}, "acm:ListCertificates"),

    # ── CodeBuild / CodePipeline ───────────────────────────────────────
    ("codebuild", "list_projects", {}, "codebuild:ListProjects"),
    ("codepipeline", "list_pipelines", {}, "codepipeline:ListPipelines"),

    # ── Glue ───────────────────────────────────────────────────────────
    ("glue", "get_databases", {"MaxResults": 1}, "glue:GetDatabases"),

    # ── Athena ─────────────────────────────────────────────────────────
    ("athena", "list_work_groups", {}, "athena:ListWorkGroups"),

    # ── ElastiCache ────────────────────────────────────────────────────
    ("elasticache", "describe_cache_clusters", {"MaxRecords": 20}, "elasticache:DescribeCacheClusters"),

    # ── Redshift ───────────────────────────────────────────────────────
    ("redshift", "describe_clusters", {"MaxRecords": 20}, "redshift:DescribeClusters"),

    # ── SageMaker ──────────────────────────────────────────────────────
    ("sagemaker", "list_notebook_instances", {"MaxResults": 1}, "sagemaker:ListNotebookInstances"),

    # ── Step Functions ─────────────────────────────────────────────────
    ("stepfunctions", "list_state_machines", {"maxResults": 1}, "states:ListStateMachines"),

    # ── EventBridge ────────────────────────────────────────────────────
    ("events", "list_rules", {"Limit": 1}, "events:ListRules"),

    # ── Kinesis ────────────────────────────────────────────────────────
    ("kinesis", "list_streams", {"Limit": 1}, "kinesis:ListStreams"),
]

# ---------------------------------------------------------------------------
# enumerate-iam integration
# ---------------------------------------------------------------------------
# Mapping from enumerate-iam service names to IAM action prefixes.
# Most services use the boto3 client name as-is, but a few differ.
_SERVICE_IAM_PREFIX: dict[str, str] = {
    "monitoring": "cloudwatch",
    "email": "ses",
    "models.lex": "lex",
    "streams.dynamodb": "dynamodb",
    "elasticmapreduce": "emr",
    "mturk-requester": "mturk",
    "devices.iot1click": "iot1click",
    "projects.iot1click": "iot1click",
    "data.mediastore": "mediastore",
    "sms-voice.pinpoint": "sms-voice",
    "a4b": "a4b",
    "opworks": "opsworks",
}

# enumerate-iam service names that are NOT valid boto3 client names.
# These need a different boto3 client name to actually call the API.
_SERVICE_BOTO3_CLIENT: dict[str, str] = {
    "monitoring": "cloudwatch",
    "email": "ses",
    "models.lex": "lex-models",
    "streams.dynamodb": "dynamodbstreams",
    "elasticmapreduce": "emr",
    "mturk-requester": "mturk",
    "devices.iot1click": "iot1click-devices",
    "projects.iot1click": "iot1click-projects",
    "data.mediastore": "mediastore-data",
    "sms-voice.pinpoint": "pinpoint-sms-voice",
    "appstream2": "appstream",
    "opworks": "opsworkscm",
}


def _snake_to_camel(name: str) -> str:
    """Convert snake_case method name to CamelCase IAM action name.

    Examples:
        list_buckets      -> ListBuckets
        describe_instances -> DescribeInstances
        get_user          -> GetUser
    """
    return "".join(word.capitalize() for word in name.split("_"))


def _load_enumerate_iam_probes() -> list[tuple[str, str, dict[str, Any], str]]:
    """Load the vendored enumerate-iam probe list and convert to Atlas format.

    The vendored data lives in ``enumerate_iam_data.py`` (generated from
    Andres Riancho's enumerate-iam project).  Falls back to trying the
    external ``enumerate-iam`` package if the vendored file is missing,
    and returns an empty list if neither is available.
    """
    tests: dict[str, list[str]] | None = None

    # Try vendored data first (always available if repo is intact)
    try:
        from atlas.recon.collectors.enumerate_iam_data import ENUMERATE_IAM_TESTS
        tests = ENUMERATE_IAM_TESTS
    except ImportError:
        pass

    # Fallback: try the external enumerate-iam package
    if tests is None:
        try:
            from enumerate_iam.bruteforce_tests import BRUTEFORCE_TESTS  # type: ignore[import-untyped]
            tests = BRUTEFORCE_TESTS
        except ImportError:
            logger.debug(
                "No enumerate-iam data found — using Atlas built-in probes only"
            )
            return []

    probes: list[tuple[str, str, dict[str, Any], str]] = []
    seen: set[tuple[str, str]] = set()

    for service_name, methods in tests.items():
        # Resolve the boto3 client name (may differ from the API service name)
        boto3_client = _SERVICE_BOTO3_CLIENT.get(service_name, service_name)

        # Resolve the IAM action prefix
        iam_prefix = _SERVICE_IAM_PREFIX.get(service_name, service_name)

        for method in methods:
            key = (boto3_client, method)
            if key in seen:
                continue  # enumerate-iam has many duplicates
            seen.add(key)

            iam_action = f"{iam_prefix}:{_snake_to_camel(method)}"
            probes.append((boto3_client, method, {}, iam_action))

    logger.debug(
        "enumerate-iam data loaded: %d unique probes from %d services",
        len(probes),
        len(tests),
    )
    return probes


def build_merged_probes() -> list[tuple[str, str, dict[str, Any], str]]:
    """Build the final probe list by merging Atlas + enumerate-iam probes.

    Atlas's built-in BRUTEFORCE_PROBES take priority because they carry
    optimized kwargs (MaxItems, MaxResults, Limit) and dynamic
    placeholders (__FIRST_BUCKET__, __CALLER__, __FIRST_TRAIL__).

    enumerate-iam probes fill in coverage gaps across 130+ services.
    """
    # Index Atlas probes by (client, method) for fast lookup
    atlas_keys: set[tuple[str, str]] = set()
    for client, method, _kwargs, _action in BRUTEFORCE_PROBES:
        atlas_keys.add((client, method))

    # Start with all Atlas probes
    merged = list(BRUTEFORCE_PROBES)

    # Add enumerate-iam probes that Atlas doesn't already cover
    external = _load_enumerate_iam_probes()
    added = 0
    for probe in external:
        client, method = probe[0], probe[1]
        if (client, method) not in atlas_keys:
            merged.append(probe)
            atlas_keys.add((client, method))
            added += 1

    if external:
        logger.debug(
            "Merged probes: %d Atlas + %d from enumerate-iam = %d total",
            len(BRUTEFORCE_PROBES),
            added,
            len(merged),
        )

    return merged
