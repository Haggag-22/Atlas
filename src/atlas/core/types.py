"""
atlas.core.types
~~~~~~~~~~~~~~~~
Shared enums, type aliases, and constants used across all layers.

Every layer imports from here -- never from each other directly.
"""

from __future__ import annotations

from enum import Enum, unique


# ---------------------------------------------------------------------------
# Layer identifiers (used in telemetry, logging, safety checks)
# ---------------------------------------------------------------------------
@unique
class Layer(str, Enum):
    """Which architectural layer generated an event."""
    RECON = "recon"
    PLANNER = "planner"
    EXECUTOR = "executor"
    CLI = "cli"
    SAFETY = "safety"


# ---------------------------------------------------------------------------
# Graph node / edge taxonomy
# ---------------------------------------------------------------------------
@unique
class NodeType(str, Enum):
    """Types of nodes in the EnvironmentModel graph."""
    USER = "iam_user"
    ROLE = "iam_role"
    GROUP = "iam_group"
    POLICY = "iam_policy"
    S3_BUCKET = "s3_bucket"
    EC2_INSTANCE = "ec2_instance"
    LAMBDA_FUNCTION = "lambda_function"
    RDS_INSTANCE = "rds_instance"
    KMS_KEY = "kms_key"
    SECRETS_MANAGER = "secrets_manager"
    SSM_PARAMETER = "ssm_parameter"
    CLOUDFORMATION_STACK = "cloudformation_stack"
    ACCOUNT = "account"
    CREDENTIAL = "credential"


@unique
class EdgeType(str, Enum):
    """Types of edges (relationships / transitions) in the graph."""
    # Identity relationships
    HAS_POLICY = "has_policy"              # identity -> policy
    MEMBER_OF = "member_of"                # user -> group
    HAS_INLINE_POLICY = "has_inline_policy"
    HAS_PERMISSION_BOUNDARY = "has_permission_boundary"

    # Trust / assumption
    CAN_ASSUME = "can_assume"              # identity -> role  (via trust policy)
    TRUSTS = "trusts"                      # role -> principal (trust policy direction)
    CAN_PASSROLE = "can_passrole"          # identity -> role  (iam:PassRole)

    # Resource access
    HAS_ACCESS_TO = "has_access_to"        # identity -> resource
    RESOURCE_POLICY_ALLOWS = "resource_policy_allows"  # resource -> identity (inverse)
    CAN_READ_S3 = "can_read_s3"            # identity -> s3 bucket (read access)
    CAN_WRITE_S3 = "can_write_s3"          # identity -> s3 bucket (write access)

    # Privilege escalation edges
    CAN_CREATE_KEY = "can_create_key"      # identity -> target_user
    CAN_ATTACH_POLICY = "can_attach_policy"
    CAN_PUT_POLICY = "can_put_policy"
    CAN_CREATE_ROLE = "can_create_role"
    CAN_UPDATE_LAMBDA = "can_update_lambda"
    CAN_CREATE_LAMBDA = "can_create_lambda"
    CAN_MODIFY_TRUST = "can_modify_trust"

    # Credential chain
    CREDENTIAL_FOR = "credential_for"      # credential -> identity


# ---------------------------------------------------------------------------
# Detection / stealth classification
# ---------------------------------------------------------------------------
@unique
class NoiseLevel(str, Enum):
    """How noisy an action is from a detection standpoint."""
    SILENT = "silent"      # No CloudTrail event at all
    LOW = "low"            # Read-only, baseline API
    MEDIUM = "medium"      # Write API but common in automation
    HIGH = "high"          # Creates/modifies IAM, triggers GuardDuty
    CRITICAL = "critical"  # Almost certainly triggers alerts


@unique
class CloudTrailVisibility(str, Enum):
    """How an API call appears in CloudTrail."""
    MANAGEMENT_READ = "management_read"
    MANAGEMENT_WRITE = "management_write"
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    NOT_LOGGED = "not_logged"


# ---------------------------------------------------------------------------
# Operation state machine
# ---------------------------------------------------------------------------
@unique
class OperationPhase(str, Enum):
    """Current phase of an operation."""
    INITIALIZING = "initializing"
    RECON = "recon"
    PLANNING = "planning"
    EXECUTING = "executing"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"


@unique
class ActionStatus(str, Enum):
    """Outcome of a single executor action."""
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"       # dry-run or planner decided to skip
    BLOCKED = "blocked"       # guardrail prevented execution
    PERMISSION_DENIED = "permission_denied"


# ---------------------------------------------------------------------------
# Strategy identifiers
# ---------------------------------------------------------------------------
@unique
class Strategy(str, Enum):
    """High-level attack strategy the planner can select."""
    LIVING_OFF_THE_LAND = "living_off_the_land"
    TRUST_CHAIN_PIVOT = "trust_chain_pivot"
    SLOW_ESCALATION = "slow_escalation"
    RESOURCE_POLICY_ABUSE = "resource_policy_abuse"
    CREDENTIAL_HARVESTING = "credential_harvesting"


# ---------------------------------------------------------------------------
# Severity levels (for findings, guardrail analysis)
# ---------------------------------------------------------------------------
@unique
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
