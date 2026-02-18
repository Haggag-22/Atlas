"""
atlas.core.models
~~~~~~~~~~~~~~~~~
Core data models shared across all three layers.

These models represent the *state of the world* as Atlas understands it.
The EnvironmentModel is the central structure that the Recon layer builds
and the Planner layer consumes.

Design rules:
  - Every model is immutable after construction (frozen Pydantic).
  - Mutable state lives only in the EnvironmentModel graph, never in these DTOs.
  - No AWS SDK imports here -- pure data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from atlas.core.types import (
    CloudTrailVisibility,
    EdgeType,
    NodeType,
    NoiseLevel,
    Severity,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════
# Identity models
# ═══════════════════════════════════════════════════════════════════════════
class IAMUser(BaseModel):
    """Represents a discovered IAM user."""
    model_config = {"frozen": True}

    arn: str
    user_name: str
    user_id: str
    account_id: str
    path: str = "/"
    create_date: str | None = None
    password_last_used: str | None = None
    has_console_access: bool = False
    has_mfa: bool = False
    access_key_ids: list[str] = Field(default_factory=list)
    inline_policy_names: list[str] = Field(default_factory=list)
    attached_policy_arns: list[str] = Field(default_factory=list)
    group_names: list[str] = Field(default_factory=list)
    permission_boundary_arn: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class IAMRole(BaseModel):
    """Represents a discovered IAM role with its trust policy."""
    model_config = {"frozen": True}

    arn: str
    role_name: str
    role_id: str
    account_id: str
    path: str = "/"
    trust_policy: dict[str, Any] = Field(default_factory=dict)
    inline_policy_names: list[str] = Field(default_factory=list)
    attached_policy_arns: list[str] = Field(default_factory=list)
    permission_boundary_arn: str | None = None
    max_session_duration: int = 3600
    is_service_linked: bool = False
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class IAMGroup(BaseModel):
    """Represents a discovered IAM group."""
    model_config = {"frozen": True}

    arn: str
    group_name: str
    group_id: str
    path: str = "/"
    inline_policy_names: list[str] = Field(default_factory=list)
    attached_policy_arns: list[str] = Field(default_factory=list)
    member_user_arns: list[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=_now_iso)


class IAMPolicy(BaseModel):
    """Represents a discovered IAM policy (managed or inline)."""
    model_config = {"frozen": True}

    arn: str | None = None          # None for inline policies
    policy_name: str
    policy_document: dict[str, Any] = Field(default_factory=dict)
    is_aws_managed: bool = False
    is_inline: bool = False
    attached_to: str | None = None  # ARN of entity this is inline on
    version_id: str | None = None
    discovered_at: str = Field(default_factory=_now_iso)


# ═══════════════════════════════════════════════════════════════════════════
# Resource models
# ═══════════════════════════════════════════════════════════════════════════
class S3Bucket(BaseModel):
    model_config = {"frozen": True}

    name: str
    arn: str
    region: str | None = None
    creation_date: str | None = None
    public_access_block: dict[str, bool] = Field(default_factory=dict)
    bucket_policy: dict[str, Any] | None = None
    versioning_enabled: bool = False
    encryption_config: dict[str, Any] | None = None
    logging_enabled: bool = False
    discovered_at: str = Field(default_factory=_now_iso)


class EC2Instance(BaseModel):
    model_config = {"frozen": True}

    instance_id: str
    arn: str
    region: str
    state: str = "unknown"
    instance_profile_arn: str | None = None
    public_ip: str | None = None
    private_ip: str | None = None
    security_group_ids: list[str] = Field(default_factory=list)
    subnet_id: str | None = None
    vpc_id: str | None = None
    user_data_available: bool = False
    imds_v2_required: bool = False
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class ECSTaskDefinition(BaseModel):
    """Represents an ECS task definition with its task role."""

    model_config = {"frozen": True}

    family: str
    arn: str
    region: str
    task_role_arn: str | None = None
    execution_role_arn: str | None = None
    network_mode: str = "bridge"
    launch_type: str = "EC2"  # EC2 | FARGATE
    discovered_at: str = Field(default_factory=_now_iso)


class LambdaFunction(BaseModel):
    model_config = {"frozen": True}

    function_name: str
    arn: str
    region: str
    runtime: str | None = None
    role_arn: str | None = None
    handler: str | None = None
    environment_variables: dict[str, str] = Field(default_factory=dict)
    layers: list[str] = Field(default_factory=list)
    resource_policy: dict[str, Any] | None = None
    discovered_at: str = Field(default_factory=_now_iso)


class RDSInstance(BaseModel):
    """Represents a discovered RDS database instance."""
    model_config = {"frozen": True}

    db_instance_identifier: str
    arn: str
    region: str
    engine: str = ""                               # e.g. "mysql", "postgres", "aurora"
    engine_version: str = ""
    db_instance_class: str = ""
    storage_encrypted: bool = False
    publicly_accessible: bool = False
    endpoint_address: str | None = None
    endpoint_port: int | None = None
    vpc_id: str | None = None
    subnet_group_name: str | None = None
    security_group_ids: list[str] = Field(default_factory=list)
    iam_auth_enabled: bool = False
    multi_az: bool = False
    auto_minor_version_upgrade: bool = True
    master_username: str = ""
    kms_key_id: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class KMSKey(BaseModel):
    """Represents a discovered KMS key."""
    model_config = {"frozen": True}

    key_id: str
    arn: str
    region: str
    description: str = ""
    key_state: str = "Enabled"                     # Enabled | Disabled | PendingDeletion
    key_manager: str = "CUSTOMER"                  # CUSTOMER | AWS
    key_usage: str = "ENCRYPT_DECRYPT"
    origin: str = "AWS_KMS"
    key_policy: dict[str, Any] | None = None
    grants: list[dict[str, Any]] = Field(default_factory=list)
    rotation_enabled: bool = False
    aliases: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class ECRRepository(BaseModel):
    """Represents an ECR repository with its resource policy."""

    model_config = {"frozen": True}

    repository_name: str
    arn: str
    region: str
    repository_uri: str = ""
    resource_policy: dict[str, Any] | None = None
    image_tag_mutability: str = "MUTABLE"
    discovered_at: str = Field(default_factory=_now_iso)


class CognitoUserPool(BaseModel):
    """Represents a Cognito User Pool (authn)."""

    model_config = {"frozen": True}

    pool_id: str
    arn: str
    region: str
    name: str = ""
    admin_create_user_config: dict[str, Any] = Field(default_factory=dict)
    auto_verified_attributes: list[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=_now_iso)


class CognitoIdentityPool(BaseModel):
    """Represents a Cognito Identity Pool (federation -> temp AWS creds)."""

    model_config = {"frozen": True}

    identity_pool_id: str
    arn: str
    region: str
    identity_pool_name: str = ""
    roles: dict[str, str] = Field(default_factory=dict)  # authenticated, unauthenticated
    allow_unauthenticated: bool = False
    discovered_at: str = Field(default_factory=_now_iso)


class CloudFrontDistribution(BaseModel):
    """Represents a CloudFront distribution with S3 origin (takeover vector)."""

    model_config = {"frozen": True}

    distribution_id: str
    arn: str
    origin_domain: str
    origin_bucket: str
    aliases: list[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=_now_iso)


class SecretsManagerSecret(BaseModel):
    """Represents a discovered Secrets Manager secret (value NOT stored)."""
    model_config = {"frozen": True}

    name: str
    arn: str
    region: str
    description: str = ""
    kms_key_id: str | None = None
    rotation_enabled: bool = False
    rotation_lambda_arn: str | None = None
    last_accessed_date: str | None = None
    last_rotated_date: str | None = None
    resource_policy: dict[str, Any] | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class SSMParameter(BaseModel):
    """Represents a discovered SSM Parameter Store parameter (value NOT stored)."""
    model_config = {"frozen": True}

    name: str
    arn: str
    region: str
    type: str = "String"                           # String | StringList | SecureString
    description: str = ""
    tier: str = "Standard"                         # Standard | Advanced | Intelligent-Tiering
    version: int = 1
    last_modified_date: str | None = None
    kms_key_id: str | None = None                  # for SecureString
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class CloudFormationStack(BaseModel):
    """Represents a discovered CloudFormation stack."""
    model_config = {"frozen": True}

    stack_name: str
    stack_id: str
    arn: str
    region: str
    status: str = ""                               # e.g. "CREATE_COMPLETE"
    role_arn: str | None = None                    # IAM role used for stack operations
    template_description: str = ""
    creation_time: str | None = None
    last_updated_time: str | None = None
    capabilities: list[str] = Field(default_factory=list)  # e.g. ["CAPABILITY_IAM"]
    outputs: list[dict[str, str]] = Field(default_factory=list)
    parameters: list[dict[str, str]] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class EBSSnapshot(BaseModel):
    """Represents a publicly exposed EBS snapshot discovered for the target account.

    Public EBS snapshots are globally queryable via ec2:DescribeSnapshots
    with ``--restorable-by-user-ids all --owner-ids <account_id>``.
    Anyone with ANY AWS account can discover and clone these snapshots,
    gaining full read access to the underlying filesystem data.
    """
    model_config = {"frozen": True}

    snapshot_id: str
    arn: str
    region: str
    owner_id: str                                  # Account ID that owns the snapshot
    volume_id: str | None = None                   # Source EBS volume ID
    volume_size_gb: int = 0                        # Size of the snapshot in GiB
    description: str = ""                          # Snapshot description (often contains context)
    encrypted: bool = False                        # Whether the snapshot is encrypted
    kms_key_id: str | None = None                  # KMS key used for encryption
    state: str = "completed"                       # pending | completed | error | recoverable
    start_time: str | None = None                  # When the snapshot was created
    is_public: bool = True                         # Always True for discovered public snapshots
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class BackupPlan(BaseModel):
    """Represents a discovered AWS Backup plan with schedule and resource targets."""
    model_config = {"frozen": True}

    plan_id: str
    plan_name: str
    arn: str
    region: str
    creation_date: str | None = None
    rules: list[dict[str, Any]] = Field(default_factory=list)
    # Resources targeted by this plan (ARNs discovered via selections)
    protected_resource_arns: list[str] = Field(default_factory=list)
    protected_resource_types: list[str] = Field(default_factory=list)
    # Selection metadata (naming conventions, tag strategies)
    selections: list[dict[str, Any]] = Field(default_factory=list)
    # IAM role used by the backup service
    backup_role_arn: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=_now_iso)


class ProtectedResource(BaseModel):
    """A resource discovered via AWS Backup (may not appear in direct service enumeration)."""
    model_config = {"frozen": True}

    resource_arn: str
    resource_type: str                             # e.g. "RDS", "EC2", "EBS", "DynamoDB"
    resource_name: str = ""
    last_backup_time: str | None = None
    last_backup_vault_arn: str | None = None
    discovered_via_backup: bool = True             # flag: found through Backup, not direct enum
    discovered_at: str = Field(default_factory=_now_iso)


# ═══════════════════════════════════════════════════════════════════════════
# Guardrail models
# ═══════════════════════════════════════════════════════════════════════════
class SCPPolicy(BaseModel):
    """Service Control Policy from AWS Organizations."""
    model_config = {"frozen": True}

    policy_id: str
    policy_name: str
    description: str = ""
    policy_document: dict[str, Any] = Field(default_factory=dict)
    targets: list[str] = Field(default_factory=list)  # OUs / account IDs
    discovered_at: str = Field(default_factory=_now_iso)


class GuardrailState(BaseModel):
    """Aggregated guardrail posture of the account."""

    scps: list[SCPPolicy] = Field(default_factory=list)
    permission_boundaries: dict[str, str] = Field(
        default_factory=dict,
        description="Map of identity ARN -> boundary policy ARN",
    )
    mfa_enforcement: dict[str, bool] = Field(
        default_factory=dict,
        description="Map of identity ARN -> has MFA condition in policy",
    )
    session_policies: list[dict[str, Any]] = Field(default_factory=list)
    ip_restrictions: list[dict[str, Any]] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Logging / detection posture
# ═══════════════════════════════════════════════════════════════════════════
class CloudTrailConfig(BaseModel):
    model_config = {"frozen": True}

    trail_name: str
    trail_arn: str
    is_multi_region: bool = False
    is_organization_trail: bool = False
    is_logging: bool = True
    has_log_file_validation: bool = False
    s3_bucket_name: str | None = None
    cloudwatch_log_group_arn: str | None = None
    include_management_events: bool = True
    data_event_selectors: list[dict[str, Any]] = Field(default_factory=list)


class GuardDutyConfig(BaseModel):
    model_config = {"frozen": True}

    detector_id: str | None = None
    is_enabled: bool = False
    findings_count: int = 0
    s3_protection: bool = False
    eks_protection: bool = False
    malware_protection: bool = False


class LoggingState(BaseModel):
    """What is being logged and how -- directly impacts detection cost scoring."""

    cloudtrail_trails: list[CloudTrailConfig] = Field(default_factory=list)
    guardduty: GuardDutyConfig = Field(default_factory=GuardDutyConfig)
    config_recorder_enabled: bool = False
    security_hub_enabled: bool = False
    access_analyzer_enabled: bool = False

    @property
    def has_active_cloudtrail(self) -> bool:
        return any(t.is_logging for t in self.cloudtrail_trails)

    @property
    def has_data_events(self) -> bool:
        return any(
            len(t.data_event_selectors) > 0
            for t in self.cloudtrail_trails
            if t.is_logging
        )


# ═══════════════════════════════════════════════════════════════════════════
# Detection cost model
# ═══════════════════════════════════════════════════════════════════════════
class DetectionProfile(BaseModel):
    """Detection cost metadata for a single AWS API action.

    Loaded from the knowledge base, then dynamically adjusted based on
    the account's LoggingState.
    """
    model_config = {"frozen": True}

    api_action: str                          # e.g. "iam:CreateAccessKey"
    service: str = ""                        # e.g. "iam"
    cloudtrail_visibility: CloudTrailVisibility = CloudTrailVisibility.MANAGEMENT_WRITE
    is_read_only: bool = False
    guardduty_finding_types: list[str] = Field(default_factory=list)
    base_detection_score: float = 0.5        # 0.0 = invisible, 1.0 = instant alert
    noise_level: NoiseLevel = NoiseLevel.MEDIUM
    behavioral_notes: str = ""
    is_mutating: bool = True


# ═══════════════════════════════════════════════════════════════════════════
# Attack planning models  (consumed by Planner, produced for Executor)
# ═══════════════════════════════════════════════════════════════════════════
class AttackEdge(BaseModel):
    """A single privilege transition in the attack graph."""
    model_config = {"frozen": True}

    source_arn: str
    target_arn: str
    edge_type: EdgeType
    required_permissions: list[str] = Field(default_factory=list)
    api_actions: list[str] = Field(default_factory=list)
    detection_cost: float = 0.5
    success_probability: float = 0.5
    noise_level: NoiseLevel = NoiseLevel.MEDIUM
    guardrail_status: str = "unknown"   # "clear" | "blocked" | "uncertain"
    conditions: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class AttackChain(BaseModel):
    """A multi-step attack path through the attack graph.

    Represents a sequence of edges: A → B → C where each hop
    is a privilege transition. Single-hop chains wrap one edge.
    """
    model_config = {"frozen": True}

    chain_id: str = ""
    edges: list[AttackEdge] = Field(default_factory=list)
    total_detection_cost: float = 0.0
    total_success_probability: float = 1.0
    hop_count: int = 0
    objective: str = ""

    @property
    def source_arn(self) -> str:
        return self.edges[0].source_arn if self.edges else ""

    @property
    def final_target_arn(self) -> str:
        return self.edges[-1].target_arn if self.edges else ""

    @property
    def max_noise_level(self) -> NoiseLevel:
        """The noisiest step in the chain."""
        _order = {"silent": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        worst = NoiseLevel.SILENT
        for e in self.edges:
            val = e.noise_level.value if hasattr(e.noise_level, "value") else str(e.noise_level)
            if _order.get(val, 0) > _order.get(worst.value, 0):
                worst = e.noise_level
        return worst

    @property
    def summary_text(self) -> str:
        """Human-readable chain summary: A → B → C."""
        if not self.edges:
            return ""
        parts = [self.edges[0].source_arn.split("/")[-1]]
        for e in self.edges:
            name = e.target_arn.split("/")[-1] if "/" in e.target_arn else e.target_arn.split(":")[-1]
            parts.append(name)
        return " → ".join(parts)


class PlannedAction(BaseModel):
    """A single action the executor should perform."""
    model_config = {"frozen": True}

    action_id: str                    # unique within the plan
    action_type: str                  # e.g. "assume_role", "create_access_key"
    source_arn: str                   # identity performing the action
    target_arn: str                   # target of the action
    api_calls: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    detection_cost: float = 0.0
    success_probability: float = 1.0
    noise_level: NoiseLevel = NoiseLevel.LOW
    pace_hint_seconds: float = 0.0    # suggested delay before this action
    stealth_notes: str = ""
    rollback_type: str | None = None  # how to undo this action
    fallback_action_id: str | None = None
    depends_on: list[str] = Field(default_factory=list)


class AttackPlan(BaseModel):
    """Complete plan produced by the Planner for the Executor."""

    plan_id: str
    strategy: str
    objective: str = ""
    steps: list[PlannedAction] = Field(default_factory=list)
    total_detection_cost: float = 0.0
    estimated_success_probability: float = 0.0
    noise_budget_remaining: float = 1.0
    reasoning: list[str] = Field(default_factory=list)
    alternative_paths: int = 0       # how many other paths were considered
    created_at: str = Field(default_factory=_now_iso)


# ═══════════════════════════════════════════════════════════════════════════
# Execution result (feedback from Executor → Recon)
# ═══════════════════════════════════════════════════════════════════════════
class ActionResult(BaseModel):
    """Result of executing a single PlannedAction."""

    action_id: str
    status: str                              # ActionStatus value
    message: str = ""
    error: str | None = None
    outputs: dict[str, Any] = Field(default_factory=dict)
    new_discoveries: list[dict[str, Any]] = Field(default_factory=list)
    actual_detection_cost: float = 0.0
    duration_seconds: float = 0.0
    executed_at: str = Field(default_factory=_now_iso)


# ═══════════════════════════════════════════════════════════════════════════
# Security findings
# ═══════════════════════════════════════════════════════════════════════════
class Finding(BaseModel):
    """A security finding / misconfiguration discovered during recon or planning."""
    model_config = {"frozen": True}

    finding_id: str                          # e.g. "S3-PUBLIC-01"
    title: str                               # e.g. "Public S3 Bucket"
    severity: Severity
    resource_arn: str
    resource_type: str                       # e.g. "S3 Bucket"
    description: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    discovered_at: str = Field(default_factory=_now_iso)


# ═══════════════════════════════════════════════════════════════════════════
# Environment model metadata
# ═══════════════════════════════════════════════════════════════════════════
class EnvironmentMetadata(BaseModel):
    """Metadata about the environment model snapshot."""

    account_id: str = ""
    account_alias: str | None = None
    region: str = "us-east-1"
    caller_arn: str = ""
    caller_user_id: str = ""
    collected_at: str = Field(default_factory=_now_iso)
    collector_versions: dict[str, str] = Field(default_factory=dict)
    total_nodes: int = 0
    total_edges: int = 0
