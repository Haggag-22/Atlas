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
    BACKUP_PLAN = "backup_plan"
    EBS_SNAPSHOT = "ebs_snapshot"
    ECS_TASK_DEFINITION = "ecs_task_definition"
    EFS_FILE_SYSTEM = "efs_file_system"
    ECR_REPOSITORY = "ecr_repository"
    COGNITO_USER_POOL = "cognito_user_pool"
    COGNITO_IDENTITY_POOL = "cognito_identity_pool"
    CLOUDFRONT_DISTRIBUTION = "cloudfront_distribution"
    CODEBUILD_PROJECT = "codebuild_project"
    ELASTICBEANSTALK_ENVIRONMENT = "elasticbeanstalk_environment"
    BEDROCK_AGENT = "bedrock_agent"
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
    CAN_READ_USERDATA = "can_read_userdata" # identity -> ec2 instance (user data disclosure)
    CAN_ENUM_BACKUP = "can_enum_backup"    # identity -> account (backup service enumeration)
    CAN_DECODE_KEY = "can_decode_key"      # identity -> credential (account ID from access key)
    CAN_LOOT_SNAPSHOT = "can_loot_snapshot" # identity -> ebs_snapshot (public snapshot exfil)
    CAN_STEAL_IMDS_CREDS = "can_steal_imds_creds"  # identity -> role (via IMDSv1 instance)
    CAN_SSM_SESSION = "can_ssm_session"    # identity -> ec2 instance (SSM session/command)
    CAN_SNAPSHOT_VOLUME = "can_snapshot_volume"  # identity -> ec2 instance (volume snapshot loot)
    CAN_MODIFY_USERDATA = "can_modify_userdata"  # identity -> ec2 instance (inject user data)
    CAN_STEAL_LAMBDA_CREDS = "can_steal_lambda_creds"  # identity -> role (via Lambda SSRF/XXE)
    CAN_STEAL_ECS_TASK_CREDS = "can_steal_ecs_task_creds"  # identity -> role (via ECS container RCE)
    CAN_BACKDOOR_ECS_TASK = "can_backdoor_ecs_task"  # identity -> role (RegisterTaskDefinition + UpdateService)
    CAN_ENABLE_SSM_VIA_TAGS = "can_enable_ssm_via_tags"  # identity -> ec2 (CreateTags + StartSession)
    CAN_ACCESS_EFS_FROM_EC2 = "can_access_efs_from_ec2"  # ec2 instance -> efs (same VPC)
    CAN_READ_CODEBUILD_ENV = "can_read_codebuild_env"  # identity -> role (creds in CodeBuild env; CloudGoat codebuild_secrets)
    CAN_READ_BEANSTALK_ENV = "can_read_beanstalk_env"  # identity -> role (creds in Beanstalk config; CloudGoat beanstalk_secrets)
    CAN_HIJACK_BEDROCK_AGENT = "can_hijack_bedrock_agent"  # identity -> Lambda role (update Lambda used by agent; CloudGoat bedrock_agent_hijacking)
    CAN_ACCESS_VIA_RESOURCE_POLICY = "can_access_via_resource_policy"  # identity -> resource (Principal "*" etc.)
    CAN_ASSUME_VIA_OIDC_MISCONFIG = "can_assume_via_oidc_misconfig"  # external -> role (GitLab/Terraform/GitHub/Cognito)
    CAN_SELF_SIGNUP_COGNITO = "can_self_signup_cognito"  # identity -> cognito user pool
    CAN_TAKEOVER_CLOUDFRONT_ORIGIN = "can_takeover_cloudfront_origin"  # finding: orphaned S3 origin
    CAN_GET_EC2_PASSWORD_DATA = "can_get_ec2_password_data"  # identity -> ec2 (Windows password)
    CAN_OPEN_SECURITY_GROUP_INGRESS = "can_open_security_group_ingress"  # open port 22
    CAN_SHARE_AMI = "can_share_ami"
    CAN_SHARE_EBS_SNAPSHOT = "can_share_ebs_snapshot"
    CAN_SHARE_RDS_SNAPSHOT = "can_share_rds_snapshot"
    CAN_INVOKE_BEDROCK_MODEL = "can_invoke_bedrock_model"  # LLMjacking
    CAN_EC2_INSTANCE_CONNECT = "can_ec2_instance_connect"
    CAN_EC2_SERIAL_CONSOLE_SSH = "can_ec2_serial_console_ssh"
    CAN_DELETE_DNS_LOGS = "can_delete_dns_logs"
    CAN_LEAVE_ORGANIZATION = "can_leave_organization"
    CAN_REMOVE_VPC_FLOW_LOGS = "can_remove_vpc_flow_logs"
    CAN_ENUMERATE_SES = "can_enumerate_ses"
    CAN_MODIFY_SAGEMAKER_LIFECYCLE = "can_modify_sagemaker_lifecycle"
    CAN_CREATE_EKS_ACCESS_ENTRY = "can_create_eks_access_entry"

    # Privilege escalation edges
    CAN_CREATE_KEY = "can_create_key"      # identity -> target_user
    CAN_ATTACH_POLICY = "can_attach_policy"
    CAN_PUT_POLICY = "can_put_policy"
    CAN_CREATE_ROLE = "can_create_role"
    CAN_UPDATE_LAMBDA = "can_update_lambda"
    CAN_CREATE_LAMBDA = "can_create_lambda"
    CAN_UPDATE_LAMBDA_CONFIG = "can_update_lambda_config"  # role change or malicious layer
    CAN_BACKDOOR_LAMBDA = "can_backdoor_lambda"  # AddPermission for external invoke
    CAN_MODIFY_TRUST = "can_modify_trust"
    CAN_CREATE_LOGIN_PROFILE = "can_create_login_profile"
    CAN_UPDATE_LOGIN_PROFILE = "can_update_login_profile"
    CAN_ADD_USER_TO_GROUP = "can_add_user_to_group"
    CAN_CREATE_ADMIN_USER = "can_create_admin_user"
    CAN_CREATE_BACKDOOR_ROLE = "can_create_backdoor_role"
    CAN_CREATE_POLICY_VERSION = "can_create_policy_version"
    CAN_SET_DEFAULT_POLICY_VERSION = "can_set_default_policy_version"
    CAN_DELETE_OR_DETACH_POLICY = "can_delete_or_detach_policy"
    CAN_DELETE_PERMISSIONS_BOUNDARY = "can_delete_permissions_boundary"
    CAN_PUT_PERMISSIONS_BOUNDARY = "can_put_permissions_boundary"
    CAN_PASSROLE_EC2 = "can_passrole_ec2"       # PassRole + ec2:RunInstances
    CAN_PASSROLE_ECS = "can_passrole_ecs"      # PassRole + ecs:RunTask
    CAN_PASSROLE_CLOUDFORMATION = "can_passrole_cloudformation"
    CAN_PASSROLE_AGENTCORE = "can_passrole_agentcore"  # PassRole + create code interpreter (role confusion)
    CAN_PASSROLE_GLUE = "can_passrole_glue"
    CAN_PASSROLE_AUTOSCALING = "can_passrole_autoscaling"
    CAN_UPDATE_GLUE_DEV_ENDPOINT = "can_update_glue_dev_endpoint"
    CAN_OBTAIN_CREDS_VIA_COGNITO_IDENTITY_POOL = "can_obtain_creds_via_cognito_identity_pool"

    # Persistence edges
    CAN_CREATE_EVENTBRIDGE_RULE = "can_create_eventbridge_rule"  # schedule/event-triggered automation
    CAN_GET_FEDERATION_TOKEN = "can_get_federation_token"  # survive access key deletion
    CAN_CREATE_CODEBUILD_GITHUB_RUNNER = "can_create_codebuild_github_runner"  # CodeBuild + attacker repo
    CAN_CREATE_ROGUE_OIDC_PERSISTENCE = "can_create_rogue_oidc_persistence"  # attacker OIDC IdP + role backdoor
    CAN_CREATE_ROLES_ANYWHERE_PERSISTENCE = "can_create_roles_anywhere_persistence"  # trust anchor + cert
    CAN_MODIFY_S3_ACL_PERSISTENCE = "can_modify_s3_acl_persistence"  # PutBucketAcl/PutObjectAcl backdoor

    # Defense evasion (GuardDuty / detection degradation)
    CAN_MODIFY_GUARDDUTY_DETECTOR = "can_modify_guardduty_detector"
    CAN_MODIFY_GUARDDUTY_IP_TRUST_LIST = "can_modify_guardduty_ip_trust_list"
    CAN_MODIFY_GUARDDUTY_EVENT_RULES = "can_modify_guardduty_event_rules"
    CAN_CREATE_GUARDDUTY_SUPPRESSION = "can_create_guardduty_suppression"
    CAN_DELETE_GUARDDUTY_PUBLISHING_DEST = "can_delete_guardduty_publishing_dest"

    # Defense evasion (CloudTrail / logging degradation)
    CAN_STOP_CLOUDTRAIL = "can_stop_cloudtrail"
    CAN_DELETE_CLOUDTRAIL = "can_delete_cloudtrail"
    CAN_UPDATE_CLOUDTRAIL_CONFIG = "can_update_cloudtrail_config"
    CAN_MODIFY_CLOUDTRAIL_BUCKET_LIFECYCLE = "can_modify_cloudtrail_bucket_lifecycle"
    CAN_MODIFY_CLOUDTRAIL_EVENT_SELECTORS = "can_modify_cloudtrail_event_selectors"

    # Credential chain
    CREDENTIAL_FOR = "credential_for"      # credential -> identity

    # Resource → identity pivot (leaked creds in resource config)
    CAN_PIVOT_VIA_BEANSTALK_CREDS = "can_pivot_via_beanstalk_creds"  # env -> identity (creds in option_settings)


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
