"""
atlas.recon.engine
~~~~~~~~~~~~~~~~~~
Recon layer orchestrator.

Runs all enabled collectors in sequence, builds the EnvironmentModel,
and returns it as a clean data structure for the Planner layer.

The ReconEngine is the ONLY entry point into Layer 1.  The Planner and
Executor never import individual collectors.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from atlas.core.config import AtlasConfig
from atlas.core.graph import EnvironmentGraph
from atlas.core.models import EnvironmentMetadata, Finding, GuardrailState, LoggingState
from atlas.core.permission_map import PermissionMap
from atlas.core.telemetry import TelemetryRecorder
from atlas.core.types import Layer, NodeType
from atlas.recon.base import BaseCollector
from atlas.recon.collectors.backup import BackupCollector
from atlas.recon.collectors.guardrail import GuardrailCollector
from atlas.recon.collectors.identity import IdentityCollector
from atlas.recon.collectors.logging_config import LoggingConfigCollector
from atlas.recon.collectors.permission_resolver import PermissionResolverCollector
from atlas.recon.collectors.policy import PolicyCollector
from atlas.recon.collectors.resource import ResourceCollector
from atlas.recon.collectors.trust import TrustCollector
from atlas.utils.aws import create_async_session, get_caller_identity

logger = structlog.get_logger(__name__)


class EnvironmentModel:
    """The complete picture of the AWS account as Atlas understands it.

    Built by the ReconEngine.  Consumed (read-only) by the PlannerEngine.
    Can be serialized for replay/persistence.
    """

    def __init__(self) -> None:
        self.graph = EnvironmentGraph()
        self.metadata = EnvironmentMetadata()
        self.guardrail_state = GuardrailState()
        self.logging_state = LoggingState()
        self.permission_map = PermissionMap()
        self.collector_stats: dict[str, dict[str, Any]] = {}
        self.findings: list[Any] = []  # list of Finding objects

    def to_dict(self) -> dict[str, Any]:
        """Serialize the entire model for persistence/replay."""
        return {
            "metadata": self.metadata.model_dump(),
            "graph": self.graph.to_dict(),
            "guardrail_state": self.guardrail_state.model_dump(),
            "logging_state": self.logging_state.model_dump(),
            "permission_map": self.permission_map.to_dict(),
            "collector_stats": self.collector_stats,
            "findings": [f.model_dump() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnvironmentModel:
        """Reconstruct from serialized form (supports replay/simulate)."""
        model = cls()
        model.metadata = EnvironmentMetadata(**data.get("metadata", {}))
        model.graph = EnvironmentGraph.from_dict(data.get("graph", {}))
        model.guardrail_state = GuardrailState(**data.get("guardrail_state", {}))
        model.logging_state = LoggingState(**data.get("logging_state", {}))
        # Restore PermissionMap from serialized data
        pmap_data = data.get("permission_map")
        if pmap_data:
            model.permission_map = PermissionMap.from_dict(pmap_data)
        model.collector_stats = data.get("collector_stats", {})
        model.findings = [Finding(**f) for f in data.get("findings", [])]
        return model

    def summary(self) -> dict[str, Any]:
        """Quick human-readable summary."""
        return {
            "Account": self.metadata.account_id,
            "Region": self.metadata.region,
            "Caller Identity": self.metadata.caller_arn,
            "IAM Users": len(self.graph.nodes_of_type(NodeType.USER)),
            "IAM Roles": len(self.graph.nodes_of_type(NodeType.ROLE)),
            "IAM Groups": len(self.graph.nodes_of_type(NodeType.GROUP)),
            "Policies": len(self.graph.nodes_of_type(NodeType.POLICY)),
            "S3 Buckets": len(self.graph.nodes_of_type(NodeType.S3_BUCKET)),
            "EC2 Instances": len(self.graph.nodes_of_type(NodeType.EC2_INSTANCE)),
            "Lambda Functions": len(self.graph.nodes_of_type(NodeType.LAMBDA_FUNCTION)),
            "RDS Instances": len(self.graph.nodes_of_type(NodeType.RDS_INSTANCE)),
            "KMS Keys": len(self.graph.nodes_of_type(NodeType.KMS_KEY)),
            "Secrets Manager Secrets": len(self.graph.nodes_of_type(NodeType.SECRETS_MANAGER)),
            "SSM Parameters": len(self.graph.nodes_of_type(NodeType.SSM_PARAMETER)),
            "CloudFormation Stacks": len(self.graph.nodes_of_type(NodeType.CLOUDFORMATION_STACK)),
            "Backup Plans": len(self.graph.nodes_of_type(NodeType.BACKUP_PLAN)),
            "Public EBS Snapshots": len(self.graph.nodes_of_type(NodeType.EBS_SNAPSHOT)),
            "Permission Map": self.permission_map.resolution_summary.get("tier_used", "none"),
            "Permissions Mapped": self.permission_map.resolution_summary.get("total_permissions_mapped", 0),
            "SCPs in PermMap": self.permission_map.resolution_summary.get("scps_loaded", 0),
            "Perm Boundaries Applied": self.permission_map.resolution_summary.get("permission_boundaries_applied", 0),
            "Resource Policies": self.permission_map.resolution_summary.get("resource_policies_analyzed", 0),
            "Condition-Gated": self.permission_map.resolution_summary.get("condition_gated_permissions", 0),
            "CloudTrail Active": self.logging_state.has_active_cloudtrail,
            "GuardDuty Enabled": self.logging_state.guardduty.is_enabled,
            "SCPs": len(self.guardrail_state.scps),
            "Permission Boundaries": len(self.guardrail_state.permission_boundaries),
            "Findings": len(self.findings),
            "Graph Nodes": self.graph.node_count,
            "Graph Edges": self.graph.edge_count,
        }


class ReconEngine:
    """Layer 1 orchestrator.  Runs collectors, builds EnvironmentModel."""

    # Collector registry (order matters — later collectors depend on earlier ones)
    # permission_resolver MUST run LAST — it consumes data from all others.
    COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
        "identity": IdentityCollector,
        "policy": PolicyCollector,
        "trust": TrustCollector,
        "guardrail": GuardrailCollector,
        "logging_config": LoggingConfigCollector,
        "resource": ResourceCollector,
        "backup": BackupCollector,
        "permission_resolver": PermissionResolverCollector,
    }

    def __init__(
        self,
        config: AtlasConfig,
        recorder: TelemetryRecorder,
    ) -> None:
        self._config = config
        self._recorder = recorder

    async def run(self) -> EnvironmentModel:
        """Execute all enabled collectors and return the EnvironmentModel."""
        model = EnvironmentModel()
        session = create_async_session(self._config.aws)

        # ── Identify ourselves ─────────────────────────────────────
        identity = await get_caller_identity(session)
        if not identity:
            raise RuntimeError(
                "Failed to get caller identity.  Check AWS credentials."
            )

        account_id = identity["Account"]
        region = self._config.aws.region
        caller_arn = identity["Arn"]

        model.metadata = EnvironmentMetadata(
            account_id=account_id,
            region=region,
            caller_arn=caller_arn,
            caller_user_id=identity.get("UserId", ""),
            collected_at=datetime.now(timezone.utc).isoformat(),
        )

        self._recorder.record(
            layer=Layer.RECON,
            event_type="recon_start",
            action="sts:GetCallerIdentity",
            source_arn=caller_arn,
            details={"account_id": account_id, "region": region},
        )

        # ── Add account root node ─────────────────────────────────
        root_arn = f"arn:aws:iam::{account_id}:root"
        model.graph.add_node(root_arn, NodeType.ACCOUNT, label=f"account:{account_id}")

        # ── Run collectors in order ────────────────────────────────
        enabled = self._config.recon.enabled_collectors

        for collector_id in enabled:
            collector_cls = self.COLLECTOR_REGISTRY.get(collector_id)
            if not collector_cls:
                logger.warning("unknown_collector", collector_id=collector_id)
                continue

            logger.info("collector_starting", collector=collector_id)
            collector = collector_cls(
                session=session,
                config=self._config,
                graph=model.graph,
                recorder=self._recorder,
            )

            try:
                stats = await collector.collect(account_id, region)
                model.collector_stats[collector_id] = stats
                logger.info("collector_complete", collector=collector_id, stats=stats)

                # Extract guardrail/logging state if collector returned them
                if "guardrail_state" in stats:
                    model.guardrail_state = GuardrailState(**stats["guardrail_state"])
                if "logging_state" in stats:
                    model.logging_state = LoggingState(**stats["logging_state"])
                # Extract PermissionMap from permission_resolver
                if "_permission_map" in stats:
                    model.permission_map = stats.pop("_permission_map")

            except Exception as exc:
                logger.error(
                    "collector_failed",
                    collector=collector_id,
                    error=str(exc),
                )
                model.collector_stats[collector_id] = {"error": str(exc)}
                self._recorder.record(
                    layer=Layer.RECON,
                    event_type="collector_error",
                    action=collector_id,
                    status="failure",
                    error=str(exc),
                )

        # ── Analyze findings ───────────────────────────────────────
        model.findings = (
            _analyze_s3_findings(model)
            + _analyze_ec2_findings(model)
            + _analyze_credential_findings(model)
            + _analyze_ebs_snapshot_findings(model)
        )

        # ── Finalize metadata ──────────────────────────────────────
        model.metadata = EnvironmentMetadata(
            account_id=account_id,
            region=region,
            caller_arn=caller_arn,
            caller_user_id=identity.get("UserId", ""),
            collected_at=datetime.now(timezone.utc).isoformat(),
            total_nodes=model.graph.node_count,
            total_edges=model.graph.edge_count,
        )

        self._recorder.record(
            layer=Layer.RECON,
            event_type="recon_complete",
            details=model.summary(),
        )

        logger.info("recon_complete", **model.summary())
        return model


# ---------------------------------------------------------------------------
# S3 finding analysis (runs post-collection)
# ---------------------------------------------------------------------------
def _analyze_s3_findings(model: EnvironmentModel) -> list[Finding]:
    """Analyze S3 buckets for misconfigurations and return findings."""
    from atlas.core.types import Severity

    findings: list[Finding] = []
    buckets = model.graph.nodes_of_type(NodeType.S3_BUCKET)
    finding_idx = 0

    for bucket_arn in buckets:
        data = model.graph.get_node_data(bucket_arn)
        bucket_name = data.get("name", bucket_arn.split(":::")[-1])
        pab = data.get("public_access_block", {})
        bucket_policy = data.get("bucket_policy")

        # --- Check 1: Public Access Block disabled ---
        all_blocked = (
            pab.get("BlockPublicAcls", False)
            and pab.get("IgnorePublicAcls", False)
            and pab.get("BlockPublicPolicy", False)
            and pab.get("RestrictPublicBuckets", False)
        )

        if not all_blocked and not pab:
            finding_idx += 1
            findings.append(Finding(
                finding_id=f"S3-PAB-{finding_idx:02d}",
                title="Public Access Block Not Configured",
                severity=Severity.HIGH,
                resource_arn=bucket_arn,
                resource_type="S3 Bucket",
                description=f"Bucket '{bucket_name}' has no Public Access Block configuration. "
                            "This leaves the bucket exposed to public access via ACLs or bucket policies.",
                details={"public_access_block": pab},
                remediation="Enable all four Public Access Block settings on the bucket.",
            ))
        elif not all_blocked:
            finding_idx += 1
            disabled = [k for k, v in pab.items() if not v]
            findings.append(Finding(
                finding_id=f"S3-PAB-{finding_idx:02d}",
                title="Partial Public Access Block",
                severity=Severity.MEDIUM,
                resource_arn=bucket_arn,
                resource_type="S3 Bucket",
                description=f"Bucket '{bucket_name}' has some Public Access Block settings disabled: "
                            f"{', '.join(disabled)}.",
                details={"public_access_block": pab, "disabled_settings": disabled},
                remediation="Enable all four Public Access Block settings.",
            ))

        # --- Check 2: Bucket policy allows public access ---
        if bucket_policy:
            public_stmts = _find_public_policy_statements(bucket_policy)
            if public_stmts:
                finding_idx += 1
                actions = []
                for stmt in public_stmts:
                    acts = stmt.get("Action", [])
                    if isinstance(acts, str):
                        acts = [acts]
                    actions.extend(acts)

                findings.append(Finding(
                    finding_id=f"S3-POL-{finding_idx:02d}",
                    title="Public Bucket Policy",
                    severity=Severity.CRITICAL,
                    resource_arn=bucket_arn,
                    resource_type="S3 Bucket",
                    description=f"Bucket '{bucket_name}' has a bucket policy that grants access to "
                                f"everyone (Principal: *). Actions: {', '.join(set(actions))}.",
                    details={
                        "public_statements": len(public_stmts),
                        "actions": list(set(actions)),
                    },
                    remediation="Remove or restrict the Principal in the bucket policy. "
                                "Use specific account/role ARNs instead of '*'.",
                ))

        # --- Check 3: Bucket policy grants cross-account access ---
        if bucket_policy:
            cross_stmts = _find_cross_account_statements(
                bucket_policy, model.metadata.account_id,
            )
            if cross_stmts:
                finding_idx += 1
                ext_accounts = set()
                for stmt in cross_stmts:
                    for p in _extract_aws_principals(stmt):
                        parts = p.split(":")
                        if len(parts) >= 5:
                            ext_accounts.add(parts[4])
                findings.append(Finding(
                    finding_id=f"S3-XAC-{finding_idx:02d}",
                    title="Cross-Account Bucket Policy",
                    severity=Severity.MEDIUM,
                    resource_arn=bucket_arn,
                    resource_type="S3 Bucket",
                    description=f"Bucket '{bucket_name}' policy grants access to external accounts: "
                                f"{', '.join(ext_accounts)}.",
                    details={"external_accounts": list(ext_accounts)},
                    remediation="Verify the cross-account access is intentional and uses conditions.",
                ))

    return findings


def _find_public_policy_statements(policy: dict) -> list[dict]:
    """Return statements that grant access to Principal: *."""
    results = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            results.append(stmt)
        elif isinstance(principal, dict):
            aws_val = principal.get("AWS", [])
            if isinstance(aws_val, str):
                aws_val = [aws_val]
            if "*" in aws_val:
                results.append(stmt)
    return results


def _find_cross_account_statements(policy: dict, own_account: str) -> list[dict]:
    """Return statements that grant access to principals outside own_account."""
    results = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        for p in _extract_aws_principals(stmt):
            if p == "*":
                continue  # handled by public check
            parts = p.split(":")
            if len(parts) >= 5 and parts[4] and parts[4] != own_account:
                results.append(stmt)
                break
    return results


def _extract_aws_principals(stmt: dict) -> list[str]:
    """Get list of AWS principal ARNs from a statement."""
    principal = stmt.get("Principal", {})
    if isinstance(principal, str):
        return [principal] if principal != "*" else []
    if isinstance(principal, dict):
        aws_val = principal.get("AWS", [])
        if isinstance(aws_val, str):
            return [aws_val]
        return aws_val
    return []


# ---------------------------------------------------------------------------
# EC2 finding analysis (runs post-collection)
# ---------------------------------------------------------------------------
def _analyze_ec2_findings(model: EnvironmentModel) -> list[Finding]:
    """Analyze EC2 instances for user data exposure and IMDS misconfigurations."""
    from atlas.core.types import Severity

    findings: list[Finding] = []
    instances = model.graph.nodes_of_type(NodeType.EC2_INSTANCE)
    finding_idx = 0

    for inst_arn in instances:
        data = model.graph.get_node_data(inst_arn)
        instance_id = data.get("instance_id", inst_arn.split("/")[-1])
        has_userdata = data.get("user_data_available", False)
        imds_v2_required = data.get("imds_v2_required", True)
        has_profile = bool(data.get("instance_profile_arn"))
        state = data.get("state", "unknown")

        # Only analyze running or stopped instances (user data persists)
        if state not in ("running", "stopped"):
            continue

        # --- Check 1: User data present (potential credential exposure) ---
        if has_userdata:
            finding_idx += 1
            severity = Severity.HIGH if not imds_v2_required else Severity.MEDIUM
            findings.append(Finding(
                finding_id=f"EC2-UD-{finding_idx:02d}",
                title="EC2 User Data Contains Potential Secrets",
                severity=severity,
                resource_arn=inst_arn,
                resource_type="EC2 Instance",
                description=(
                    f"Instance '{instance_id}' has user data configured. "
                    f"User data is base64 encoded but NOT encrypted and "
                    f"frequently contains hardcoded credentials, API keys, "
                    f"database passwords, and bootstrap configuration. "
                    f"Any identity with ec2:DescribeInstanceAttribute can "
                    f"retrieve it via the API. "
                    + (
                        "Additionally, IMDSv1 is enabled, making the user "
                        "data accessible via SSRF attacks from within the "
                        "instance without any authentication."
                        if not imds_v2_required
                        else "IMDSv2 is enforced, which mitigates "
                        "SSRF-based metadata extraction."
                    )
                ),
                details={
                    "user_data_available": True,
                    "imds_v2_required": imds_v2_required,
                    "has_instance_profile": has_profile,
                },
                remediation=(
                    "Review and remove any credentials or secrets from "
                    "user data. Use AWS Secrets Manager or SSM Parameter "
                    "Store (SecureString) for sensitive configuration. "
                    "Restrict ec2:DescribeInstanceAttribute permissions "
                    "to only identities that require it."
                ),
            ))

        # --- Check 2: IMDSv1 enabled (SSRF risk for metadata + creds) ---
        if not imds_v2_required and has_profile:
            finding_idx += 1
            findings.append(Finding(
                finding_id=f"EC2-IMDS-{finding_idx:02d}",
                title="IMDSv1 Enabled with Instance Profile",
                severity=Severity.HIGH,
                resource_arn=inst_arn,
                resource_type="EC2 Instance",
                description=(
                    f"Instance '{instance_id}' has IMDSv1 enabled and an "
                    f"instance profile attached. IMDSv1 does not require "
                    f"session tokens, making the instance metadata service "
                    f"vulnerable to SSRF attacks. An attacker exploiting "
                    f"SSRF can steal the instance role credentials from "
                    f"http://169.254.169.254/latest/meta-data/"
                    f"iam/security-credentials/ as well as any user data."
                ),
                details={
                    "imds_v2_required": False,
                    "instance_profile_arn": data.get("instance_profile_arn"),
                },
                remediation=(
                    "Enforce IMDSv2 by setting HttpTokens to 'required'. "
                    "This requires all metadata requests to include a "
                    "session token, blocking SSRF-based credential theft."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Credential finding analysis (runs post-collection)
# ---------------------------------------------------------------------------
def _analyze_credential_findings(model: EnvironmentModel) -> list[Finding]:
    """Analyze access key credentials for account ID mismatches and anomalies.

    Uses offline decoding of access key IDs (no API calls) to:
      - Detect cross-account keys (key's encoded account != current account)
      - Flag old-format keys that cannot be decoded offline
    """
    from atlas.core.types import Severity

    findings: list[Finding] = []
    credentials = model.graph.nodes_of_type(NodeType.CREDENTIAL)
    finding_idx = 0

    for cred_arn in credentials:
        data = model.graph.get_node_data(cred_arn)
        if not data:
            continue

        ak_id = data.get("access_key_id", "")
        decoded_account = data.get("decoded_account_id")
        owner_account = data.get("owner_account_id", model.metadata.account_id)
        owner_arn = data.get("owner_arn", "")
        is_cross_account = data.get("is_cross_account", False)

        # --- Finding: Cross-account key detected ---
        if is_cross_account and decoded_account:
            finding_idx += 1
            findings.append(Finding(
                finding_id=f"CRED-XAC-{finding_idx:02d}",
                title="Cross-Account Access Key Detected",
                severity=Severity.HIGH,
                resource_arn=cred_arn,
                resource_type="Access Key",
                description=(
                    f"Access key {ak_id[:8]}... is associated with user "
                    f"{owner_arn.split('/')[-1] if owner_arn else 'unknown'} "
                    f"in account {owner_account}, but the key ID encodes "
                    f"account {decoded_account}. This indicates the key "
                    f"may belong to a different account or was created "
                    f"under unusual circumstances."
                ),
                details={
                    "access_key_id_prefix": ak_id[:8],
                    "decoded_account_id": decoded_account,
                    "owner_account_id": owner_account,
                    "owner_arn": owner_arn,
                },
                remediation=(
                    "Investigate whether this key legitimately belongs "
                    "to this account. If it's from an external account, "
                    "verify scope authorization before using it."
                ),
            ))

        # --- Finding: Old-format key (pre-March 2019) ---
        if not data.get("is_new_format", True) and ak_id:
            finding_idx += 1
            findings.append(Finding(
                finding_id=f"CRED-OLD-{finding_idx:02d}",
                title="Old-Format Access Key (Pre-2019)",
                severity=Severity.LOW,
                resource_arn=cred_arn,
                resource_type="Access Key",
                description=(
                    f"Access key {ak_id[:8]}... uses the old format "
                    f"(created before March 2019). The account ID cannot "
                    f"be decoded offline. Use sts:GetAccessKeyInfo from "
                    f"your own account to resolve it (only logs in your "
                    f"account, not the target's)."
                ),
                details={
                    "access_key_id_prefix": ak_id[:8],
                    "is_new_format": False,
                    "owner_arn": owner_arn,
                },
                remediation=(
                    "Consider rotating this old access key. Keys older "
                    "than 5 years indicate poor credential hygiene."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# EBS snapshot finding analysis (runs post-collection)
# ---------------------------------------------------------------------------
def _analyze_ebs_snapshot_findings(model: EnvironmentModel) -> list[Finding]:
    """Analyze discovered public EBS snapshots for security findings.

    Any public EBS snapshot is a HIGH or CRITICAL finding because:
      - Anyone with an AWS account can discover and clone the data
      - There are NO resource policies to limit access
      - Snapshot contents often include full filesystem images with secrets
      - The victim has zero visibility into who is accessing the snapshots
    """
    from atlas.core.types import Severity

    findings: list[Finding] = []
    snapshots = model.graph.nodes_of_type(NodeType.EBS_SNAPSHOT)

    for idx, snap_arn in enumerate(snapshots, start=1):
        data = model.graph.get_node_data(snap_arn)
        if not data:
            continue

        snap_id = data.get("snapshot_id", snap_arn.split("/")[-1])
        volume_size = data.get("volume_size_gb", 0)
        encrypted = data.get("encrypted", False)
        description = data.get("description", "")
        owner_id = data.get("owner_id", "")

        # Encrypted public snapshots are still bad but slightly less exploitable
        severity = Severity.HIGH if encrypted else Severity.CRITICAL

        desc_parts = [
            f"EBS snapshot {snap_id} ({volume_size} GiB) is publicly accessible. "
            f"Anyone with an AWS account can clone this snapshot and read its "
            f"entire contents including filesystems, databases, credentials, "
            f"and application data.",
        ]
        if encrypted:
            desc_parts.append(
                " The snapshot is encrypted, which limits exploitation to "
                "those with access to the encryption key."
            )
        else:
            desc_parts.append(
                " The snapshot is NOT encrypted — any AWS account can "
                "create a volume from it and mount the data immediately."
            )
        if description:
            desc_parts.append(
                f" Snapshot description: '{description[:120]}'."
            )

        findings.append(Finding(
            finding_id=f"EBS-PUB-{idx:02d}",
            title="Public EBS Snapshot Exposed",
            severity=severity,
            resource_arn=snap_arn,
            resource_type="EBS Snapshot",
            description="".join(desc_parts),
            details={
                "snapshot_id": snap_id,
                "volume_size_gb": volume_size,
                "encrypted": encrypted,
                "owner_account_id": owner_id,
                "description": description[:200] if description else "",
            },
            remediation=(
                "Immediately make this snapshot private using "
                "ec2:ModifySnapshotAttribute to remove the 'all' group "
                "from createVolumePermission. If the snapshot data has been "
                "exposed, rotate all credentials and secrets that may have "
                "been stored on the volume. Enable AWS Config rule "
                "'ec2-ebs-snapshot-public-restorable-check' and Prowler "
                "check 'ec2_ebs_public_snapshot' for ongoing monitoring."
            ),
        ))

    return findings
