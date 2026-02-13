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
from atlas.core.telemetry import TelemetryRecorder
from atlas.core.types import Layer, NodeType
from atlas.recon.base import BaseCollector
from atlas.recon.collectors.guardrail import GuardrailCollector
from atlas.recon.collectors.identity import IdentityCollector
from atlas.recon.collectors.logging_config import LoggingConfigCollector
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
        self.collector_stats: dict[str, dict[str, Any]] = {}
        self.findings: list[Any] = []  # list of Finding objects

    def to_dict(self) -> dict[str, Any]:
        """Serialize the entire model for persistence."""
        return {
            "metadata": self.metadata.model_dump(),
            "graph": self.graph.to_dict(),
            "guardrail_state": self.guardrail_state.model_dump(),
            "logging_state": self.logging_state.model_dump(),
            "collector_stats": self.collector_stats,
            "findings": [f.model_dump() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnvironmentModel:
        """Reconstruct from serialized form."""
        model = cls()
        model.metadata = EnvironmentMetadata(**data.get("metadata", {}))
        model.graph = EnvironmentGraph.from_dict(data.get("graph", {}))
        model.guardrail_state = GuardrailState(**data.get("guardrail_state", {}))
        model.logging_state = LoggingState(**data.get("logging_state", {}))
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
    COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
        "identity": IdentityCollector,
        "policy": PolicyCollector,
        "trust": TrustCollector,
        "guardrail": GuardrailCollector,
        "logging_config": LoggingConfigCollector,
        "resource": ResourceCollector,
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

        # ── Analyze S3 findings ────────────────────────────────────
        model.findings = _analyze_s3_findings(model)

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
