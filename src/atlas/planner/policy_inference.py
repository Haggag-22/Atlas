"""
atlas.planner.policy_inference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Inference-driven attack graph construction.

Instead of hardcoding techniques, this module derives attack edges from:
  1. PermissionMap (identity policies + resource policies)
  2. Environment graph (identities, resources, trust)
  3. Resource policies stored on graph nodes

Edges are added when identity_has_permission(identity, action, resource) is True,
regardless of whether the permission came from identity policy or resource policy.

Technique-specific builders can supplement with patterns inference cannot capture
(e.g. IMDS credential theft, Lambda env var exfil).
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.graph import EnvironmentGraph
from atlas.core.models import AttackEdge
from atlas.core.permission_map import PermissionMap
from atlas.core.types import EdgeType, NodeType, NoiseLevel
from atlas.planner.detection import DetectionScorer

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Resource type → actions that grant meaningful access
# ---------------------------------------------------------------------------
# For each resource type, we check if the identity has ANY of these actions.
# If so, we add an edge.  Actions are service:Action format.
# Order: read-like first, then write-like (write implies read for edge purpose).

_RESOURCE_ACTIONS: dict[NodeType, list[tuple[str, EdgeType, str]]] = {
    NodeType.S3_BUCKET: [
        ("s3:GetObject", EdgeType.HAS_ACCESS_TO, "read"),
        ("s3:ListBucket", EdgeType.HAS_ACCESS_TO, "read"),
        ("s3:GetBucketLocation", EdgeType.HAS_ACCESS_TO, "read"),
        ("s3:GetBucketPolicy", EdgeType.HAS_ACCESS_TO, "read"),
        ("s3:GetBucketAcl", EdgeType.HAS_ACCESS_TO, "read"),
        ("s3:GetBucketPublicAccessBlock", EdgeType.HAS_ACCESS_TO, "read"),
        ("s3:PutObject", EdgeType.HAS_ACCESS_TO, "write"),
        ("s3:DeleteObject", EdgeType.HAS_ACCESS_TO, "write"),
        ("s3:PutBucketPolicy", EdgeType.HAS_ACCESS_TO, "write"),
        ("s3:PutBucketAcl", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.LAMBDA_FUNCTION: [
        ("lambda:InvokeFunction", EdgeType.HAS_ACCESS_TO, "invoke"),
        ("lambda:GetFunction", EdgeType.HAS_ACCESS_TO, "read"),
        ("lambda:GetFunctionConfiguration", EdgeType.HAS_ACCESS_TO, "read"),
        ("lambda:GetPolicy", EdgeType.HAS_ACCESS_TO, "read"),
        ("lambda:UpdateFunctionCode", EdgeType.HAS_ACCESS_TO, "write"),
        ("lambda:UpdateFunctionConfiguration", EdgeType.HAS_ACCESS_TO, "write"),
        ("lambda:AddPermission", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.KMS_KEY: [
        ("kms:Decrypt", EdgeType.HAS_ACCESS_TO, "decrypt"),
        ("kms:Encrypt", EdgeType.HAS_ACCESS_TO, "encrypt"),
        ("kms:GenerateDataKey", EdgeType.HAS_ACCESS_TO, "encrypt"),
        ("kms:DescribeKey", EdgeType.HAS_ACCESS_TO, "read"),
        ("kms:CreateGrant", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.SECRETS_MANAGER: [
        ("secretsmanager:GetSecretValue", EdgeType.HAS_ACCESS_TO, "read"),
        ("secretsmanager:DescribeSecret", EdgeType.HAS_ACCESS_TO, "read"),
        ("secretsmanager:PutSecretValue", EdgeType.HAS_ACCESS_TO, "write"),
        ("secretsmanager:CreateSecret", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.SSM_PARAMETER: [
        ("ssm:GetParameter", EdgeType.HAS_ACCESS_TO, "read"),
        ("ssm:GetParameters", EdgeType.HAS_ACCESS_TO, "read"),
        ("ssm:DescribeParameters", EdgeType.HAS_ACCESS_TO, "read"),
        ("ssm:PutParameter", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.ECR_REPOSITORY: [
        ("ecr:GetDownloadUrlForLayer", EdgeType.HAS_ACCESS_TO, "pull"),
        ("ecr:BatchGetImage", EdgeType.HAS_ACCESS_TO, "pull"),
        ("ecr:BatchCheckLayerAvailability", EdgeType.HAS_ACCESS_TO, "pull"),
        ("ecr:PutImage", EdgeType.HAS_ACCESS_TO, "push"),
        ("ecr:InitiateLayerUpload", EdgeType.HAS_ACCESS_TO, "push"),
        ("ecr:UploadLayerPart", EdgeType.HAS_ACCESS_TO, "push"),
        ("ecr:CompleteLayerUpload", EdgeType.HAS_ACCESS_TO, "push"),
    ],
    NodeType.RDS_INSTANCE: [
        ("rds:DescribeDBInstances", EdgeType.HAS_ACCESS_TO, "read"),
        ("rds:CreateDBSnapshot", EdgeType.HAS_ACCESS_TO, "write"),
        ("rds:ModifyDBSnapshotAttribute", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.EBS_SNAPSHOT: [
        ("ec2:DescribeSnapshots", EdgeType.HAS_ACCESS_TO, "read"),
        ("ec2:ModifySnapshotAttribute", EdgeType.HAS_ACCESS_TO, "write"),
        ("ec2:CreateVolume", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.EC2_INSTANCE: [
        ("ec2:DescribeInstances", EdgeType.HAS_ACCESS_TO, "read"),
        ("ec2:DescribeInstanceAttribute", EdgeType.HAS_ACCESS_TO, "read"),
        ("ec2:GetPasswordData", EdgeType.HAS_ACCESS_TO, "read"),
        ("ec2:TerminateInstances", EdgeType.HAS_ACCESS_TO, "write"),
        ("ec2:ModifyInstanceAttribute", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.CLOUDFORMATION_STACK: [
        ("cloudformation:DescribeStacks", EdgeType.HAS_ACCESS_TO, "read"),
        ("cloudformation:DescribeStackEvents", EdgeType.HAS_ACCESS_TO, "read"),
        ("cloudformation:UpdateStack", EdgeType.HAS_ACCESS_TO, "write"),
        ("cloudformation:CreateStack", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.BACKUP_PLAN: [
        ("backup:DescribeProtectedResource", EdgeType.HAS_ACCESS_TO, "read"),
        ("backup:ListProtectedResources", EdgeType.HAS_ACCESS_TO, "read"),
        ("backup:StartRestoreJob", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.EFS_FILE_SYSTEM: [
        ("elasticfilesystem:DescribeFileSystems", EdgeType.HAS_ACCESS_TO, "read"),
        ("elasticfilesystem:DescribeMountTargets", EdgeType.HAS_ACCESS_TO, "read"),
    ],
    NodeType.CODEBUILD_PROJECT: [
        ("codebuild:BatchGetProjects", EdgeType.HAS_ACCESS_TO, "read"),
        ("codebuild:StartBuild", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.ECS_TASK_DEFINITION: [
        ("ecs:DescribeTaskDefinition", EdgeType.HAS_ACCESS_TO, "read"),
        ("ecs:RegisterTaskDefinition", EdgeType.HAS_ACCESS_TO, "write"),
        ("ecs:UpdateService", EdgeType.HAS_ACCESS_TO, "write"),
    ],
    NodeType.BEDROCK_AGENT: [
        ("bedrock:GetAgent", EdgeType.HAS_ACCESS_TO, "read"),
        ("bedrock:UpdateAgent", EdgeType.HAS_ACCESS_TO, "write"),
    ],
}


class PolicyInferenceEngine:
    """Derives attack edges from permissions and resource policies.

    Does NOT rely on hardcoded techniques.  For each (identity, resource)
    pair, checks PermissionMap.identity_has_permission for the relevant
    actions.  If any match, adds an edge.
    """

    def __init__(
        self,
        env: EnvironmentGraph,
        pmap: PermissionMap,
        scorer: DetectionScorer,
    ) -> None:
        self._env = env
        self._pmap = pmap
        self._scorer = scorer

    def infer_edges(self) -> list[AttackEdge]:
        """Produce all inference-derived attack edges."""
        edges: list[AttackEdge] = []
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )

        for node_type, action_specs in _RESOURCE_ACTIONS.items():
            resources = self._env.nodes_of_type(node_type)
            for resource_arn in resources:
                for identity_arn in identities:
                    allowed_actions: list[str] = []
                    for action, edge_type, _mode in action_specs:
                        if self._pmap.identity_has_permission(
                            identity_arn,
                            action,
                            resource_arn=resource_arn,
                        ):
                            allowed_actions.append(action)

                    if allowed_actions:
                        # Dedupe and pick representative edge type
                        edge = self._make_edge(
                            identity_arn,
                            resource_arn,
                            allowed_actions,
                            node_type,
                        )
                        if edge and not self._duplicate(edge, edges):
                            edges.append(edge)

        logger.info(
            "inference_edges_produced",
            count=len(edges),
        )
        return edges

    def _make_edge(
        self,
        source: str,
        target: str,
        actions: list[str],
        target_type: NodeType,
    ) -> AttackEdge | None:
        """Build a single inference edge."""
        if not actions:
            return None

        # Detection cost = sum of action scores (capped)
        cost = sum(
            self._scorer.score(a) for a in actions[:5]
        ) / min(len(actions), 5)
        cost = min(cost, 2.0)

        # Success probability from permission confidence
        mult = 0.9
        for a in actions[:3]:
            m = self._pmap.get_confidence_multiplier(source, a, target)
            if m > 0:
                mult = max(mult, m)
                break

        notes = (
            f"Inferred from permissions: {', '.join(sorted(actions)[:5])}"
            + (" ..." if len(actions) > 5 else "")
        )

        return AttackEdge(
            source_arn=source,
            target_arn=target,
            edge_type=EdgeType.HAS_ACCESS_TO,
            required_permissions=actions,
            api_actions=actions,
            detection_cost=cost,
            success_probability=mult,
            noise_level=NoiseLevel.LOW,
            guardrail_status="clear",
            conditions={"inference": True, "target_type": target_type.value},
            notes=notes,
        )

    def _duplicate(self, edge: AttackEdge, existing: list[AttackEdge]) -> bool:
        """Check if we already have this (source, target) pair."""
        for e in existing:
            if e.source_arn == edge.source_arn and e.target_arn == edge.target_arn:
                return True
        return False
