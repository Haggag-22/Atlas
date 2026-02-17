"""
atlas.recon.auth.backup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers AWS Backup plans, protected resources, and backup selections.

AWS Backup acts as a curated index of what actually matters in an account.
Instead of enumerating each service individually (which SOCs monitor), an
attacker with backup:List* / backup:Describe* permissions can use this
meta-service to discover critical production resources, naming conventions,
tagging strategies, operational timing, and retention policies — all in a
few low-noise API calls.

This is a Living-off-the-Cloud (LotC) reconnaissance technique.

Resources discovered via Backup that are NOT already in the environment
graph are added as new nodes (flagged with ``discovered_via_backup``).
Resources that already exist are enriched with backup metadata.
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.models import BackupPlan, ProtectedResource
from atlas.core.types import EdgeType, NodeType
from atlas.knowledge.api_profiles import get_detection_score
from atlas.recon.base import BaseCollector
from atlas.utils.aws import async_paginate, safe_api_call

logger = structlog.get_logger(__name__)

# Map AWS Backup resource type strings to Atlas NodeType values.
_RESOURCE_TYPE_MAP: dict[str, NodeType] = {
    "EC2": NodeType.EC2_INSTANCE,
    "EBS": NodeType.EC2_INSTANCE,         # EBS volumes relate to EC2
    "RDS": NodeType.RDS_INSTANCE,
    "Aurora": NodeType.RDS_INSTANCE,
    "DynamoDB": NodeType.RDS_INSTANCE,    # closest match available
    "EFS": NodeType.S3_BUCKET,            # file storage; approximate
    "S3": NodeType.S3_BUCKET,
    "CloudFormation": NodeType.CLOUDFORMATION_STACK,
    "Redshift": NodeType.RDS_INSTANCE,    # data warehouse; approximate
}


class BackupCollector(BaseCollector):
    """Enumerate AWS Backup to discover critical resources and operational intel."""

    @property
    def collector_id(self) -> str:
        return "backup"

    @property
    def description(self) -> str:
        return (
            "Enumerate AWS Backup plans, protected resources, and backup "
            "selections to discover critical production assets and "
            "operational timing without using traditional service-level "
            "enumeration commands."
        )

    @property
    def required_permissions(self) -> list[str]:
        return [
            "backup:ListProtectedResources",
            "backup:ListBackupPlans",
            "backup:GetBackupPlan",
            "backup:ListBackupSelections",
            "backup:GetBackupSelection",
            "backup:ListBackupVaults",
        ]

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        stats: dict[str, int] = {
            "protected_resources": 0,
            "backup_plans": 0,
            "backup_selections": 0,
            "new_resources_discovered": 0,
            "skipped_no_permission": 0,
        }

        if not self._caller_has("backup:ListProtectedResources"):
            logger.info("backup_skipped", reason="no backup:List* permissions")
            stats["skipped_no_permission"] = 1
            return stats

        async with self._session.client("backup", region_name=region) as backup:
            # 1. Discover protected resources (the crown jewels)
            protected = await self._collect_protected_resources(
                backup, account_id, region,
            )
            stats["protected_resources"] = len(protected)

            # Track which resources we discovered only via Backup
            new_count = 0
            for res in protected:
                if not self._graph.has_node(res.resource_arn):
                    node_type = _RESOURCE_TYPE_MAP.get(
                        res.resource_type, NodeType.EC2_INSTANCE,
                    )
                    self._graph.add_node(
                        res.resource_arn,
                        node_type,
                        data=res.model_dump(),
                        label=res.resource_name or res.resource_arn.split(":")[-1],
                    )
                    new_count += 1
                    logger.info(
                        "backup_discovered_new_resource",
                        arn=res.resource_arn,
                        resource_type=res.resource_type,
                    )
            stats["new_resources_discovered"] = new_count

            # 2. Enumerate backup plans (operational intelligence)
            plans = await self._collect_backup_plans(
                backup, account_id, region,
            )
            stats["backup_plans"] = len(plans)

            # Add backup plan nodes to the graph
            for plan in plans:
                self._graph.add_node(
                    plan.arn,
                    NodeType.BACKUP_PLAN,
                    data=plan.model_dump(),
                    label=plan.plan_name,
                )
                stats["backup_selections"] += len(plan.selections)

        logger.info("backup_collection_complete", **stats)
        return stats

    # ------------------------------------------------------------------
    # Protected resources (the single most valuable call)
    # ------------------------------------------------------------------
    async def _collect_protected_resources(
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[ProtectedResource]:
        """List all resources that have been backed up — the crown jewels."""
        resources: list[ProtectedResource] = []

        raw_items = await async_paginate(
            client, "list_protected_resources", "Results",
        )
        self._record(
            "backup:ListProtectedResources",
            detection_cost=get_detection_score(
                "backup:ListProtectedResources"
            ),
        )

        for raw in raw_items:
            resource_arn = raw.get("ResourceArn", "")
            resources.append(ProtectedResource(
                resource_arn=resource_arn,
                resource_type=raw.get("ResourceType", ""),
                resource_name=raw.get("ResourceName", ""),
                last_backup_time=(
                    str(raw["LastBackupTime"])
                    if raw.get("LastBackupTime") else None
                ),
                last_backup_vault_arn=raw.get("LastBackupVaultArn"),
                discovered_via_backup=True,
            ))

        return resources

    # ------------------------------------------------------------------
    # Backup plans + selections (timing, naming, targeting intel)
    # ------------------------------------------------------------------
    async def _collect_backup_plans(
        self,
        client: Any,
        account_id: str,
        region: str,
    ) -> list[BackupPlan]:
        """Enumerate backup plans, their rules, and resource selections."""
        plans: list[BackupPlan] = []

        raw_plans = await async_paginate(
            client, "list_backup_plans", "BackupPlansList",
        )
        self._record(
            "backup:ListBackupPlans",
            detection_cost=get_detection_score("backup:ListBackupPlans"),
        )

        for raw_plan in raw_plans:
            plan_id = raw_plan.get("BackupPlanId", "")
            plan_arn = raw_plan.get(
                "BackupPlanArn",
                f"arn:aws:backup:{region}:{account_id}:backup-plan:{plan_id}",
            )

            # Get plan details (rules, schedules, retention)
            detail_resp = await safe_api_call(
                client.get_backup_plan(BackupPlanId=plan_id),
                default=None,
            )
            self._record(
                "backup:GetBackupPlan",
                target_arn=plan_arn,
                detection_cost=get_detection_score("backup:GetBackupPlan"),
            )

            rules: list[dict[str, Any]] = []
            if detail_resp:
                bp = detail_resp.get("BackupPlan", {})
                for rule in bp.get("Rules", []):
                    rules.append({
                        "rule_name": rule.get("RuleName", ""),
                        "target_vault": rule.get(
                            "TargetBackupVaultName", ""
                        ),
                        "schedule": rule.get("ScheduleExpression", ""),
                        "schedule_tz": rule.get(
                            "ScheduleExpressionTimezone", ""
                        ),
                        "lifecycle_delete_days": (
                            rule.get("Lifecycle", {})
                            .get("DeleteAfterDays")
                        ),
                        "start_window_minutes": rule.get(
                            "StartWindowMinutes"
                        ),
                    })

            # Get selections (which resources this plan targets)
            selections: list[dict[str, Any]] = []
            protected_arns: list[str] = []
            protected_types: list[str] = []
            backup_role_arn: str | None = None

            sel_list = await safe_api_call(
                client.list_backup_selections(BackupPlanId=plan_id),
                default={"BackupSelectionsList": []},
            )
            self._record(
                "backup:ListBackupSelections",
                target_arn=plan_arn,
                detection_cost=get_detection_score(
                    "backup:ListBackupSelections"
                ),
            )

            for sel_item in (sel_list or {}).get("BackupSelectionsList", []):
                sel_id = sel_item.get("SelectionId", "")
                if not backup_role_arn:
                    backup_role_arn = sel_item.get("IamRoleArn")

                # Get the actual selection details (resource ARNs, tags)
                sel_detail = await safe_api_call(
                    client.get_backup_selection(
                        BackupPlanId=plan_id,
                        SelectionId=sel_id,
                    ),
                    default=None,
                )
                self._record(
                    "backup:GetBackupSelection",
                    target_arn=plan_arn,
                    detection_cost=get_detection_score(
                        "backup:GetBackupSelection"
                    ),
                )

                if sel_detail:
                    sel_data = sel_detail.get("BackupSelection", {})
                    sel_resources = sel_data.get("Resources", [])
                    sel_tags = sel_data.get("ListOfTags", [])
                    sel_conditions = sel_data.get("Conditions", {})

                    protected_arns.extend(sel_resources)

                    selections.append({
                        "selection_name": sel_data.get(
                            "SelectionName", ""
                        ),
                        "resources": sel_resources,
                        "tag_conditions": sel_tags,
                        "conditions": sel_conditions,
                        "iam_role_arn": sel_data.get("IamRoleArn", ""),
                    })

            creation_date = raw_plan.get("CreationDate")
            plan_model = BackupPlan(
                plan_id=plan_id,
                plan_name=raw_plan.get("BackupPlanName", ""),
                arn=plan_arn,
                region=region,
                creation_date=(
                    str(creation_date) if creation_date else None
                ),
                rules=rules,
                protected_resource_arns=protected_arns,
                protected_resource_types=list(set(protected_types)),
                selections=selections,
                backup_role_arn=backup_role_arn,
            )
            plans.append(plan_model)

        return plans
