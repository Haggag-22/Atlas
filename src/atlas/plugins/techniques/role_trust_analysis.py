"""Role trust analysis: get trust policies for IAM roles (T1098 - Account Manipulation)."""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from atlas.core.plugin import TechniquePlugin, TechniqueResult
from atlas.core.state import CampaignState
from atlas.plugins.base_aws import (
    apply_rate_limit,
    ensure_safe_account_and_region,
    get_boto_session,
    get_caller_identity,
    record_telemetry,
)


class RoleTrustAnalysisPlugin(TechniquePlugin):
    """Analyze IAM role trust policies for cross-account or overly permissive trust."""

    @property
    def id(self) -> str:
        return "role_trust_analysis"

    @property
    def name(self) -> str:
        return "Role Trust Analysis"

    @property
    def description(self) -> str:
        return "Retrieve and analyze trust policies of IAM roles."

    @property
    def mitre_technique(self) -> str:
        return "T1098"

    @property
    def required_permissions(self) -> list[str]:
        return ["iam:ListRoles", "iam:GetRole", "sts:GetCallerIdentity"]

    def execute(
        self,
        state: CampaignState,
        parameters: dict[str, Any],
        config: Any = None,
    ) -> TechniqueResult:
        if not config:
            return TechniqueResult(success=False, error="Config required")
        session = get_boto_session(config)
        region = config.aws_region
        identity = get_caller_identity(session)
        if not identity:
            return TechniqueResult(success=False, error="Could not get caller identity")
        account_id = identity.get("Account", "")
        ok, msg = ensure_safe_account_and_region(config, account_id, region)
        if not ok:
            return TechniqueResult(success=False, error=msg)
        iam = session.client("iam")
        roles_detail: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for r in page.get("Roles", []):
                    apply_rate_limit(config)
                    role_info = iam.get_role(RoleName=r["RoleName"])
                    record_telemetry("role_trust_analysis", "iam:GetRole", service="iam", resource_arn=r.get("Arn"))
                    trust = role_info["Role"].get("AssumeRolePolicyDocument", {})
                    principal = trust.get("Statement", [{}])[0].get("Principal", {}) if trust.get("Statement") else {}
                    roles_detail.append({
                        "role_name": r["RoleName"],
                        "arn": r["Arn"],
                        "trust_policy": trust,
                        "principal": principal,
                    })
                    if isinstance(principal.get("AWS"), str) and principal.get("AWS") == "*":
                        findings.append({
                            "finding_type": "wildcard_trust",
                            "severity": "high",
                            "title": "Wildcard principal in role trust",
                            "description": f"Role {r['RoleName']} allows any AWS principal to assume it",
                            "resource_arn": r.get("Arn"),
                            "resource_type": "iam_role",
                            "technique_id": self.id,
                        })
        except ClientError as e:
            return TechniqueResult(success=False, error=str(e), outputs={"roles": roles_detail})
        return TechniqueResult(
            success=True,
            message=f"Analyzed trust for {len(roles_detail)} roles",
            outputs={
                "roles_detail": roles_detail,
                "roles": [
                    {"arn": r["arn"], "role_name": r["role_name"], "account_id": account_id, "trust_policy": r["trust_policy"]}
                    for r in roles_detail
                ],
            },
            findings=findings,
            resources=[{"resource_type": "iam_role", "identifier": r["role_name"], "arn": r["arn"], "details": {"trust_policy": r["trust_policy"]}} for r in roles_detail],
        )
