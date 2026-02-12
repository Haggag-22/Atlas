"""Security group enumeration (T1565 - Cloud storage discovery)."""

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


class SecurityGroupEnumerationPlugin(TechniquePlugin):
    """List EC2 security groups and their rules in allowed regions."""

    @property
    def id(self) -> str:
        return "security_group_enumeration"

    @property
    def name(self) -> str:
        return "Security Group Enumeration"

    @property
    def description(self) -> str:
        return "List EC2 security groups and their ingress/egress rules."

    @property
    def mitre_technique(self) -> str:
        return "T1565"

    @property
    def required_permissions(self) -> list[str]:
        return ["ec2:DescribeSecurityGroups", "ec2:DescribeVpcs", "sts:GetCallerIdentity"]

    def get_input_schema(self) -> dict[str, Any]:
        return {"regions": {"type": "array", "items": {"type": "string"}, "description": "Override regions to scan"}}

    def execute(
        self,
        state: CampaignState,
        parameters: dict[str, Any],
        config: Any = None,
    ) -> TechniqueResult:
        if not config:
            return TechniqueResult(success=False, error="Config required")
        session = get_boto_session(config)
        identity = get_caller_identity(session)
        if not identity:
            return TechniqueResult(success=False, error="Could not get caller identity")
        account_id = identity.get("Account", "")
        regions = parameters.get("regions") or config.safety.allowed_regions
        regions = [r for r in regions if ensure_safe_account_and_region(config, account_id, r)[0]]
        if not regions:
            return TechniqueResult(success=False, error="No allowed regions to scan")
        all_groups: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            try:
                paginator = ec2.get_paginator("describe_security_groups")
                for page in paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        apply_rate_limit(config)
                        record_telemetry(
                            "security_group_enumeration",
                            "ec2:DescribeSecurityGroups",
                            service="ec2",
                            resource_arn=sg.get("GroupId"),
                            region=region,
                        )
                        all_groups.append({
                            "group_id": sg.get("GroupId"),
                            "group_name": sg.get("GroupName"),
                            "vpc_id": sg.get("VpcId"),
                            "description": sg.get("Description"),
                            "region": region,
                            "ip_permissions": sg.get("IpPermissions", []),
                            "ip_permissions_egress": sg.get("IpPermissionsEgress", []),
                        })
                        for perm in sg.get("IpPermissions", []):
                            if _is_open_to_world(perm):
                                findings.append({
                                    "finding_type": "sg_open_to_world",
                                    "severity": "medium",
                                    "title": "Security group allows 0.0.0.0/0",
                                    "description": f"SG {sg.get('GroupName')} ({sg.get('GroupId')}) in {region} has open ingress",
                                    "resource_arn": f"arn:aws:ec2:{region}:{account_id}:security-group/{sg.get('GroupId')}",
                                    "resource_type": "security_group",
                                    "region": region,
                                    "technique_id": self.id,
                                    "evidence": {"perm": perm},
                                })
                                break
            except ClientError as e:
                record_telemetry("security_group_enumeration", "ec2:DescribeSecurityGroups", region=region, result="failure", error=str(e))
                continue
        return TechniqueResult(
            success=True,
            message=f"Enumerated {len(all_groups)} security groups across {len(regions)} regions",
            outputs={"security_groups": all_groups},
            findings=findings,
            resources=[
                {
                    "resource_type": "security_group",
                    "identifier": g["group_id"],
                    "arn": f"arn:aws:ec2:{g['region']}:{account_id}:security-group/{g['group_id']}",
                    "region": g["region"],
                    "details": g,
                }
                for g in all_groups
            ],
        )


def _is_open_to_world(perm: dict[str, Any]) -> bool:
    for r in perm.get("IpRanges", []):
        if isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0":
            return True
    for r in perm.get("Ipv6Ranges", []):
        if isinstance(r, dict) and r.get("CidrIpv6") == "::/0":
            return True
    return False
