"""S3 bucket enumeration (T1530 - Cloud Object Storage)."""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from atlas.core.plugin import TechniquePlugin, TechniqueResult
from atlas.core.state import CampaignState
from atlas.core.safety import check_region_allowed as safety_check_region
from atlas.plugins.base_aws import (
    apply_rate_limit,
    ensure_safe_account_and_region,
    get_boto_session,
    get_caller_identity,
    record_telemetry,
)


class S3EnumerationPlugin(TechniquePlugin):
    """List S3 buckets and optionally their region and public access block."""

    @property
    def id(self) -> str:
        return "s3_enumeration"

    @property
    def name(self) -> str:
        return "S3 Bucket Enumeration"

    @property
    def description(self) -> str:
        return "List S3 buckets in the account and retrieve basic attributes."

    @property
    def mitre_technique(self) -> str:
        return "T1530"

    @property
    def required_permissions(self) -> list[str]:
        return ["s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketPublicAccessBlock", "sts:GetCallerIdentity"]

    def get_input_schema(self) -> dict[str, Any]:
        return {"include_public_block": {"type": "boolean", "default": True}}

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
        include_public = parameters.get("include_public_block", True)
        s3 = session.client("s3")
        buckets: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        try:
            resp = s3.list_buckets()
            record_telemetry("s3_enumeration", "s3:ListAllMyBuckets", service="s3", result="success")
            apply_rate_limit(config)
            for b in resp.get("Buckets", []):
                name = b["Name"]
                loc = None
                try:
                    loc = s3.get_bucket_location(Bucket=name)
                    apply_rate_limit(config)
                    record_telemetry("s3_enumeration", "s3:GetBucketLocation", service="s3", resource_arn=f"arn:aws:s3:::{name}")
                except ClientError:
                    pass
                bucket_region = loc.get("LocationConstraint") or "us-east-1"
                if not safety_check_region(bucket_region, config.safety):
                    continue
                public_block = None
                if include_public:
                    try:
                        public_block = s3.get_bucket_public_access_block(Bucket=name)
                        apply_rate_limit(config)
                    except ClientError:
                        public_block = {"no_block": True}
                buckets.append({
                    "name": name,
                    "creation_date": b.get("CreationDate", "").isoformat() if b.get("CreationDate") else None,
                    "region": bucket_region,
                    "public_access_block": public_block,
                })
                if public_block is not None and public_block.get("no_block"):
                    findings.append({
                        "finding_type": "s3_no_public_access_block",
                        "severity": "medium",
                        "title": "S3 bucket has no public access block",
                        "description": f"Bucket {name} may allow public access",
                        "resource_arn": f"arn:aws:s3:::{name}",
                        "resource_type": "s3_bucket",
                        "region": bucket_region,
                        "technique_id": self.id,
                    })
        except ClientError as e:
            record_telemetry("s3_enumeration", "s3:ListAllMyBuckets", result="failure", error=str(e))
            return TechniqueResult(success=False, error=str(e), outputs={"buckets": buckets})
        return TechniqueResult(
            success=True,
            message=f"Enumerated {len(buckets)} S3 buckets",
            outputs={"buckets": buckets},
            findings=findings,
            resources=[
                {"resource_type": "s3_bucket", "identifier": b["name"], "arn": f"arn:aws:s3:::{b['name']}", "region": b["region"], "details": b}
                for b in buckets
            ],
        )
