"""
atlas.recon.collectors.resource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers AWS resources: S3 buckets, EC2 instances, Lambda functions.

Populates resource nodes in the graph.  Resource policies (S3 bucket
policies, Lambda resource policies) are captured for the planner's
resource-based attack path analysis.
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.models import EC2Instance, LambdaFunction, S3Bucket
from atlas.core.types import NodeType
from atlas.knowledge.api_profiles import get_detection_score
from atlas.recon.base import BaseCollector
from atlas.utils.aws import async_paginate, safe_api_call

logger = structlog.get_logger(__name__)


class ResourceCollector(BaseCollector):
    """Discover S3, EC2, and Lambda resources."""

    @property
    def collector_id(self) -> str:
        return "resource"

    @property
    def description(self) -> str:
        return "Discover S3 buckets, EC2 instances, and Lambda functions."

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        stats = {"s3_buckets": 0, "ec2_instances": 0, "lambda_functions": 0}
        resource_types = self._config.recon.resource_types

        if "s3" in resource_types:
            stats["s3_buckets"] = await self._collect_s3(account_id, region)
        if "ec2" in resource_types:
            stats["ec2_instances"] = await self._collect_ec2(account_id, region)
        if "lambda" in resource_types:
            stats["lambda_functions"] = await self._collect_lambda(account_id, region)

        logger.info("resource_collection_complete", **stats)
        return stats

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------
    async def _collect_s3(self, account_id: str, region: str) -> int:
        count = 0
        async with self._session.client("s3", region_name=region) as s3:
            resp = await safe_api_call(s3.list_buckets(), default={"Buckets": []})
            self._record("s3:ListBuckets", detection_cost=get_detection_score("s3:ListBuckets"))

            for raw in (resp or {}).get("Buckets", []):
                name = raw["Name"]
                bucket_arn = f"arn:aws:s3:::{name}"

                # Get bucket policy
                policy = await safe_api_call(
                    s3.get_bucket_policy(Bucket=name), default=None,
                )
                self._record("s3:GetBucketPolicy", target_arn=bucket_arn,
                             detection_cost=get_detection_score("s3:GetBucketPolicy"))
                bucket_policy = None
                if policy:
                    import json
                    try:
                        bucket_policy = json.loads(policy.get("Policy", "{}"))
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Get public access block
                pab = await safe_api_call(
                    s3.get_public_access_block(Bucket=name), default=None,
                )
                self._record("s3:GetBucketPublicAccessBlock", target_arn=bucket_arn,
                             detection_cost=get_detection_score("s3:GetBucketPublicAccessBlock"))
                pab_config: dict[str, bool] = {}
                if pab:
                    pab_config = {
                        k: v for k, v in
                        pab.get("PublicAccessBlockConfiguration", {}).items()
                        if isinstance(v, bool)
                    }

                bucket = S3Bucket(
                    name=name,
                    arn=bucket_arn,
                    region=region,
                    creation_date=str(raw.get("CreationDate", "")),
                    public_access_block=pab_config,
                    bucket_policy=bucket_policy,
                )

                self._graph.add_node(
                    bucket_arn, NodeType.S3_BUCKET,
                    data=bucket.model_dump(), label=name,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # EC2
    # ------------------------------------------------------------------
    async def _collect_ec2(self, account_id: str, region: str) -> int:
        count = 0
        async with self._session.client("ec2", region_name=region) as ec2:
            resp = await safe_api_call(
                ec2.describe_instances(), default={"Reservations": []},
            )
            self._record("ec2:DescribeInstances",
                         detection_cost=get_detection_score("ec2:DescribeInstances"))

            for reservation in (resp or {}).get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    instance_id = inst["InstanceId"]
                    inst_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"

                    # Check IMDS configuration
                    metadata_options = inst.get("MetadataOptions", {})
                    imds_v2 = metadata_options.get("HttpTokens") == "required"

                    # Instance profile
                    iam_profile = inst.get("IamInstanceProfile", {})
                    profile_arn = iam_profile.get("Arn") if iam_profile else None

                    instance = EC2Instance(
                        instance_id=instance_id,
                        arn=inst_arn,
                        region=region,
                        state=inst.get("State", {}).get("Name", "unknown"),
                        instance_profile_arn=profile_arn,
                        public_ip=inst.get("PublicIpAddress"),
                        private_ip=inst.get("PrivateIpAddress"),
                        security_group_ids=[
                            sg["GroupId"] for sg in inst.get("SecurityGroups", [])
                        ],
                        subnet_id=inst.get("SubnetId"),
                        vpc_id=inst.get("VpcId"),
                        imds_v2_required=imds_v2,
                        tags={
                            t["Key"]: t["Value"] for t in inst.get("Tags", [])
                        },
                    )

                    self._graph.add_node(
                        inst_arn, NodeType.EC2_INSTANCE,
                        data=instance.model_dump(), label=instance_id,
                    )
                    count += 1

        return count

    # ------------------------------------------------------------------
    # Lambda
    # ------------------------------------------------------------------
    async def _collect_lambda(self, account_id: str, region: str) -> int:
        count = 0
        async with self._session.client("lambda", region_name=region) as lam:
            raw_functions = await async_paginate(lam, "list_functions", "Functions")
            self._record("lambda:ListFunctions",
                         detection_cost=get_detection_score("lambda:ListFunctions"))

            for raw in raw_functions:
                func_arn = raw["FunctionArn"]
                func_name = raw["FunctionName"]

                # Get resource policy
                policy_resp = await safe_api_call(
                    lam.get_policy(FunctionName=func_name), default=None,
                )
                self._record("lambda:GetPolicy", target_arn=func_arn,
                             detection_cost=get_detection_score("lambda:GetPolicy"))
                resource_policy = None
                if policy_resp:
                    import json
                    try:
                        resource_policy = json.loads(policy_resp.get("Policy", "{}"))
                    except (json.JSONDecodeError, TypeError):
                        pass

                env_vars = raw.get("Environment", {}).get("Variables", {})
                # Redact potential secrets in env vars for safety
                safe_env = {
                    k: "***REDACTED***" if any(s in k.upper() for s in ("SECRET", "PASSWORD", "TOKEN", "KEY"))
                    else v
                    for k, v in env_vars.items()
                }

                function = LambdaFunction(
                    function_name=func_name,
                    arn=func_arn,
                    region=region,
                    runtime=raw.get("Runtime"),
                    role_arn=raw.get("Role"),
                    handler=raw.get("Handler"),
                    environment_variables=safe_env,
                    layers=[
                        layer["Arn"] for layer in raw.get("Layers", [])
                    ],
                    resource_policy=resource_policy,
                )

                self._graph.add_node(
                    func_arn, NodeType.LAMBDA_FUNCTION,
                    data=function.model_dump(), label=func_name,
                )
                count += 1

        return count
