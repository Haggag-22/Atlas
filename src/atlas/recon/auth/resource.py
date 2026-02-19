"""
atlas.recon.auth.resource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers AWS resources: S3 buckets, EC2 instances, Lambda functions,
RDS instances, KMS keys, Secrets Manager secrets, SSM parameters, and
CloudFormation stacks.

Populates resource nodes in the graph.  Resource policies (S3 bucket
policies, Lambda resource policies, KMS key policies, Secrets Manager
resource policies) are captured for the planner's resource-based attack
path analysis.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from atlas.core.models import (
    BedrockAgent,
    CloudFormationStack,
    CloudFrontDistribution,
    CodeBuildProject,
    CognitoIdentityPool,
    CognitoUserPool,
    EBSSnapshot,
    EC2Instance,
    EFSFileSystem,
    ElasticBeanstalkEnvironment,
    ECRRepository,
    ECSTaskDefinition,
    KMSKey,
    LambdaFunction,
    RDSInstance,
    S3Bucket,
    SecretsManagerSecret,
    SSMParameter,
)
from atlas.core.types import NodeType
from atlas.knowledge.api_profiles import get_detection_score
from atlas.recon.base import BaseCollector
from atlas.utils.aws import async_paginate, safe_api_call

logger = structlog.get_logger(__name__)


class ResourceCollector(BaseCollector):
    """Discover S3, EC2, Lambda, RDS, KMS, Secrets Manager, SSM, CloudFormation, and public EBS snapshots."""

    @property
    def collector_id(self) -> str:
        return "resource"

    @property
    def description(self) -> str:
        return (
            "Discover S3 buckets, EC2 instances, Lambda functions, RDS instances, "
            "KMS keys, Secrets Manager secrets, SSM parameters, CloudFormation stacks, "
            "and publicly exposed EBS snapshots."
        )

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        stats: dict[str, int] = {
            "s3_buckets": 0,
            "ec2_instances": 0,
            "lambda_functions": 0,
            "rds_instances": 0,
            "kms_keys": 0,
            "secrets_manager_secrets": 0,
            "ssm_parameters": 0,
            "cloudformation_stacks": 0,
            "ebs_public_snapshots": 0,
            "ecs_task_definitions": 0,
            "ecr_repositories": 0,
            "cognito_user_pools": 0,
            "cognito_identity_pools": 0,
            "cloudfront_distributions": 0,
            "codebuild_projects": 0,
            "elasticbeanstalk_environments": 0,
            "bedrock_agents": 0,
            "efs_file_systems": 0,
            "skipped_no_permission": 0,
        }
        resource_types = self._config.recon.resource_types

        if "s3" in resource_types and self._caller_has("s3:ListBuckets"):
            stats["s3_buckets"] = await self._collect_s3(account_id, region)
        elif "s3" in resource_types:
            logger.info("resource_skipped", service="s3", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "ec2" in resource_types and self._caller_has("ec2:DescribeInstances"):
            stats["ec2_instances"] = await self._collect_ec2(account_id, region)
        elif "ec2" in resource_types:
            logger.info("resource_skipped", service="ec2", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "lambda" in resource_types and self._caller_has("lambda:ListFunctions"):
            stats["lambda_functions"] = await self._collect_lambda(account_id, region)
        elif "lambda" in resource_types:
            logger.info("resource_skipped", service="lambda", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "rds" in resource_types and self._caller_has("rds:DescribeDBInstances"):
            stats["rds_instances"] = await self._collect_rds(account_id, region)
        elif "rds" in resource_types:
            logger.info("resource_skipped", service="rds", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "kms" in resource_types and self._caller_has("kms:ListKeys"):
            stats["kms_keys"] = await self._collect_kms(account_id, region)
        elif "kms" in resource_types:
            logger.info("resource_skipped", service="kms", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "secretsmanager" in resource_types and self._caller_has("secretsmanager:ListSecrets"):
            stats["secrets_manager_secrets"] = await self._collect_secrets_manager(account_id, region)
        elif "secretsmanager" in resource_types:
            logger.info("resource_skipped", service="secretsmanager", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "ssm" in resource_types and self._caller_has("ssm:DescribeParameters"):
            stats["ssm_parameters"] = await self._collect_ssm(account_id, region)
        elif "ssm" in resource_types:
            logger.info("resource_skipped", service="ssm", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "cloudformation" in resource_types and self._caller_has("cloudformation:DescribeStacks"):
            stats["cloudformation_stacks"] = await self._collect_cloudformation(account_id, region)
        elif "cloudformation" in resource_types:
            logger.info("resource_skipped", service="cloudformation", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "ebs" in resource_types and self._caller_has("ec2:DescribeSnapshots"):
            stats["ebs_public_snapshots"] = await self._collect_public_ebs_snapshots(account_id, region)
        elif "ebs" in resource_types:
            logger.info("resource_skipped", service="ebs", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "ecs" in resource_types and self._caller_has("ecs:ListTaskDefinitions"):
            stats["ecs_task_definitions"] = await self._collect_ecs(account_id, region)
        elif "ecs" in resource_types:
            logger.info("resource_skipped", service="ecs", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "efs" in resource_types and self._caller_has("elasticfilesystem:DescribeFileSystems"):
            stats["efs_file_systems"] = await self._collect_efs(account_id, region)
        elif "efs" in resource_types:
            logger.info("resource_skipped", service="efs", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "ecr" in resource_types and self._caller_has("ecr:DescribeRepositories"):
            stats["ecr_repositories"] = await self._collect_ecr(account_id, region)
        elif "ecr" in resource_types:
            logger.info("resource_skipped", service="ecr", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "cognito" in resource_types and self._caller_has("cognito-idp:ListUserPools"):
            stats["cognito_user_pools"] = await self._collect_cognito(account_id, region)
        if "cognito" in resource_types and self._caller_has("cognito-identity:ListIdentityPools"):
            stats["cognito_identity_pools"] = await self._collect_cognito_identity_pools(
                account_id, region
            )
        if (
            "cognito" in resource_types
            and not self._caller_has("cognito-idp:ListUserPools")
            and not self._caller_has("cognito-identity:ListIdentityPools")
        ):
            logger.info("resource_skipped", service="cognito", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "cloudfront" in resource_types and region == "us-east-1" and self._caller_has("cloudfront:ListDistributions"):
            stats["cloudfront_distributions"] = await self._collect_cloudfront(account_id, region)
        elif "cloudfront" in resource_types and region != "us-east-1":
            pass  # CloudFront is global; only collect in us-east-1
        elif "cloudfront" in resource_types:
            logger.info("resource_skipped", service="cloudfront", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "codebuild" in resource_types and self._caller_has("codebuild:ListProjects"):
            stats["codebuild_projects"] = await self._collect_codebuild(account_id, region)
        elif "codebuild" in resource_types:
            logger.info("resource_skipped", service="codebuild", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "elasticbeanstalk" in resource_types and self._caller_has("elasticbeanstalk:DescribeEnvironments"):
            stats["elasticbeanstalk_environments"] = await self._collect_elasticbeanstalk(account_id, region)
        elif "elasticbeanstalk" in resource_types:
            logger.info("resource_skipped", service="elasticbeanstalk", reason="no permission")
            stats["skipped_no_permission"] += 1

        if "bedrock" in resource_types and self._caller_has("bedrock:ListAgents"):
            stats["bedrock_agents"] = await self._collect_bedrock_agents(account_id, region)
        elif "bedrock" in resource_types:
            logger.info("resource_skipped", service="bedrock", reason="no permission")
            stats["skipped_no_permission"] += 1

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

                    # Check if user data exists (credential harvesting vector)
                    user_data_present = False
                    ud_resp = await safe_api_call(
                        ec2.describe_instance_attribute(
                            InstanceId=instance_id,
                            Attribute="userData",
                        ),
                        default=None,
                    )
                    self._record(
                        "ec2:DescribeInstanceAttribute",
                        target_arn=inst_arn,
                        detection_cost=get_detection_score(
                            "ec2:DescribeInstanceAttribute"
                        ),
                    )
                    if ud_resp:
                        ud_value = ud_resp.get("UserData", {})
                        # UserData is a dict with a "Value" key when present
                        if isinstance(ud_value, dict) and ud_value.get("Value"):
                            user_data_present = True
                        elif isinstance(ud_value, str) and ud_value:
                            user_data_present = True

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
                        user_data_available=user_data_present,
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

    # ------------------------------------------------------------------
    # ECS
    # ------------------------------------------------------------------
    async def _collect_ecs(self, account_id: str, region: str) -> int:
        """Collect ECS task definitions with task roles (credential theft vector)."""
        count = 0
        async with self._session.client("ecs", region_name=region) as ecs:
            raw_tds = await async_paginate(
                ecs, "list_task_definitions", "taskDefinitionArns",
            )
            self._record(
                "ecs:ListTaskDefinitions",
                detection_cost=get_detection_score("ecs:ListTaskDefinitions"),
            )

            seen: set[str] = set()
            for td_arn in raw_tds or []:
                if td_arn in seen:
                    continue
                seen.add(td_arn)

                desc = await safe_api_call(
                    ecs.describe_task_definition(taskDefinition=td_arn),
                    default=None,
                )
                self._record(
                    "ecs:DescribeTaskDefinition",
                    target_arn=td_arn,
                    detection_cost=get_detection_score("ecs:DescribeTaskDefinition"),
                )
                if not desc:
                    continue

                td = desc.get("taskDefinition", {})
                task_role = td.get("taskRoleArn")
                exec_role = td.get("executionRoleArn")
                if not task_role:
                    continue

                family = td.get("family", td_arn.split("/")[-1].rsplit(":", 1)[0])
                compat = td.get("requiresCompatibilities") or []
                launch_type = "FARGATE" if "FARGATE" in compat else "EC2"

                task_def = ECSTaskDefinition(
                    family=family,
                    arn=td_arn,
                    region=region,
                    task_role_arn=task_role,
                    execution_role_arn=exec_role,
                    network_mode=td.get("networkMode", "bridge"),
                    launch_type=launch_type,
                )

                self._graph.add_node(
                    td_arn, NodeType.ECS_TASK_DEFINITION,
                    data=task_def.model_dump(), label=family,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # EFS
    # ------------------------------------------------------------------
    async def _collect_efs(self, account_id: str, region: str) -> int:
        """Collect EFS file systems with mount targets (VPC/subnet for EC2 reachability)."""
        count = 0
        async with self._session.client("efs", region_name=region) as efs:
            raw_fs = await async_paginate(
                efs, "describe_file_systems", "FileSystems",
            )
            self._record(
                "elasticfilesystem:DescribeFileSystems",
                detection_cost=get_detection_score("elasticfilesystem:DescribeFileSystems"),
            )

            for raw in raw_fs or []:
                fs_id = raw.get("FileSystemId")
                if not fs_id:
                    continue
                fs_arn = raw.get("FileArn", f"arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{fs_id}")

                mt_resp = await safe_api_call(
                    efs.describe_mount_targets(FileSystemId=fs_id),
                    default={"MountTargets": []},
                )
                self._record(
                    "elasticfilesystem:DescribeMountTargets",
                    target_arn=fs_arn,
                    detection_cost=get_detection_score("elasticfilesystem:DescribeMountTargets"),
                )

                vpc_ids: list[str] = []
                subnet_ids: list[str] = []
                for mt in mt_resp.get("MountTargets", []):
                    if mt.get("VpcId"):
                        vpc_ids.append(mt["VpcId"])
                    if mt.get("SubnetId"):
                        subnet_ids.append(mt["SubnetId"])

                efs_model = EFSFileSystem(
                    file_system_id=fs_id,
                    arn=fs_arn,
                    region=region,
                    vpc_ids=list(dict.fromkeys(vpc_ids)),
                    subnet_ids=list(dict.fromkeys(subnet_ids)),
                )

                self._graph.add_node(
                    fs_arn, NodeType.EFS_FILE_SYSTEM,
                    data=efs_model.model_dump(), label=fs_id,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # ECR
    # ------------------------------------------------------------------
    async def _collect_ecr(self, account_id: str, region: str) -> int:
        """Collect ECR repositories with resource policies (misconfig vector)."""
        count = 0
        async with self._session.client("ecr", region_name=region) as ecr:
            raw_repos = await async_paginate(
                ecr, "describe_repositories", "repositories",
            )
            self._record(
                "ecr:DescribeRepositories",
                detection_cost=get_detection_score("ecr:DescribeRepositories"),
            )

            for raw in raw_repos or []:
                repo_name = raw["repositoryName"]
                repo_arn = raw["repositoryArn"]
                repo_uri = raw.get("repositoryUri", "")

                policy_resp = await safe_api_call(
                    ecr.get_repository_policy(repositoryName=repo_name),
                    default=None,
                )
                self._record(
                    "ecr:GetRepositoryPolicy",
                    target_arn=repo_arn,
                    detection_cost=get_detection_score("ecr:GetRepositoryPolicy"),
                )
                resource_policy = None
                if policy_resp:
                    try:
                        resource_policy = json.loads(
                            policy_resp.get("policy", "{}"),
                        )
                    except (json.JSONDecodeError, TypeError):
                        pass

                repo = ECRRepository(
                    repository_name=repo_name,
                    arn=repo_arn,
                    region=region,
                    repository_uri=repo_uri,
                    resource_policy=resource_policy,
                    image_tag_mutability=raw.get("imageTagMutability", "MUTABLE"),
                )

                self._graph.add_node(
                    repo_arn, NodeType.ECR_REPOSITORY,
                    data=repo.model_dump(), label=repo_name,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # Cognito
    # ------------------------------------------------------------------
    async def _collect_cognito(self, account_id: str, region: str) -> int:
        """Collect Cognito User Pools (self-signup misconfig vector)."""
        count = 0
        async with self._session.client("cognito-idp", region_name=region) as cognito:
            raw_pools = await async_paginate(
                cognito, "list_user_pools", "UserPools",
                MaxResults=60,
            )
            self._record(
                "cognito-idp:ListUserPools",
                detection_cost=get_detection_score("cognito-idp:ListUserPools"),
            )

            for raw in raw_pools or []:
                pool_id = raw["Id"]
                pool_name = raw.get("Name", "")

                desc = await safe_api_call(
                    cognito.describe_user_pool(UserPoolId=pool_id),
                    default=None,
                )
                self._record(
                    "cognito-idp:DescribeUserPool",
                    target_arn=f"arn:aws:cognito-idp:{region}:{account_id}:userpool/{pool_id}",
                    detection_cost=get_detection_score("cognito-idp:DescribeUserPool"),
                )
                if not desc:
                    continue

                pool = desc.get("UserPool", {})
                admin_config = pool.get("AdminCreateUserConfig", {})

                user_pool = CognitoUserPool(
                    pool_id=pool_id,
                    arn=f"arn:aws:cognito-idp:{region}:{account_id}:userpool/{pool_id}",
                    region=region,
                    name=pool.get("Name", pool_name),
                    admin_create_user_config=admin_config,
                    auto_verified_attributes=pool.get("AutoVerifiedAttributes", []),
                )

                self._graph.add_node(
                    user_pool.arn, NodeType.COGNITO_USER_POOL,
                    data=user_pool.model_dump(), label=pool.get("Name", pool_id),
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # Cognito Identity Pools (federation -> temp AWS creds)
    # ------------------------------------------------------------------
    async def _collect_cognito_identity_pools(
        self, account_id: str, region: str
    ) -> int:
        """Collect Cognito Identity Pools and their IAM role mappings.

        Overpermissioned identity pools issue temp creds with excessive
        IAM permissions. Attack: authenticate (self-signup/creds) -> get
        ID token -> exchange for identity pool creds -> abuse role.
        """
        count = 0
        async with self._session.client(
            "cognito-identity", region_name=region
        ) as cognito_id:
            raw_pools = await async_paginate(
                cognito_id, "list_identity_pools", "IdentityPools",
                MaxResults=60,
            )
            self._record(
                "cognito-identity:ListIdentityPools",
                detection_cost=get_detection_score(
                    "cognito-identity:ListIdentityPools"
                ),
            )

            for raw in raw_pools or []:
                pool_id = raw.get("IdentityPoolId")
                pool_name = raw.get("IdentityPoolName", "")

                roles_resp = await safe_api_call(
                    cognito_id.get_identity_pool_roles(
                        IdentityPoolId=pool_id,
                    ),
                    default=None,
                )
                self._record(
                    "cognito-identity:GetIdentityPoolRoles",
                    target_arn=f"arn:aws:cognito-identity:{region}:{account_id}:identitypool/{pool_id}",
                    detection_cost=get_detection_score(
                        "cognito-identity:GetIdentityPoolRoles"
                    ),
                )
                if not roles_resp:
                    continue

                roles = roles_resp.get("Roles", {})
                allow_unauth = "unauthenticated" in roles

                identity_pool = CognitoIdentityPool(
                    identity_pool_id=pool_id,
                    arn=f"arn:aws:cognito-identity:{region}:{account_id}:identitypool/{pool_id}",
                    region=region,
                    identity_pool_name=pool_name,
                    roles=roles,
                    allow_unauthenticated=allow_unauth,
                )

                self._graph.add_node(
                    identity_pool.arn,
                    NodeType.COGNITO_IDENTITY_POOL,
                    data=identity_pool.model_dump(),
                    label=pool_name or pool_id,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # CloudFront (for S3 origin takeover detection)
    # ------------------------------------------------------------------
    async def _collect_cloudfront(self, account_id: str, region: str) -> int:
        """Collect CloudFront distributions; flag orphaned S3 origins."""
        count = 0
        # CloudFront is global; use us-east-1
        cf_region = "us-east-1"
        async with self._session.client(
            "cloudfront", region_name=cf_region
        ) as cloudfront:
            raw_list = await safe_api_call(
                cloudfront.list_distributions(), default={"DistributionList": {}},
            )
            self._record(
                "cloudfront:ListDistributions",
                detection_cost=get_detection_score("cloudfront:ListDistributions"),
            )

            items = (raw_list or {}).get("DistributionList", {}).get("Items", [])
            for raw in items:
                dist_id = raw.get("Id")
                if not dist_id:
                    continue

                desc = await safe_api_call(
                    cloudfront.get_distribution(Id=dist_id),
                    default=None,
                )
                self._record(
                    "cloudfront:GetDistribution",
                    detection_cost=get_detection_score("cloudfront:GetDistribution"),
                )
                if not desc:
                    continue

                dist = desc.get("Distribution", {})
                origins = dist.get("Origins", {}).get("Items", [])

                for origin in origins:
                    domain = origin.get("DomainName", "")
                    if not domain:
                        continue
                    # S3 origin: bucket.s3.amazonaws.com or bucket.s3-website.region.amazonaws.com
                    if ".s3." in domain and "amazonaws.com" in domain:
                        bucket_name = domain.split(".s3.")[0].split(".")[-1]
                        if bucket_name:
                            cf_dist = CloudFrontDistribution(
                                distribution_id=dist_id,
                                arn=f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}",
                                origin_domain=domain,
                                origin_bucket=bucket_name,
                                aliases=dist.get("Aliases", {}).get("Items", []),
                            )
                            self._graph.add_node(
                                cf_dist.arn,
                                NodeType.CLOUDFRONT_DISTRIBUTION,
                                data=cf_dist.model_dump(),
                                label=f"cf-{dist_id}",
                            )
                            count += 1
                            break

        return count

    # ------------------------------------------------------------------
    # RDS
    # ------------------------------------------------------------------
    async def _collect_rds(self, account_id: str, region: str) -> int:
        count = 0
        async with self._session.client("rds", region_name=region) as rds:
            raw_instances = await async_paginate(
                rds, "describe_db_instances", "DBInstances",
            )
            self._record(
                "rds:DescribeDBInstances",
                detection_cost=get_detection_score("rds:DescribeDBInstances"),
            )

            for raw in raw_instances:
                db_id = raw["DBInstanceIdentifier"]
                db_arn = raw.get(
                    "DBInstanceArn",
                    f"arn:aws:rds:{region}:{account_id}:db:{db_id}",
                )

                endpoint = raw.get("Endpoint", {})
                vpc_sgs = raw.get("VpcSecurityGroups", [])

                instance = RDSInstance(
                    db_instance_identifier=db_id,
                    arn=db_arn,
                    region=region,
                    engine=raw.get("Engine", ""),
                    engine_version=raw.get("EngineVersion", ""),
                    db_instance_class=raw.get("DBInstanceClass", ""),
                    storage_encrypted=raw.get("StorageEncrypted", False),
                    publicly_accessible=raw.get("PubliclyAccessible", False),
                    endpoint_address=endpoint.get("Address"),
                    endpoint_port=endpoint.get("Port"),
                    vpc_id=raw.get("DBSubnetGroup", {}).get("VpcId"),
                    subnet_group_name=raw.get("DBSubnetGroup", {}).get(
                        "DBSubnetGroupName"
                    ),
                    security_group_ids=[
                        sg["VpcSecurityGroupId"]
                        for sg in vpc_sgs
                        if sg.get("Status") == "active"
                    ],
                    iam_auth_enabled=raw.get(
                        "IAMDatabaseAuthenticationEnabled", False
                    ),
                    multi_az=raw.get("MultiAZ", False),
                    auto_minor_version_upgrade=raw.get(
                        "AutoMinorVersionUpgrade", True
                    ),
                    master_username=raw.get("MasterUsername", ""),
                    kms_key_id=raw.get("KmsKeyId"),
                    tags={
                        t["Key"]: t["Value"]
                        for t in raw.get("TagList", [])
                    },
                )

                self._graph.add_node(
                    db_arn,
                    NodeType.RDS_INSTANCE,
                    data=instance.model_dump(),
                    label=db_id,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # KMS
    # ------------------------------------------------------------------
    async def _collect_kms(self, account_id: str, region: str) -> int:
        count = 0
        async with self._session.client("kms", region_name=region) as kms:
            raw_keys = await async_paginate(kms, "list_keys", "Keys")
            self._record(
                "kms:ListKeys",
                detection_cost=get_detection_score("kms:ListKeys"),
            )

            # Pre-fetch aliases for labelling
            raw_aliases = await async_paginate(kms, "list_aliases", "Aliases")
            self._record(
                "kms:ListAliases",
                detection_cost=get_detection_score("kms:ListAliases"),
            )
            alias_map: dict[str, list[str]] = {}
            for alias in raw_aliases:
                target = alias.get("TargetKeyId", "")
                if target:
                    alias_map.setdefault(target, []).append(
                        alias.get("AliasName", "")
                    )

            for raw in raw_keys:
                key_id = raw["KeyId"]
                key_arn = raw.get(
                    "KeyArn",
                    f"arn:aws:kms:{region}:{account_id}:key/{key_id}",
                )

                # Describe key for metadata
                desc_resp = await safe_api_call(
                    kms.describe_key(KeyId=key_id), default=None,
                )
                self._record(
                    "kms:DescribeKey",
                    target_arn=key_arn,
                    detection_cost=get_detection_score("kms:DescribeKey"),
                )
                meta = (desc_resp or {}).get("KeyMetadata", {})

                # Skip AWS-managed keys (aws/s3, aws/ebs, etc.) — not useful
                key_manager = meta.get("KeyManager", "CUSTOMER")
                if key_manager == "AWS":
                    continue

                # Get key policy
                key_policy = None
                policy_resp = await safe_api_call(
                    kms.get_key_policy(KeyId=key_id, PolicyName="default"),
                    default=None,
                )
                self._record(
                    "kms:GetKeyPolicy",
                    target_arn=key_arn,
                    detection_cost=get_detection_score("kms:GetKeyPolicy"),
                )
                if policy_resp:
                    try:
                        key_policy = json.loads(
                            policy_resp.get("Policy", "{}")
                        )
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Get grants
                grants_raw = await safe_api_call(
                    kms.list_grants(KeyId=key_id), default={"Grants": []},
                )
                self._record(
                    "kms:ListGrants",
                    target_arn=key_arn,
                    detection_cost=get_detection_score("kms:ListGrants"),
                )
                grants = [
                    {
                        "grant_id": g.get("GrantId", ""),
                        "grantee_principal": g.get("GranteePrincipal", ""),
                        "operations": g.get("Operations", []),
                    }
                    for g in (grants_raw or {}).get("Grants", [])
                ]

                # Check rotation
                rotation_resp = await safe_api_call(
                    kms.get_key_rotation_status(KeyId=key_id), default=None,
                )
                self._record(
                    "kms:GetKeyRotationStatus",
                    target_arn=key_arn,
                    detection_cost=get_detection_score(
                        "kms:GetKeyRotationStatus"
                    ),
                )
                rotation_enabled = False
                if rotation_resp:
                    rotation_enabled = rotation_resp.get(
                        "KeyRotationEnabled", False
                    )

                key_model = KMSKey(
                    key_id=key_id,
                    arn=key_arn,
                    region=region,
                    description=meta.get("Description", ""),
                    key_state=meta.get("KeyState", "Enabled"),
                    key_manager=key_manager,
                    key_usage=meta.get("KeyUsage", "ENCRYPT_DECRYPT"),
                    origin=meta.get("Origin", "AWS_KMS"),
                    key_policy=key_policy,
                    grants=grants,
                    rotation_enabled=rotation_enabled,
                    aliases=alias_map.get(key_id, []),
                    tags={
                        t["TagKey"]: t["TagValue"]
                        for t in meta.get("Tags", [])
                    },
                )

                label = alias_map.get(key_id, [key_id])[0]
                self._graph.add_node(
                    key_arn,
                    NodeType.KMS_KEY,
                    data=key_model.model_dump(),
                    label=label,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # Secrets Manager
    # ------------------------------------------------------------------
    async def _collect_secrets_manager(
        self, account_id: str, region: str,
    ) -> int:
        count = 0
        async with self._session.client(
            "secretsmanager", region_name=region,
        ) as sm:
            raw_secrets = await async_paginate(
                sm, "list_secrets", "SecretList",
            )
            self._record(
                "secretsmanager:ListSecrets",
                detection_cost=get_detection_score(
                    "secretsmanager:ListSecrets"
                ),
            )

            for raw in raw_secrets:
                secret_arn = raw["ARN"]
                secret_name = raw.get("Name", "")

                # Get resource policy
                resource_policy = None
                policy_resp = await safe_api_call(
                    sm.get_resource_policy(SecretId=secret_arn),
                    default=None,
                )
                self._record(
                    "secretsmanager:GetResourcePolicy",
                    target_arn=secret_arn,
                    detection_cost=get_detection_score(
                        "secretsmanager:GetResourcePolicy"
                    ),
                )
                if policy_resp and policy_resp.get("ResourcePolicy"):
                    try:
                        resource_policy = json.loads(
                            policy_resp["ResourcePolicy"]
                        )
                    except (json.JSONDecodeError, TypeError):
                        pass

                last_accessed = raw.get("LastAccessedDate")
                last_rotated = raw.get("LastRotatedDate")

                secret = SecretsManagerSecret(
                    name=secret_name,
                    arn=secret_arn,
                    region=region,
                    description=raw.get("Description", ""),
                    kms_key_id=raw.get("KmsKeyId"),
                    rotation_enabled=raw.get("RotationEnabled", False),
                    rotation_lambda_arn=raw.get("RotationLambdaARN"),
                    last_accessed_date=(
                        str(last_accessed) if last_accessed else None
                    ),
                    last_rotated_date=(
                        str(last_rotated) if last_rotated else None
                    ),
                    resource_policy=resource_policy,
                    tags={
                        t["Key"]: t["Value"]
                        for t in raw.get("Tags", [])
                    },
                )

                self._graph.add_node(
                    secret_arn,
                    NodeType.SECRETS_MANAGER,
                    data=secret.model_dump(),
                    label=secret_name,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # SSM Parameter Store
    # ------------------------------------------------------------------
    async def _collect_ssm(self, account_id: str, region: str) -> int:
        count = 0
        async with self._session.client("ssm", region_name=region) as ssm:
            raw_params = await async_paginate(
                ssm, "describe_parameters", "Parameters",
            )
            self._record(
                "ssm:DescribeParameters",
                detection_cost=get_detection_score("ssm:DescribeParameters"),
            )

            for raw in raw_params:
                param_name = raw.get("Name", "")
                param_arn = (
                    f"arn:aws:ssm:{region}:{account_id}:"
                    f"parameter{param_name}"
                )

                last_modified = raw.get("LastModifiedDate")

                param = SSMParameter(
                    name=param_name,
                    arn=param_arn,
                    region=region,
                    type=raw.get("Type", "String"),
                    description=raw.get("Description", ""),
                    tier=raw.get("Tier", "Standard"),
                    version=raw.get("Version", 1),
                    last_modified_date=(
                        str(last_modified) if last_modified else None
                    ),
                    kms_key_id=raw.get("KeyId"),
                    tags={},  # tags require a separate API call
                )

                self._graph.add_node(
                    param_arn,
                    NodeType.SSM_PARAMETER,
                    data=param.model_dump(),
                    label=param_name,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # CloudFormation
    # ------------------------------------------------------------------
    async def _collect_cloudformation(
        self, account_id: str, region: str,
    ) -> int:
        count = 0
        async with self._session.client(
            "cloudformation", region_name=region,
        ) as cfn:
            raw_stacks = await async_paginate(
                cfn, "describe_stacks", "Stacks",
            )
            self._record(
                "cloudformation:DescribeStacks",
                detection_cost=get_detection_score(
                    "cloudformation:DescribeStacks"
                ),
            )

            for raw in raw_stacks:
                stack_name = raw.get("StackName", "")
                stack_id = raw.get("StackId", "")
                stack_arn = stack_id  # StackId IS the ARN

                creation_time = raw.get("CreationTime")
                last_updated = raw.get("LastUpdatedTime")

                stack = CloudFormationStack(
                    stack_name=stack_name,
                    stack_id=stack_id,
                    arn=stack_arn,
                    region=region,
                    status=raw.get("StackStatus", ""),
                    role_arn=raw.get("RoleARN"),
                    template_description=raw.get("Description", ""),
                    creation_time=(
                        str(creation_time) if creation_time else None
                    ),
                    last_updated_time=(
                        str(last_updated) if last_updated else None
                    ),
                    capabilities=raw.get("Capabilities", []),
                    outputs=[
                        {
                            "OutputKey": o.get("OutputKey", ""),
                            "OutputValue": o.get("OutputValue", ""),
                        }
                        for o in raw.get("Outputs", [])
                    ],
                    parameters=[
                        {
                            "ParameterKey": p.get("ParameterKey", ""),
                            "ParameterValue": (
                                "***REDACTED***"
                                if p.get("ParameterKey", "").upper()
                                in ("PASSWORD", "SECRET", "TOKEN", "APIKEY")
                                else p.get("ParameterValue", "")
                            ),
                        }
                        for p in raw.get("Parameters", [])
                    ],
                    tags={
                        t["Key"]: t["Value"]
                        for t in raw.get("Tags", [])
                    },
                )

                self._graph.add_node(
                    stack_arn,
                    NodeType.CLOUDFORMATION_STACK,
                    data=stack.model_dump(),
                    label=stack_name,
                )
                count += 1

        return count

    # ------------------------------------------------------------------
    # Public EBS Snapshots
    # ------------------------------------------------------------------
    async def _collect_public_ebs_snapshots(
        self, account_id: str, region: str,
    ) -> int:
        """Discover publicly exposed EBS snapshots for the target account.

        This queries the global public snapshot index using:
          ec2:DescribeSnapshots --restorable-by-user-ids all --owner-ids <account_id>

        Key properties:
          - Any AWS account can query this — no target credentials needed
            (but we do it from the assessment account for convenience).
          - This call logs in the CALLER's CloudTrail, not the victim's.
          - Public snapshots can be cloned into any account for full data access.
          - Finding any public snapshots is an immediate high-severity finding.
        """
        count = 0
        async with self._session.client("ec2", region_name=region) as ec2:
            resp = await safe_api_call(
                ec2.describe_snapshots(
                    Filters=[
                        {"Name": "status", "Values": ["completed"]},
                    ],
                    OwnerIds=[account_id],
                    RestorableByUserIds=["all"],
                ),
                default={"Snapshots": []},
            )
            self._record(
                "ec2:DescribeSnapshots",
                detection_cost=get_detection_score("ec2:DescribeSnapshots"),
            )

            for raw in (resp or {}).get("Snapshots", []):
                snapshot_id = raw["SnapshotId"]
                snap_arn = (
                    f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot_id}"
                )

                snapshot = EBSSnapshot(
                    snapshot_id=snapshot_id,
                    arn=snap_arn,
                    region=region,
                    owner_id=raw.get("OwnerId", account_id),
                    volume_id=raw.get("VolumeId"),
                    volume_size_gb=raw.get("VolumeSize", 0),
                    description=raw.get("Description", ""),
                    encrypted=raw.get("Encrypted", False),
                    kms_key_id=raw.get("KmsKeyId"),
                    state=raw.get("State", "completed"),
                    start_time=(
                        str(raw["StartTime"])
                        if raw.get("StartTime")
                        else None
                    ),
                    is_public=True,  # by definition — we filtered for public
                    tags={
                        t["Key"]: t["Value"]
                        for t in raw.get("Tags", [])
                    },
                )

                self._graph.add_node(
                    snap_arn,
                    NodeType.EBS_SNAPSHOT,
                    data=snapshot.model_dump(),
                    label=snapshot_id,
                )
                count += 1

                logger.info(
                    "public_ebs_snapshot_found",
                    snapshot_id=snapshot_id,
                    volume_size_gb=snapshot.volume_size_gb,
                    encrypted=snapshot.encrypted,
                    description=snapshot.description[:80] if snapshot.description else "",
                )

        if count > 0:
            logger.warning(
                "public_ebs_snapshots_exposed",
                account_id=account_id,
                region=region,
                count=count,
                severity="HIGH",
            )

        return count

    # ------------------------------------------------------------------
    # CodeBuild (CloudGoat codebuild_secrets)
    # ------------------------------------------------------------------
    async def _collect_codebuild(self, account_id: str, region: str) -> int:
        """Collect CodeBuild projects with env vars (credential theft vector)."""
        count = 0
        async with self._session.client("codebuild", region_name=region) as cb:
            raw_names = await async_paginate(cb, "list_projects", "projects")
            names = [n for n in raw_names if isinstance(n, str)]
            self._record(
                "codebuild:ListProjects",
                detection_cost=get_detection_score("codebuild:ListProjects"),
            )
            if not names:
                return 0

            batch = await safe_api_call(
                cb.batch_get_projects(names=names[:25]),
                default={"projects": []},
            )
            self._record(
                "codebuild:BatchGetProjects",
                detection_cost=get_detection_score("codebuild:BatchGetProjects"),
            )
            for raw in (batch or {}).get("projects", []):
                proj_name = raw.get("name", "")
                proj_arn = raw.get("arn", f"arn:aws:codebuild:{region}:{account_id}:project/{proj_name}")
                env = raw.get("environment", {})
                env_vars = {o["name"]: o.get("value", "") for o in env.get("environmentVariables", [])}
                cred_keys = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ACCESS_KEY", "SECRET_KEY"}
                has_cred = any(k.upper() in cred_keys for k in env_vars)
                safe_env = {
                    k: "***REDACTED***" if any(s in k.upper() for s in ("SECRET", "PASSWORD", "TOKEN", "KEY"))
                    else v for k, v in env_vars.items()
                }
                project = CodeBuildProject(
                    project_name=proj_name,
                    arn=proj_arn,
                    region=region,
                    service_role_arn=raw.get("serviceRole"),
                    environment_variables=safe_env,
                    has_credential_like_env=has_cred,
                )
                self._graph.add_node(
                    proj_arn, NodeType.CODEBUILD_PROJECT,
                    data=project.model_dump(), label=proj_name,
                )
                count += 1
        return count

    # ------------------------------------------------------------------
    # Elastic Beanstalk (CloudGoat beanstalk_secrets)
    # ------------------------------------------------------------------
    async def _collect_elasticbeanstalk(self, account_id: str, region: str) -> int:
        """Collect Elastic Beanstalk environments with option settings (credential theft vector)."""
        count = 0
        async with self._session.client("elasticbeanstalk", region_name=region) as eb:
            envs = await safe_api_call(eb.describe_environments(), default={"Environments": []})
            self._record(
                "elasticbeanstalk:DescribeEnvironments",
                detection_cost=get_detection_score("elasticbeanstalk:DescribeEnvironments"),
            )
            for env in (envs or {}).get("Environments", []):
                env_name = env.get("EnvironmentName", "")
                env_id = env.get("EnvironmentId", "")
                app_name = env.get("ApplicationName", "")
                env_arn = f"arn:aws:elasticbeanstalk:{region}:{account_id}:environment/{app_name}/{env_name}"
                cfg = await safe_api_call(
                    eb.describe_configuration_settings(
                        ApplicationName=app_name,
                        EnvironmentName=env_name,
                    ),
                    default={"ConfigurationSettings": []},
                )
                self._record(
                    "elasticbeanstalk:DescribeConfigurationSettings",
                    target_arn=env_arn,
                    detection_cost=get_detection_score("elasticbeanstalk:DescribeConfigurationSettings"),
                )
                opts: dict[str, str] = {}
                for cs in (cfg or {}).get("ConfigurationSettings", []):
                    for opt in cs.get("OptionSettings", []):
                        n, v = opt.get("OptionName", ""), opt.get("Value", "")
                        if n and v:
                            opts[n] = str(v)
                cred_keys = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "RDS_PASSWORD", "DB_PASSWORD"}
                has_cred = any(k.upper() in cred_keys for k in opts)
                eb_env = ElasticBeanstalkEnvironment(
                    environment_name=env_name,
                    environment_id=env_id,
                    arn=env_arn,
                    region=region,
                    application_name=app_name,
                    option_settings=opts,
                    has_credential_like_env=has_cred,
                )
                self._graph.add_node(
                    env_arn, NodeType.ELASTICBEANSTALK_ENVIRONMENT,
                    data=eb_env.model_dump(), label=env_name,
                )
                count += 1
        return count

    # ------------------------------------------------------------------
    # Bedrock Agents (CloudGoat bedrock_agent_hijacking)
    # ------------------------------------------------------------------
    async def _collect_bedrock_agents(self, account_id: str, region: str) -> int:
        """Collect Bedrock agents with action group Lambda ARNs."""
        count = 0
        async with self._session.client("bedrock-agent", region_name=region) as agent:
            summaries = await async_paginate(agent, "list_agents", "agentSummaries")
            self._record(
                "bedrock:ListAgents",
                detection_cost=get_detection_score("bedrock:ListAgents"),
            )
            for s in (summaries or []):
                agent_id = s.get("agentId", "")
                agent_name = s.get("agentName", agent_id)
                agent_arn = f"arn:aws:bedrock:{region}:{account_id}:agent/{agent_id}"
                version = s.get("latestAgentVersion", "DRAFT")
                if not version or version == "DRAFT":
                    version = "DRAFT"
                ag_groups = await safe_api_call(
                    agent.list_agent_action_groups(
                        agentId=agent_id,
                        agentVersion=version,
                    ),
                    default={"actionGroupSummaries": []},
                )
                self._record(
                    "bedrock:ListAgentActionGroups",
                    target_arn=agent_arn,
                    detection_cost=get_detection_score("bedrock:ListAgentActionGroups"),
                )
                lambda_arns: list[str] = []
                for ag in (ag_groups or {}).get("actionGroupSummaries", []):
                    ag_id = ag.get("actionGroupId", "")
                    if not ag_id:
                        continue
                    detail = await safe_api_call(
                        agent.get_agent_action_group(
                            agentId=agent_id,
                            agentVersion=version,
                            actionGroupId=ag_id,
                        ),
                        default={},
                    )
                    self._record(
                        "bedrock:GetAgentActionGroup",
                        target_arn=agent_arn,
                        detection_cost=get_detection_score("bedrock:GetAgentActionGroup"),
                    )
                    exec_cfg = (detail or {}).get("actionGroupExecutor", {})
                    lam = exec_cfg.get("lambda")
                    if lam:
                        lambda_arns.append(lam)
                bedrock_agent = BedrockAgent(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    arn=agent_arn,
                    region=region,
                    action_group_lambda_arns=lambda_arns,
                )
                self._graph.add_node(
                    agent_arn, NodeType.BEDROCK_AGENT,
                    data=bedrock_agent.model_dump(), label=agent_name,
                )
                count += 1
        return count
