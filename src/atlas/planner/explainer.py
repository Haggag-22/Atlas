"""
atlas.planner.explainer
~~~~~~~~~~~~~~~~~~~~~~~
AI-powered attack path explainer.

Uses an LLM (OpenAI) to generate clear, step-by-step explanations
of how a specific attack path works. Falls back to a structured
template if no API key is configured.

Usage:
    explainer = AttackPathExplainer()
    explanation = await explainer.explain(edge, source_info, target_info)
"""

from __future__ import annotations

import os
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _arn_short_name(arn: str) -> str:
    """Extract a short display name from an ARN (handles S3 ::: format)."""
    if ":::" in arn:
        return arn.split(":::")[-1]
    return arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]


class AttackPathExplainer:
    """Explain how an attack path works in plain language."""

    # Friendly names for edge types
    _ATTACK_NAMES: dict[str, str] = {
        "can_assume": "Role Assumption",
        "can_create_key": "Access Key Creation",
        "can_attach_policy": "Policy Attachment",
        "can_put_policy": "Inline Policy Injection",
        "can_passrole": "PassRole Abuse",
        "can_passrole_agentcore": "AgentCore Role Confusion",
        "can_modify_trust": "Trust Policy Modification",
        "can_update_lambda": "Lambda Code Injection",
        "can_read_s3": "S3 Read Access",
        "can_write_s3": "S3 Write Access",
        "can_read_userdata": "EC2 User Data Disclosure",
        "can_enum_backup": "Backup Service Enumeration",
        "can_decode_key": "Access Key Account Decode",
        "can_loot_snapshot": "Public EBS Snapshot Loot",
        "can_stop_cloudtrail": "CloudTrail Stop Logging Evasion",
        "can_delete_cloudtrail": "CloudTrail Delete Trail Evasion",
        "can_update_cloudtrail_config": "CloudTrail Config Update Evasion",
        "can_modify_cloudtrail_bucket_lifecycle": "CloudTrail Bucket Lifecycle Evasion",
        "can_modify_cloudtrail_event_selectors": "CloudTrail Event Selectors Evasion",
        "can_create_admin_user": "Create Admin User",
        "can_create_backdoor_role": "Create Backdoor Role",
        "can_backdoor_lambda": "Lambda Resource Policy Backdoor",
        "can_get_ec2_password_data": "EC2 Get Password Data",
        "can_ec2_instance_connect": "EC2 Instance Connect",
        "can_ec2_serial_console_ssh": "EC2 Serial Console SSH",
        "can_open_security_group_ingress": "Open Security Group Port 22",
        "can_share_ami": "Share AMI",
        "can_share_ebs_snapshot": "Share EBS Snapshot",
        "can_share_rds_snapshot": "Share RDS Snapshot",
        "can_invoke_bedrock_model": "Bedrock InvokeModel",
        "can_delete_dns_logs": "Delete DNS Query Logs",
        "can_leave_organization": "Leave Organization",
        "can_remove_vpc_flow_logs": "Remove VPC Flow Logs",
        "can_enumerate_ses": "Enumerate SES",
        "can_modify_sagemaker_lifecycle": "SageMaker Lifecycle Config",
        "can_create_eks_access_entry": "EKS Create Access Entry",
        "can_get_federation_token": "GetFederationToken Persistence",
        "can_create_codebuild_github_runner": "CodeBuild GitHub Runner Persistence",
        "can_create_rogue_oidc_persistence": "Rogue OIDC IdP Persistence",
        "can_create_roles_anywhere_persistence": "IAM Roles Anywhere Persistence",
        "can_modify_s3_acl_persistence": "S3 ACL Persistence",
        "can_read_codebuild_env": "CodeBuild Env Credential Theft",
        "can_read_beanstalk_env": "Beanstalk Env Credential Theft",
        "can_hijack_bedrock_agent": "Bedrock Agent Hijacking",
    }

    def __init__(self) -> None:
        self._api_key = os.environ.get("OPENAI_API_KEY", "")

    @property
    def has_llm(self) -> bool:
        return bool(self._api_key)

    async def explain(
        self,
        edge: Any,
        source_info: dict[str, Any],
        target_info: dict[str, Any],
        source_policies: list[str],
        target_policies: list[str],
    ) -> str:
        """Generate a human-readable explanation of the attack path.

        If OPENAI_API_KEY is set, uses GPT. Otherwise falls back to a
        structured template.
        """
        context = self._build_context(
            edge, source_info, target_info,
            source_policies, target_policies,
        )

        if self.has_llm:
            try:
                return await self._llm_explain(context)
            except Exception as exc:
                logger.debug("llm_explain_failed", error=str(exc))
                # Fall through to template

        return self._template_explain(context)

    def _build_context(
        self,
        edge: Any,
        source_info: dict[str, Any],
        target_info: dict[str, Any],
        source_policies: list[str],
        target_policies: list[str],
    ) -> dict[str, Any]:
        """Build a structured context dict for the explanation."""
        edge_type = edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type)
        noise_val = edge.noise_level.value if hasattr(edge.noise_level, "value") else str(edge.noise_level)

        return {
            "attack_type": self._ATTACK_NAMES.get(edge_type, edge_type),
            "edge_type": edge_type,
            "source_arn": edge.source_arn,
            "source_name": _arn_short_name(edge.source_arn),
            "source_type": source_info.get("type", "unknown"),
            "source_policies": source_policies,
            "target_arn": edge.target_arn,
            "target_name": _arn_short_name(edge.target_arn),
            "target_type": target_info.get("type", "unknown"),
            "target_policies": target_policies,
            "trust_policy": target_info.get("trust_policy", {}),
            "detection_cost": edge.detection_cost,
            "noise_level": noise_val,
            "success_probability": edge.success_probability,
            "guardrail_status": edge.guardrail_status,
            "api_actions": edge.api_actions,
            "conditions": edge.conditions,
            "notes": edge.notes,
        }

    async def _llm_explain(self, context: dict[str, Any]) -> str:
        """Use OpenAI to generate an explanation."""
        import openai

        client = openai.AsyncOpenAI(api_key=self._api_key)

        system_prompt = (
            "You are an expert AWS cloud security analyst explaining attack paths "
            "to a red team operator. Be precise, technical, and practical. "
            "Use numbered steps. Mention specific AWS API calls. "
            "Explain what permissions make this possible and what detection "
            "mechanisms might catch it. Keep the explanation under 300 words."
        )

        user_prompt = self._format_prompt(context)

        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=600,
        )

        return response.choices[0].message.content or "No explanation generated."

    def _format_prompt(self, ctx: dict[str, Any]) -> str:
        """Format the prompt for the LLM."""
        lines = [
            f"Explain this AWS attack path in detail:",
            f"",
            f"Attack Type: {ctx['attack_type']}",
            f"Source: {ctx['source_name']} ({ctx['source_type']})",
            f"Target: {ctx['target_name']} ({ctx['target_type']})",
            f"API Actions: {', '.join(ctx['api_actions'])}",
            f"Detection Cost: {ctx['detection_cost']:.4f}",
            f"Noise Level: {ctx['noise_level']}",
            f"Success Probability: {ctx['success_probability']:.0%}",
            f"Guardrail Status: {ctx['guardrail_status']}",
        ]

        if ctx["source_policies"]:
            lines.append(f"Source Policies: {', '.join(ctx['source_policies'])}")
        if ctx["target_policies"]:
            lines.append(f"Target Policies: {', '.join(ctx['target_policies'])}")

        if ctx["trust_policy"]:
            import json
            lines.append(f"Trust Policy: {json.dumps(ctx['trust_policy'], default=str)[:500]}")

        if ctx["conditions"]:
            lines.append(f"Conditions: {ctx['conditions']}")

        if ctx["notes"]:
            lines.append(f"Notes: {ctx['notes']}")

        lines.extend([
            "",
            "Explain:",
            "1. What makes this attack path possible (permissions, trust, misconfigurations)",
            "2. Step-by-step how the attacker would execute it",
            "3. What AWS API calls are made and what they do",
            "4. Detection risk and what might catch this",
            "5. Impact if successful",
        ])

        return "\n".join(lines)

    def _template_explain(self, ctx: dict[str, Any]) -> str:
        """Generate a structured explanation without an LLM."""
        edge_type = ctx["edge_type"]

        # Attack-specific explanation templates
        explanations: dict[str, str] = {
            "can_assume": (
                "ROLE ASSUMPTION ATTACK\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can assume the role {target} using\n"
                "  the sts:AssumeRole API. This is possible because:\n"
                "    - The role's trust policy allows assumption from this identity\n"
                "    - The attacker has the sts:AssumeRole permission\n"
                "\n"
                "Execution:\n"
                "  1. Call sts:AssumeRole with the target role ARN\n"
                "  2. Receive temporary credentials (access key, secret key, session token)\n"
                "  3. Use those credentials to operate as the target role\n"
                "\n"
                "Detection:\n"
                "  - CloudTrail logs the AssumeRole call under the caller's identity\n"
                "  - GuardDuty may flag unusual cross-account or cross-region assumptions\n"
                "  - The assumed session appears as a separate identity in subsequent logs\n"
                "\n"
                "Impact:\n"
                "  The attacker gains all permissions attached to {target}.\n"
                "  This is often the quietest privilege escalation path."
            ),
            "can_create_key": (
                "ACCESS KEY CREATION ATTACK\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can create new access keys for {target}\n"
                "  using iam:CreateAccessKey. This gives persistent credentials\n"
                "  for the target identity.\n"
                "\n"
                "Execution:\n"
                "  1. Call iam:CreateAccessKey for the target user\n"
                "  2. Receive a new AccessKeyId and SecretAccessKey\n"
                "  3. Use these credentials to authenticate as the target\n"
                "\n"
                "Detection:\n"
                "  - iam:CreateAccessKey is a HIGH visibility action in CloudTrail\n"
                "  - GuardDuty may flag unusual access key creation\n"
                "  - Security tools often alert on new access keys\n"
                "\n"
                "Impact:\n"
                "  Persistent credentials for {target}. Unlike role assumption,\n"
                "  these keys don't expire until rotated or deleted."
            ),
            "can_attach_policy": (
                "POLICY ATTACHMENT ATTACK\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can attach an IAM managed policy to\n"
                "  {target} using iam:AttachUserPolicy or iam:AttachRolePolicy.\n"
                "  This can grant arbitrary permissions to the target.\n"
                "\n"
                "Execution:\n"
                "  1. Call iam:AttachUserPolicy / iam:AttachRolePolicy\n"
                "  2. Attach a high-privilege policy (e.g. AdministratorAccess)\n"
                "  3. The target identity now has those permissions\n"
                "\n"
                "Detection:\n"
                "  - Policy attachment is a HIGH visibility CloudTrail event\n"
                "  - GuardDuty and AWS Config can detect unexpected policy changes\n"
                "  - Security Hub may flag overly permissive policies\n"
                "\n"
                "Impact:\n"
                "  Privilege escalation for {target}. The attacker can grant\n"
                "  any level of access including full admin."
            ),
            "can_put_policy": (
                "INLINE POLICY INJECTION ATTACK\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can inject an inline policy into\n"
                "  {target} using iam:PutUserPolicy or iam:PutRolePolicy.\n"
                "  Inline policies are embedded directly in the identity.\n"
                "\n"
                "Execution:\n"
                "  1. Call iam:PutUserPolicy / iam:PutRolePolicy\n"
                "  2. Inject a custom policy document with desired permissions\n"
                "  3. The target identity now has additional permissions\n"
                "\n"
                "Detection:\n"
                "  - Inline policy creation is HIGH visibility in CloudTrail\n"
                "  - Harder to audit than managed policies (no central view)\n"
                "  - Config rules may detect inline policy changes\n"
                "\n"
                "Impact:\n"
                "  Custom, targeted privilege escalation. The attacker can\n"
                "  craft exactly the permissions needed."
            ),
            "can_passrole": (
                "PASSROLE ABUSE ATTACK\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can pass role {target} to an AWS\n"
                "  service using iam:PassRole. This allows a service (like Lambda,\n"
                "  EC2, or ECS) to assume the target role's permissions.\n"
                "\n"
                "Execution:\n"
                "  1. Call iam:PassRole to associate the target role with a service\n"
                "  2. Create or update a service resource (Lambda function, EC2 instance)\n"
                "  3. The service resource executes with the target role's permissions\n"
                "  4. Interact with the service to exercise those permissions\n"
                "\n"
                "Detection:\n"
                "  - PassRole + service creation is HIGH visibility\n"
                "  - Multiple API calls increase detection surface\n"
                "  - GuardDuty may flag unusual Lambda or EC2 activity\n"
                "\n"
                "Impact:\n"
                "  Indirect access to {target}'s permissions via a service.\n"
                "  The attacker controls what code runs under those permissions."
            ),
            "can_passrole_agentcore": (
                "AGENTCORE ROLE CONFUSION ATTACK (CloudGoat)\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can pass role {target} to Bedrock\n"
                "  AgentCore when creating a Code Interpreter. Both the code\n"
                "  interpreter role and agent runtime role trust bedrock-agentcore.\n"
                "  By passing the agent runtime role (instead of interpreter role),\n"
                "  the attacker gains access to Knowledge Base, S3, and foundation\n"
                "  models that the runtime role has permissions for.\n"
                "\n"
                "Execution:\n"
                "  1. Enumerate IAM roles that trust bedrock-agentcore.amazonaws.com\n"
                "  2. Create a Code Interpreter with the agent runtime role\n"
                "     (bedrock-agentcore:CreateCodeInterpreter + iam:PassRole)\n"
                "  3. Start a session (bedrock-agentcore:StartCodeInterpreterSession)\n"
                "  4. Invoke code (bedrock-agentcore:InvokeCodeInterpreter) to run\n"
                "     commands as the role — access S3, Knowledge Base, etc.\n"
                "\n"
                "Detection:\n"
                "  - CreateCodeInterpreter + PassRole is HIGH visibility\n"
                "  - InvokeCodeInterpreter execution is logged in CloudTrail\n"
                "  - Unusual AgentCore usage may trigger GuardDuty\n"
                "\n"
                "Impact:\n"
                "  Indirect code execution with {target}'s permissions.\n"
                "  Access to Bedrock Knowledge Base, S3 buckets, and foundation models."
            ),
            "can_modify_trust": (
                "TRUST POLICY MODIFICATION ATTACK\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can modify the trust policy of role\n"
                "  {target} using iam:UpdateAssumeRolePolicy. This changes who\n"
                "  is allowed to assume the role.\n"
                "\n"
                "Execution:\n"
                "  1. Call iam:UpdateAssumeRolePolicy on the target role\n"
                "  2. Add the attacker's identity as a trusted principal\n"
                "  3. Call sts:AssumeRole to assume the modified role\n"
                "  4. Operate with the target role's full permissions\n"
                "\n"
                "Detection:\n"
                "  - Trust policy modification is CRITICAL visibility\n"
                "  - This is one of the most alarming CloudTrail events\n"
                "  - GuardDuty, Config, and Security Hub all likely flag this\n"
                "\n"
                "Impact:\n"
                "  Full access to {target}'s permissions. The trust policy\n"
                "  modification is persistent until reverted."
            ),
            "can_update_lambda": (
                "LAMBDA CODE INJECTION ATTACK\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can update the code of a Lambda\n"
                "  function that executes as {target}. This lets the attacker\n"
                "  run arbitrary code with the function's role permissions.\n"
                "\n"
                "Execution:\n"
                "  1. Call lambda:UpdateFunctionCode on the target function\n"
                "  2. Upload malicious code that exercises the role's permissions\n"
                "  3. Invoke the function (or wait for it to trigger)\n"
                "  4. The code runs with the Lambda role's full permissions\n"
                "\n"
                "Detection:\n"
                "  - Lambda code updates are HIGH visibility in CloudTrail\n"
                "  - GuardDuty may flag unusual Lambda invocations\n"
                "  - Code change auditing may catch the modification\n"
                "\n"
                "Impact:\n"
                "  Indirect code execution with {target}'s permissions.\n"
                "  Can be used for data exfiltration or lateral movement."
            ),
            "can_read_s3": (
                "S3 BUCKET READ ACCESS\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) has read access to the S3 bucket\n"
                "  {target}. This is possible through IAM permissions (s3:GetObject,\n"
                "  s3:ListBucket) or through the bucket's resource policy.\n"
                "\n"
                "Execution:\n"
                "  1. Call s3:ListBucket to enumerate objects in the bucket\n"
                "  2. Call s3:GetObject to download specific objects\n"
                "  3. Analyze contents for sensitive data, credentials, or configs\n"
                "\n"
                "Detection:\n"
                "  - S3 data events are only logged if specifically enabled in CloudTrail\n"
                "  - If data events are off, these reads are essentially invisible\n"
                "  - GuardDuty S3 protection may flag unusual access patterns\n"
                "\n"
                "Impact:\n"
                "  Access to all readable objects in {target}.\n"
                "  Buckets may contain secrets, backups, config files, or PII."
            ),
            "can_write_s3": (
                "S3 BUCKET WRITE ACCESS\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) has write access to the S3 bucket\n"
                "  {target}. This is possible through IAM permissions (s3:PutObject,\n"
                "  s3:DeleteObject, s3:PutBucketPolicy) or the bucket's resource policy.\n"
                "\n"
                "Execution:\n"
                "  1. Call s3:PutObject to upload files (backdoors, web shells)\n"
                "  2. Call s3:PutBucketPolicy to modify access controls\n"
                "  3. Call s3:DeleteObject to destroy data or cover tracks\n"
                "\n"
                "Detection:\n"
                "  - s3:PutBucketPolicy is a management event (always logged)\n"
                "  - s3:PutObject/DeleteObject are data events (may not be logged)\n"
                "  - GuardDuty may flag policy changes granting anonymous access\n"
                "\n"
                "Impact:\n"
                "  Full write control over {target}. Can modify hosted content,\n"
                "  plant backdoors, or destroy data."
            ),
            "can_read_userdata": (
                "EC2 USER DATA DISCLOSURE\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can retrieve user data from EC2\n"
                "  instance {target} using ec2:DescribeInstanceAttribute.\n"
                "  User data is commonly used during instance initialization to\n"
                "  install software, configure services, and bootstrap applications.\n"
                "  It is base64 encoded but NOT encrypted, and frequently contains\n"
                "  hardcoded credentials, API keys, database passwords, internal\n"
                "  service URLs, and bootstrap configuration written at launch time.\n"
                "\n"
                "Execution (API-based):\n"
                "  1. Call ec2:DescribeInstanceAttribute with attribute=userData\n"
                "  2. Base64-decode the returned user data value\n"
                "  3. Analyze contents for credentials, secrets, and environment info\n"
                "\n"
                "Execution (IMDS-based, if attacker has shell on instance):\n"
                "  1. curl http://169.254.169.254/latest/user-data/  (IMDSv1)\n"
                "  2. Or: request a token first, then query with token  (IMDSv2)\n"
                "  3. No IAM permissions required — only local access needed\n"
                "\n"
                "Detection:\n"
                "  - ec2:DescribeInstanceAttribute is a management-read CloudTrail event\n"
                "  - Low detection score — this call is common in monitoring/automation\n"
                "  - IMDS-based access generates NO AWS API events (invisible to CloudTrail)\n"
                "  - GuardDuty does not flag user data reads specifically\n"
                "\n"
                "Impact:\n"
                "  User data from {target} may reveal database passwords, API keys,\n"
                "  internal service endpoints, bootstrap IAM logic, or hardcoded tokens.\n"
                "  This information enables follow-on attacks: lateral movement,\n"
                "  privilege escalation, or direct data access. User data scripts\n"
                "  are typically written once at launch time and forgotten, making\n"
                "  them a rich source of legacy credentials."
            ),
            "can_enum_backup": (
                "AWS BACKUP SERVICE ENUMERATION (Living-off-the-Cloud)\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can enumerate the AWS Backup service\n"
                "  to discover critical production resources in {target} without\n"
                "  using traditional, heavily-monitored service-level enumeration\n"
                "  commands like ec2:DescribeInstances or rds:DescribeDBInstances.\n"
                "\n"
                "  AWS Backup acts as a curated index of what actually matters —\n"
                "  if something is backed up, it is valuable.  This technique\n"
                "  produces high intelligence value with minimal detection risk.\n"
                "\n"
                "Execution:\n"
                "  1. Call backup:ListProtectedResources — reveals all backed-up\n"
                "     resources with ARNs, types, names, and last backup timestamps\n"
                "  2. Call backup:ListBackupPlans — discover plan names (often leak\n"
                "     environment boundaries like 'prod-backups', 'critical-data')\n"
                "  3. Call backup:GetBackupPlan — reveals cron schedules, retention\n"
                "     policies, and backup timing (attack-planning intelligence)\n"
                "  4. Call backup:ListBackupSelections + GetBackupSelection —\n"
                "     reveals exact resource ARNs targeted for backup, tag-based\n"
                "     selection strategies, and IAM roles used by the Backup service\n"
                "  5. Resources can be discovered even if no backup has run yet\n"
                "\n"
                "Intelligence gathered:\n"
                "  - Critical production assets (confirmed by backup existence)\n"
                "  - Naming and tagging conventions (prod vs production, etc.)\n"
                "  - Operational timing (when backups run, retention windows)\n"
                "  - Service breadth (which AWS services are in active use)\n"
                "  - IAM roles used by Backup (potential assumption targets)\n"
                "\n"
                "Detection:\n"
                "  - All Backup APIs are management-read CloudTrail events (low noise)\n"
                "  - These APIs are rarely monitored by SOCs compared to EC2/RDS/IAM\n"
                "  - Detection requires correlating Backup API calls with non-backup\n"
                "    identities or calls outside backup windows\n"
                "  - GuardDuty does not flag Backup enumeration specifically\n"
                "\n"
                "Impact:\n"
                "  Complete situational awareness of the account's critical assets\n"
                "  and operational patterns.  Enables targeted follow-on attacks\n"
                "  against high-value resources identified through Backup."
            ),
            "can_decode_key": (
                "ACCESS KEY ACCOUNT ID DECODE\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can extract the AWS account ID from\n"
                "  access key {target} without making any API call to the target.\n"
                "\n"
                "  Method 1 — Offline Decoding (SILENT):\n"
                "    The account ID is encoded directly in the access key ID.\n"
                "    Characters 5-12 are base32-encoded big-endian bytes that,\n"
                "    after bit-masking (AND with 0x7FFFFFFFFF80 then right-shift\n"
                "    by 7), yield the 12-digit account ID.  Character 13 encodes\n"
                "    the least-significant bit.\n"
                "\n"
                "    This generates:\n"
                "      - ZERO API calls\n"
                "      - ZERO CloudTrail events in ANY account\n"
                "      - Completely invisible reconnaissance\n"
                "\n"
                "    Works for keys created after March 29, 2019 (5th char >= 'Q').\n"
                "\n"
                "  Method 2 — API Decode (sts:GetAccessKeyInfo):\n"
                "    For old-format keys or validation, the STS API can resolve\n"
                "    the account ID.  This call is logged ONLY in the CALLER's\n"
                "    account — NOT in the target's account.\n"
                "\n"
                "Execution:\n"
                "  1. Obtain access key IDs (via iam:ListAccessKeys, credential\n"
                "     files, environment variables, or code repositories)\n"
                "  2. Extract characters 5-12, base32-decode, apply bit mask\n"
                "     to get the account ID (or call sts:GetAccessKeyInfo)\n"
                "  3. Use the account ID for scope validation, cross-account\n"
                "     mapping, or further enumeration\n"
                "\n"
                "Intelligence gathered:\n"
                "  - AWS account ID associated with each access key\n"
                "  - Whether keys belong to the expected account (scope check)\n"
                "  - Cross-account credential presence (lateral movement potential)\n"
                "  - Key age classification (pre/post March 2019 format change)\n"
                "  - Key type (AKIA=long-lived, ASIA=temporary STS)\n"
                "\n"
                "Detection:\n"
                "  - Offline decoding: UNDETECTABLE (no API calls whatsoever)\n"
                "  - API method: sts:GetAccessKeyInfo logs only in caller's\n"
                "    CloudTrail, making it invisible to the target account\n"
                "  - No GuardDuty finding type for this technique\n"
                "\n"
                "Impact:\n"
                "  Enables silent scope validation and cross-account credential\n"
                "  mapping.  Discovered account IDs feed into further recon,\n"
                "  trust relationship analysis, and lateral movement planning."
            ),
            "can_loot_snapshot": (
                "PUBLIC EBS SNAPSHOT LOOTING\n"
                "\n"
                "How it works:\n"
                "  The attacker ({source}) can discover and exfiltrate data from\n"
                "  publicly exposed EBS snapshot {target}.\n"
                "\n"
                "  EBS snapshots have two visibility settings: Private and Public.\n"
                "  Unlike most AWS resources, public EBS snapshots have NO resource-\n"
                "  based policies — if they are public, ANYONE with an AWS account\n"
                "  can discover and clone them.\n"
                "\n"
                "  The global public snapshot index is queryable via:\n"
                "    ec2:DescribeSnapshots --restorable-by-user-ids all\n"
                "                          --owner-ids <account_id>\n"
                "\n"
                "  This call logs ONLY in the caller's CloudTrail — the victim\n"
                "  has NO visibility into who is querying their public snapshots.\n"
                "\n"
                "Execution:\n"
                "  1. Determine the target account ID (via key decode, recon, etc.)\n"
                "  2. Call ec2:DescribeSnapshots with restorable-by-user-ids=all\n"
                "     and owner-ids=<target_account> to list all public snapshots\n"
                "  3. For each discovered snapshot:\n"
                "     a. ec2:CreateVolume from the snapshot in the attacker's account\n"
                "     b. ec2:AttachVolume to an attacker-controlled EC2 instance\n"
                "     c. Mount the volume and read the filesystem\n"
                "  4. Extract credentials, source code, databases, config files, keys\n"
                "\n"
                "Commonly exposed data:\n"
                "  - Database credentials and connection strings\n"
                "  - SSH private keys and TLS certificates\n"
                "  - Application source code and configuration\n"
                "  - Environment variables with API tokens\n"
                "  - Cloud service credentials (AWS keys, GCP service accounts)\n"
                "  - Customer data and PII\n"
                "\n"
                "Detection:\n"
                "  - Discovery (DescribeSnapshots): logs ONLY in caller's account\n"
                "  - Cloning (CreateVolume from snapshot): logs ONLY in caller's account\n"
                "  - The victim's ONLY signal is ec2:ModifySnapshotAttribute event\n"
                "    when the snapshot was originally made public\n"
                "  - Prowler check: ec2_ebs_public_snapshot\n"
                "  - Stratus Red Team: aws.exfiltration.ec2-share-ebs-snapshot\n"
                "\n"
                "Impact:\n"
                "  Complete data exfiltration of the snapshot contents with ZERO\n"
                "  detection in the victim's account.  Often contains full filesystem\n"
                "  images of production servers including all stored secrets."
            ),
        }

        template = explanations.get(edge_type, "No detailed explanation available for this attack type.")
        result = template.format(
            source=ctx["source_name"],
            target=ctx["target_name"],
        )

        # Append policy info
        policy_section = []
        if ctx["source_policies"]:
            policy_section.append(f"\nSource Policies ({ctx['source_name']}):")
            for p in ctx["source_policies"]:
                policy_section.append(f"  - {p}")
        if ctx["target_policies"]:
            policy_section.append(f"\nTarget Policies ({ctx['target_name']}):")
            for p in ctx["target_policies"]:
                policy_section.append(f"  - {p}")

        if policy_section:
            result += "\n" + "\n".join(policy_section)

        return result
