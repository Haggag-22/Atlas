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
        "can_modify_trust": "Trust Policy Modification",
        "can_update_lambda": "Lambda Code Injection",
        "can_read_s3": "S3 Read Access",
        "can_write_s3": "S3 Write Access",
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
