"""
atlas.planner.ai_target_selector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
AI-assisted target selection for privilege escalation.

Uses an LLM (OpenAI) to pick the best escalation target from reachable
roles when no explicit target is set. Considers role metadata, findings,
and optional operator goal. Falls back to heuristics if API is unavailable.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import structlog

from atlas.planner.attack_graph import AttackGraph
from atlas.planner.path_finder import PathFinder
from atlas.recon.engine import EnvironmentModel

logger = structlog.get_logger(__name__)


def _arn_short_name(arn: str) -> str:
    """Extract a short display name from an ARN."""
    if ":::" in arn:
        return arn.split(":::")[-1]
    return arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]


class AITargetSelector:
    """Select escalation target using AI when no explicit target is set."""

    def __init__(self) -> None:
        self._api_key = os.environ.get("OPENAI_API_KEY", "")

    @property
    def has_llm(self) -> bool:
        return bool(self._api_key)

    async def select_target(
        self,
        env_model: EnvironmentModel,
        attack_graph: AttackGraph,
        source_identity: str,
        max_depth: int = 6,
    ) -> str | None:
        """Pick the best escalation target from reachable roles.

        Returns the chosen role ARN, or None if AI selection fails
        (caller should fall back to heuristics).
        """
        if not self.has_llm:
            logger.debug("ai_target_selector_no_api_key")
            return None

        path_finder = PathFinder(attack_graph)
        reachable = path_finder.reachable_targets(
            source_identity, max_depth=max_depth,
        )

        # Filter to roles only (exclude users, resources, etc.)
        roles = [
            r for r in reachable
            if ":role/" in r.get("target", "")
        ]
        if not roles:
            logger.debug("ai_target_selector_no_reachable_roles")
            return None

        # Build role metadata for the prompt
        role_summaries: list[dict[str, Any]] = []
        for r in roles:
            arn = r["target"]
            data = env_model.graph.get_node_data(arn)
            role_summaries.append({
                "arn": arn,
                "name": data.get("role_name", _arn_short_name(arn)),
                "hops": r.get("hops", 0),
                "detection_cost": r.get("detection_cost", 0),
                "success_probability": r.get("success_probability", 0),
                "attached_policies": data.get("attached_policy_arns", [])[:5],
                "inline_policies": data.get("inline_policy_names", [])[:3],
                "is_service_linked": data.get("is_service_linked", False),
            })

        findings_summary = self._summarize_findings(env_model)

        try:
            chosen = await self._llm_select(
                source_identity=source_identity,
                roles=role_summaries,
                findings_summary=findings_summary,
            )
            if chosen and self._validate_arn(chosen, roles):
                return chosen
        except Exception as exc:
            logger.debug("ai_target_select_failed", error=str(exc))

        return None

    def _summarize_findings(self, env_model: EnvironmentModel) -> str:
        """Build a short summary of recon findings for context."""
        findings = getattr(env_model, "findings", []) or []
        if not findings:
            return "No notable findings from recon."

        lines: list[str] = []
        for f in findings[:10]:
            sev = getattr(f, "severity", None) or ""
            title = getattr(f, "title", "") or getattr(f, "summary", str(f))[:80]
            lines.append(f"  - [{sev}] {title}")
        return "\n".join(lines) if lines else "No notable findings from recon."

    def _validate_arn(self, arn: str, roles: list[dict[str, Any]]) -> bool:
        """Ensure the LLM's choice is in the reachable set."""
        valid = {r["target"] for r in roles}
        return arn in valid

    async def _llm_select(
        self,
        source_identity: str,
        roles: list[dict[str, Any]],
        findings_summary: str,
    ) -> str | None:
        """Call OpenAI to select the best target."""
        import openai

        client = openai.AsyncOpenAI(api_key=self._api_key)

        system_prompt = (
            "You are an expert AWS red team operator. Given recon data (findings, "
            "reachable roles with metadata), infer the SINGLE BEST escalation target. "
            "Consider: privilege level (admin > poweruser > limited), detection cost "
            "(lower is stealthier), success probability, and findings (e.g. roles "
            "mentioned in high-severity issues). Choose based on what the recon "
            "reveals—no external goal. Respond with ONLY a JSON object: "
            "{\"target_arn\": \"arn:aws:iam::ACCOUNT:role/ROLE_NAME\"}. "
            "No other text. The target_arn MUST be one of the ARNs from the list."
        )

        role_list = "\n".join(
            f"- {r['arn']} (name={r['name']}, hops={r['hops']}, "
            f"detection_cost={r['detection_cost']:.4f}, success_prob={r['success_probability']:.2f})"
            for r in roles
        )

        user_prompt = "\n".join([
            "Current identity:", source_identity,
            "",
            "Reachable roles:",
            role_list,
            "",
            "Findings from recon:",
            findings_summary,
            "",
            "Which single role should we target? Infer from the data above. Respond with JSON only.",
        ])

        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=200,
        )

        content = (response.choices[0].message.content or "").strip()
        return self._parse_response(content, roles)

    def _parse_response(self, content: str, roles: list[dict[str, Any]]) -> str | None:
        """Extract target_arn from LLM response."""
        # Try JSON first
        try:
            # Handle markdown code blocks
            if "```" in content:
                match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
                if match:
                    content = match.group(1)
            data = json.loads(content)
            arn = data.get("target_arn")
            if isinstance(arn, str) and arn:
                return arn
        except json.JSONDecodeError:
            pass

        # Fallback: look for ARN pattern
        arn_match = re.search(
            r"arn:aws:iam::\d{12}:role/[\w+=,.@-]+",
            content,
        )
        if arn_match:
            return arn_match.group(0)

        return None
