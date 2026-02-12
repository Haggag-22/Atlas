"""IAM policy simulation: SimulatePrincipalPolicy (T1069 - Permission Groups)."""

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


class IAMPolicySimulationPlugin(TechniquePlugin):
    """Run IAM policy simulation for a principal against a set of actions."""

    @property
    def id(self) -> str:
        return "iam_policy_simulation"

    @property
    def name(self) -> str:
        return "IAM Policy Simulation"

    @property
    def description(self) -> str:
        return "Simulate IAM policies for a user/role against specified actions (e.g. s3:GetObject, iam:CreateUser)."

    @property
    def mitre_technique(self) -> str:
        return "T1069"

    @property
    def required_permissions(self) -> list[str]:
        return ["iam:SimulatePrincipalPolicy", "sts:GetCallerIdentity"]

    def get_input_schema(self) -> dict[str, Any]:
        return {
            "principal_arn": {"type": "string", "description": "ARN of user or role to simulate"},
            "action_names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Actions to test e.g. s3:GetObject, iam:CreateUser",
                "default": ["s3:GetObject", "s3:ListBucket", "iam:CreateUser", "iam:PassRole", "ec2:RunInstances"],
            },
        }

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
        ok, msg = ensure_safe_account_and_region(config, account_id, config.aws_region)
        if not ok:
            return TechniqueResult(success=False, error=msg)
        principal_arn = parameters.get("principal_arn")
        if not principal_arn:
            return TechniqueResult(success=False, error="principal_arn required")
        action_names = parameters.get("action_names") or [
            "s3:GetObject", "s3:ListBucket", "iam:CreateUser", "iam:PassRole", "ec2:RunInstances"
        ]
        iam = session.client("iam")
        results: list[dict[str, Any]] = []
        try:
            apply_rate_limit(config)
            resp = iam.simulate_principal_policy(
                PolicySourceArn=principal_arn,
                ActionNames=action_names,
            )
            record_telemetry(
                "iam_policy_simulation",
                "iam:SimulatePrincipalPolicy",
                service="iam",
                resource_arn=principal_arn,
            )
            for ev in resp.get("EvaluationResults", []):
                results.append({
                    "action": ev.get("EvalActionName"),
                    "decision": ev.get("EvalDecision"),
                    "matched_statements": ev.get("MatchedStatements", []),
                })
        except ClientError as e:
            record_telemetry("iam_policy_simulation", "iam:SimulatePrincipalPolicy", result="failure", error=str(e))
            return TechniqueResult(success=False, error=str(e), outputs={"evaluations": results})
        allowed = [r for r in results if r.get("decision") == "allowed"]
        return TechniqueResult(
            success=True,
            message=f"Simulated {len(action_names)} actions: {len(allowed)} allowed",
            outputs={
                "principal_arn": principal_arn,
                "evaluations": results,
                "allowed_actions": [r["action"] for r in allowed],
            },
            findings=[],
        )
