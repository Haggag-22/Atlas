"""Campaign state: discovered accounts, roles, resources, credentials, findings."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DiscoveredAccount(BaseModel):
    """Discovered AWS account."""

    account_id: str
    account_alias: str | None = None
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    source: str = ""


class DiscoveredRole(BaseModel):
    """Discovered IAM role."""

    arn: str
    role_name: str
    account_id: str
    trust_policy: dict[str, Any] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class DiscoveredResource(BaseModel):
    """Generic discovered resource (S3, SG, etc.)."""

    resource_type: str
    identifier: str
    arn: str | None = None
    region: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class Finding(BaseModel):
    """Security or misconfiguration finding."""

    finding_type: str
    severity: str = "medium"
    title: str = ""
    description: str = ""
    resource_arn: str | None = None
    resource_type: str | None = None
    region: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    technique_id: str | None = None
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class CampaignState(BaseModel):
    """Mutable state passed between technique steps."""

    campaign_id: str = ""
    run_id: str = ""
    accounts: list[DiscoveredAccount] = Field(default_factory=list)
    roles: list[DiscoveredRole] = Field(default_factory=list)
    resources: list[DiscoveredResource] = Field(default_factory=list)
    credentials_refs: list[dict[str, Any]] = Field(
        default_factory=list,
        description="References to credentials (no raw secrets).",
    )
    permissions_cache: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    step_outputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Outputs from each step keyed by technique_id or step index.",
    )
    recon_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Normalized recon findings fed into campaign.",
    )

    model_config = {"arbitrary_types_allowed": True}

    def get_account_ids(self) -> list[str]:
        return [a.account_id for a in self.accounts]

    def get_role_arns(self) -> list[str]:
        return [r.arn for r in self.roles]

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def set_step_output(self, key: str, value: Any) -> None:
        self.step_outputs[key] = value

    def get_step_output(self, key: str, default: Any = None) -> Any:
        return self.step_outputs.get(key, default)
