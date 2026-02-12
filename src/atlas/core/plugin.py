"""Standard technique plugin interface."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from atlas.core.state import CampaignState


class TechniqueResult(BaseModel):
    """Standard output from a technique execute()."""

    success: bool = True
    message: str = ""
    outputs: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class TechniquePlugin(ABC):
    """Base class for all technique plugins."""

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique technique ID (e.g. identity_discovery)."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of what the technique does."""
        ...

    @property
    def mitre_tactic(self) -> str:
        """MITRE ATT&CK tactic (e.g. T1078)."""
        return ""

    @property
    def mitre_technique(self) -> str:
        """MITRE technique ID (e.g. T1078)."""
        return ""

    @property
    def required_permissions(self) -> list[str]:
        """IAM actions required (e.g. iam:ListUsers)."""
        return []

    @property
    def destructive(self) -> bool:
        """True if the technique modifies or deletes resources."""
        return False

    def get_input_schema(self) -> dict[str, Any]:
        """Expected parameters; used for validation and docs."""
        return {}

    @abstractmethod
    def execute(
        self,
        state: CampaignState,
        parameters: dict[str, Any],
        config: Any = None,
    ) -> TechniqueResult:
        """Run the technique. Must not mutate state directly; return result. config is AtlasConfig."""
        ...

    def rollback(
        self,
        state: CampaignState,
        parameters: dict[str, Any],
        previous_output: TechniqueResult,
        config: Any = None,
    ) -> TechniqueResult:
        """Optional rollback for destructive techniques."""
        return TechniqueResult(
            success=True,
            message="Rollback not implemented",
            outputs={},
        )
