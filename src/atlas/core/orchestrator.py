"""Campaign orchestrator: runs ordered techniques, maintains state, outputs timeline and report."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from atlas.core.config import AtlasConfig, CampaignDefinition, TechniqueStepConfig
from atlas.core.plugin import TechniquePlugin, TechniqueResult
from atlas.core.state import CampaignState, DiscoveredAccount, DiscoveredResource, DiscoveredRole, Finding
from atlas.core.safety import check_account_allowed, check_region_allowed, get_lab_banner
from atlas.plugins.registry import get_plugin
from atlas.telemetry.recorder import get_recorder


class CampaignOrchestrator:
    """Runs a campaign definition against current AWS context and state."""

    def __init__(self, config: AtlasConfig) -> None:
        self.config = config
        self.state = CampaignState()
        self._run_id = str(uuid.uuid4())[:8]
        self._step_results: list[dict[str, Any]] = []

    def load_campaign(self, path: Path) -> CampaignDefinition:
        import yaml
        raw = path.read_text()
        data = yaml.safe_load(raw)
        return CampaignDefinition.model_validate(data)

    def merge_state_from_recon(self, recon_findings: list[dict[str, Any]]) -> None:
        """Feed recon findings into campaign state."""
        self.state.recon_findings = recon_findings

    def run(
        self,
        campaign_path: Path,
        *,
        output_dir: Path | None = None,
        dry_run: bool | None = None,
    ) -> dict[str, Any]:
        """Execute campaign and return summary plus paths to outputs."""
        campaign = self.load_campaign(campaign_path)
        self.state.campaign_id = campaign.id
        self.state.run_id = self._run_id
        dry = dry_run if dry_run is not None else self.config.safety.dry_run

        recorder = get_recorder()
        recorder.clear()
        if self.config.telemetry.output_path:
            recorder.set_output_path(self.config.telemetry.output_path)
        recorder.record(
            actor="orchestrator",
            aws_api="campaign.start",
            result="success",
            extra={"campaign_id": campaign.id, "run_id": self._run_id, "dry_run": dry},
        )

        self._step_results = []
        for i, step in enumerate(campaign.steps):
            plugin = get_plugin(step.technique_id)
            if not plugin:
                self._step_results.append({
                    "step_index": i,
                    "technique_id": step.technique_id,
                    "success": False,
                    "error": f"Unknown technique: {step.technique_id}",
                })
                continue
            if dry:
                self._step_results.append({
                    "step_index": i,
                    "technique_id": step.technique_id,
                    "success": True,
                    "skipped": True,
                    "reason": "dry_run",
                })
                continue
            result = self._run_step(plugin, step, i)
            self._step_results.append({
                "step_index": i,
                "technique_id": step.technique_id,
                "success": result.success,
                "message": result.message,
                "error": result.error,
                "outputs_keys": list(result.outputs.keys()),
            })
            self.state.set_step_output(step.technique_id, result.outputs)
            for f in result.findings:
                self.state.add_finding(Finding(**f))
            for r in result.resources:
                if isinstance(r, dict):
                    self.state.resources.append(DiscoveredResource(**r))
                else:
                    self.state.resources.append(r)
            if "accounts" in result.outputs:
                for acc in result.outputs["accounts"]:
                    if isinstance(acc, dict) and "account_id" in acc:
                        self.state.accounts.append(DiscoveredAccount(**acc))
            if "roles" in result.outputs:
                for role in result.outputs["roles"]:
                    if isinstance(role, dict) and "arn" in role:
                        self.state.roles.append(DiscoveredRole(**role))

        recorder.flush_to_file()
        summary = self._build_summary(campaign)
        if output_dir:
            self._write_outputs(output_dir, campaign, summary)
        return summary

    def _run_step(
        self,
        plugin: TechniquePlugin,
        step: TechniqueStepConfig,
        step_index: int,
    ) -> TechniqueResult:
        params = step.parameters or {}
        try:
            return plugin.execute(self.state, params, config=self.config)
        except Exception as e:
            return TechniqueResult(
                success=False,
                message="",
                error=str(e),
                outputs={},
                findings=[],
                resources=[],
            )

    def _build_summary(self, campaign: CampaignDefinition) -> dict[str, Any]:
        return {
            "campaign_id": campaign.id,
            "campaign_name": campaign.name,
            "run_id": self._run_id,
            "finished_at": datetime.utcnow().isoformat() + "Z",
            "steps": self._step_results,
            "accounts_count": len(self.state.accounts),
            "roles_count": len(self.state.roles),
            "resources_count": len(self.state.resources),
            "findings_count": len(self.state.findings),
        }

    def _write_outputs(
        self,
        output_dir: Path,
        campaign: CampaignDefinition,
        summary: dict[str, Any],
    ) -> None:
        output_dir = output_dir / self._run_id
        output_dir.mkdir(parents=True, exist_ok=True)
        timeline_path = output_dir / "timeline.json"
        report_path = output_dir / "report.txt"
        state_path = output_dir / "state.json"

        timeline = get_recorder().get_timeline_dict()
        timeline_data = {
            "campaign_id": campaign.id,
            "run_id": self._run_id,
            "summary": summary,
            "events": timeline,
        }
        timeline_path.write_text(json.dumps(timeline_data, indent=2))

        report_lines = [
            f"Campaign: {campaign.name} ({campaign.id})",
            f"Run ID: {self._run_id}",
            "",
            "=== Summary ===",
            json.dumps(summary, indent=2),
            "",
            "=== Findings ===",
        ]
        for f in self.state.findings:
            report_lines.append(f"- [{f.severity}] {f.title}: {f.description}")
        report_lines.append("")
        report_lines.append("=== Timeline (events) ===")
        for e in timeline:
            report_lines.append(
                f"  {e.get('timestamp')} | {e.get('actor')} | {e.get('aws_api')} | {e.get('result')}"
            )
        report_path.write_text("\n".join(report_lines))

        state_export = {
            "campaign_id": self.state.campaign_id,
            "run_id": self.state.run_id,
            "accounts": [a.model_dump() for a in self.state.accounts],
            "roles": [r.model_dump() for r in self.state.roles],
            "resources": [r.model_dump() for r in self.state.resources],
            "findings": [f.model_dump() for f in self.state.findings],
            "step_outputs": self.state.step_outputs,
        }
        state_path.write_text(json.dumps(state_export, indent=2))
