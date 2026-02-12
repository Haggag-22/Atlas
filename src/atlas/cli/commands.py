"""CLI command implementations."""

from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

if TYPE_CHECKING:
    from atlas.core.config import AtlasConfig

from atlas.core.config import AtlasConfig
from atlas.core.orchestrator import CampaignOrchestrator
from atlas.plugins.registry import list_plugins
from atlas.plugins.techniques import register_builtin_plugins
from atlas.recon.scanner import ReconScanner
from atlas.telemetry.recorder import get_recorder


def _ensure_plugins() -> None:
    if not list_plugins():
        register_builtin_plugins()


def run_campaign(
    console: Console,
    config: AtlasConfig,
    campaign_path: Path | None,
    *,
    output_dir: str | Path | None = None,
    dry_run: bool = False,
) -> None:
    _ensure_plugins()
    if not campaign_path or not campaign_path.exists():
        console.print("[red]Campaign path required and must exist (e.g. campaigns/discovery.yaml)[/red]")
        raise SystemExit(2)
    if dry_run:
        config.safety.dry_run = True
    output_path = Path(output_dir) if output_dir else Path("output")
    get_recorder().clear()
    orchestrator = CampaignOrchestrator(config)
    console.print(f"[bold]Running campaign:[/bold] {campaign_path}")
    summary = orchestrator.run(campaign_path, output_dir=output_path, dry_run=dry_run)
    console.print("[green]Campaign finished.[/green]")
    console.print(f"  Run ID: {summary.get('run_id')}")
    console.print(f"  Steps: {len(summary.get('steps', []))}")
    console.print(f"  Findings: {summary.get('findings_count', 0)}")
    if output_dir:
        out = output_path / summary.get("run_id", "")
        console.print(f"  Output: {out}/timeline.json, report.txt, state.json")


def run_recon(
    console: Console,
    config: AtlasConfig,
    paths: list[Path],
) -> None:
    scanner = ReconScanner(
        exclude_patterns=config.recon.exclude_patterns,
        max_file_size=config.recon.max_file_size_bytes,
    )
    all_findings: list[object] = []
    for p in paths:
        if not p.exists():
            console.print(f"[yellow]Skip (not found): {p}[/yellow]")
            continue
        findings = scanner.scan_path(p)
        all_findings.extend(findings)
    table = Table(title="Recon findings")
    table.add_column("Type", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Path")
    table.add_column("Line")
    table.add_column("Severity")
    for f in all_findings:
        table.add_row(
            getattr(f, "finding_type", ""),
            getattr(f, "category", ""),
            getattr(f, "path", ""),
            str(getattr(f, "line_number", "")),
            getattr(f, "severity", ""),
        )
    console.print(table)
    console.print(f"Total: {len(all_findings)} findings")
    # Output normalized for campaign input
    if all_findings:
        import json
        out_path = Path("recon_findings.json")
        data = [f.model_dump() for f in all_findings if hasattr(f, "model_dump")]
        out_path.write_text(json.dumps(data, indent=2))
        console.print(f"Normalized findings written to {out_path}")


def list_plugins_cmd(console: Console) -> None:
    _ensure_plugins()
    plugins = list_plugins()
    table = Table(title="Technique plugins")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("MITRE")
    table.add_column("Permissions")
    for pid, p in plugins.items():
        table.add_row(
            pid,
            p.name,
            p.mitre_technique or "-",
            ", ".join(p.required_permissions[:5]) + ("..." if len(p.required_permissions) > 5 else ""),
        )
    console.print(table)


def list_campaigns_cmd(console: Console, campaigns_dir: Path) -> None:
    if not campaigns_dir.exists():
        console.print(f"[yellow]Directory not found: {campaigns_dir}[/yellow]")
        return
    tree = Tree(f"[bold]{campaigns_dir}[/bold]")
    for f in sorted(campaigns_dir.rglob("*.yaml")) + sorted(campaigns_dir.rglob("*.yml")):
        tree.add(str(f))
    console.print(tree)
