"""Atlas CLI entrypoint."""

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from atlas.cli.config_loader import build_config
from atlas.cli.commands import run_campaign, run_recon, list_plugins_cmd, list_campaigns_cmd
from atlas.core.safety import get_lab_banner


def main() -> None:
    console = Console()
    if "--no-banner" not in sys.argv:
        console.print(Panel(get_lab_banner(), title="[bold red]LAB USE ONLY[/bold red]", border_style="red"))
    args = sys.argv[1:]
    if "--no-banner" in args:
        args = [a for a in args if a != "--no-banner"]
    if not args or args[0] in ("-h", "--help"):
        _print_help(console)
        sys.exit(0)
    cmd = args[0].lower()
    try:
        if cmd == "run":
            campaign_path = _find_campaign_arg(args)
            dry_run = "--dry-run" in args
            output_dir = _opt_value(args, "--output-dir")
            config_path = _opt_value(args, "--config")
            config = build_config(Path(config_path) if config_path else None)
            run_campaign(console, config, campaign_path, output_dir=output_dir, dry_run=dry_run)
        elif cmd == "recon":
            paths = [p for p in args[1:] if not p.startswith("-")]
            config_path = _opt_value(args, "--config")
            config = build_config(Path(config_path) if config_path else None)
            run_recon(console, config, [Path(p) for p in paths] if paths else [Path(".")])
        elif cmd == "list-plugins":
            list_plugins_cmd(console)
        elif cmd == "list-campaigns":
            campaign_dir = _opt_value(args, "--campaigns-dir") or "campaigns"
            list_campaigns_cmd(console, Path(campaign_dir))
        else:
            _print_help(console)
            sys.exit(1)
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def _print_help(console: Console) -> None:
    console.print("""
[bold]Atlas[/bold] - AWS Cloud Adversary Emulation (lab only)

Usage:
  atlas run [CONFIG_PATH] CAMPAIGN_PATH [--dry-run] [--output-dir DIR]
  atlas recon [PATH ...] [--config CONFIG_PATH]
  atlas list-plugins
  atlas list-campaigns [--campaigns-dir DIR]

Options:
  --dry-run       Do not execute techniques, only plan
  --output-dir     Write timeline and report to DIR/<run_id>/
  --config        Config file path (recon)
  --no-banner     Suppress lab-only banner

Environment:
  ATLAS_AWS_PROFILE, ATLAS_AWS_REGION, ATLAS_DRY_RUN,
  ATLAS_ALLOWED_ACCOUNT_IDS (comma), ATLAS_ALLOWED_REGIONS (comma)
""")


def _find_campaign_arg(args: list[str]) -> Path | None:
    for a in args[1:]:
        if not a.startswith("-") and (a.endswith(".yaml") or a.endswith(".yml")):
            return Path(a)
    return None


def _opt_value(args: list[str], opt: str) -> str | None:
    for i, a in enumerate(args):
        if a == opt and i + 1 < len(args):
            return args[i + 1]
    return None
