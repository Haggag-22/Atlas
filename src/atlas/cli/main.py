"""
atlas.cli.main
~~~~~~~~~~~~~~
Typer CLI entry point for Atlas.

Commands:
  atlas config      — Set/show AWS profile and default settings
  atlas plan        — Run recon + planning, save to output/<case>/plan/
  atlas simulate    — Simulate attack path from saved case (no AWS calls)
  atlas run         — Execute attack path from saved case (uses AWS)
  atlas cases       — List saved cases
  atlas delete-case — Delete a saved case
  atlas explain     — Explain an attack path from a saved case (no AWS calls)
  atlas inspect     — Inspect detection profiles
  atlas inspect-key — Decode AWS account ID from access key ID (offline)
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

console = Console()
def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version
        typer.echo(f"atlas-redteam {version('atlas-redteam')}")
        raise typer.Exit()


app = typer.Typer(
    name="atlas",
    no_args_is_help=True,
)


@app.callback()
def _app_main(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit.",
        callback=_version_callback, is_eager=True,
    ),
) -> None:
    """Atlas v2 — AWS Cloud Adversary Emulation Platform"""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _load_config(
    config_file: Path | None,
    profile: str | None,
    region: str,
    account_id: str | None,
    dry_run: bool,
    noise_budget: float,
) -> Any:
    """Build AtlasConfig from CLI args + optional YAML file.

    If no --profile is passed, falls back to the profile saved via
    ``atlas config --profile``.
    """
    from atlas.core.config import AtlasConfig, AWSConfig, SafetyConfig, StealthConfig

    config = AtlasConfig()

    if config_file and config_file.exists():
        import yaml
        raw = yaml.safe_load(config_file.read_text())
        config = AtlasConfig(**raw)

    # Apply saved defaults from atlas config
    saved = _load_saved_config()
    if not profile and saved.get("profile"):
        profile = saved["profile"]
    if region == "us-east-1" and saved.get("region"):
        # Only override the default; if user explicitly passed --region, keep it
        region = saved["region"]

    # CLI overrides
    if profile:
        config.aws.profile = profile
    config.aws.region = region
    if account_id:
        config.safety.allowed_account_ids = [account_id]
    config.safety.dry_run = dry_run
    config.stealth.noise_budget = noise_budget
    config.safety.max_noise_budget = noise_budget

    return config


def _setup(verbose: bool = False) -> None:
    from atlas.utils.logging import setup_logging
    setup_logging(level="DEBUG" if verbose else "WARNING")


def _show_banner() -> None:
    from atlas.core.safety import LAB_BANNER
    console.print(Panel(LAB_BANNER, style="bold red"))


def _print_summary(title: str, data: dict[str, Any]) -> None:
    table = Table(title=title, show_header=True)
    table.add_column("", style="cyan")
    table.add_column("", style="white")
    for k, v in data.items():
        if isinstance(v, bool):
            v_str = "[green]Yes[/green]" if v else "[red]No[/red]"
        elif isinstance(v, float):
            v_str = f"{v:.4f}"
        elif isinstance(v, dict):
            v_str = ", ".join(f"{k2}: {v2}" for k2, v2 in v.items()) if v else "None"
        else:
            v_str = str(v) if v is not None else "—"
        table.add_row(str(k), v_str)
    console.print(table)


# ---------------------------------------------------------------------------
# Live Permission Recon table
# ---------------------------------------------------------------------------

# Human-readable labels for each collector / sub-tier
_COLLECTOR_LABELS: dict[str, tuple[str, str]] = {
    "identity":            ("IAM Identity Enumeration",       "iam:ListUsers / iam:ListRoles"),
    "policy":              ("IAM Policy Documents",           "iam:ListPolicies / iam:GetPolicyVersion"),
    "trust":               ("Trust Relationships",            "iam:GetRole / Trust policies"),
    "guardrail":           ("Guardrail / SCP Check",          "organizations:ListPolicies"),
    "logging_config":      ("Logging Configuration",          "cloudtrail / guardduty"),
    "resource":            ("Resource Enumeration",           "s3 / ec2 / lambda / rds ..."),
    "backup":              ("Backup Plan Enumeration",        "backup:ListProtectedResources"),
    # Sub-tiers inside permission_resolver (rendered individually)
    "tier:policy_docs":    ("Policy Document Analysis",       "Tier 1 — parse cached policy JSON"),
    "tier:auth_details":   ("GetAccountAuthorizationDetails", "Tier 2 — single API, all policies"),
    "tier:simulate":       ("SimulatePrincipalPolicy",        "Tier 3 — ask AWS per-action allow/deny"),
    "tier:piecemeal":      ("Piecemeal Policy Assembly",      "Tier 4 — ListAttached* + GetPolicyVersion"),
    "tier:last_accessed":  ("Service Last Accessed",          "Tier 5 — historical usage data"),
    "tier:bruteforce":     ("Brute-Force Enumeration",        "Tier 6 — try ~800 read-only API calls"),
}

# The display order: collectors first, then the sub-tiers within permission_resolver
_COLLECTOR_ORDER = [
    "identity", "policy", "trust", "guardrail",
    "logging_config", "resource", "backup",
]
_TIER_ORDER = [
    "tier:policy_docs", "tier:auth_details", "tier:simulate",
    "tier:piecemeal", "tier:last_accessed", "tier:bruteforce",
]


class _LiveReconTable:
    """Builds a Rich renderable that updates as collectors finish."""

    def __init__(self) -> None:
        self._rows: dict[str, tuple[str, str]] = {}   # id -> (status_markup, detail)
        self._bf_done = 0
        self._bf_total = 0
        self._bf_ok = 0
        self._allowed_perms: list[str] = []  # live list of allowed permissions
        self._finished = False
        self._perm_resolver_started = False  # first tier_progress received

    # Called from the ReconEngine progress callback
    def on_progress(self, collector_id: str, status: str, payload: Any) -> None:
        if status == "bf_progress":
            self._bf_done = payload.get("done", 0)
            self._bf_total = payload.get("total", 0)
            self._bf_ok = payload.get("succeeded", 0)
            last = payload.get("last_allowed")
            if last and last not in self._allowed_perms:
                self._allowed_perms.append(last)
            return

        if status == "tier_progress":
            # Sub-tier update from permission_resolver
            self._perm_resolver_started = True
            tier = payload.get("tier", "")
            tier_status = payload.get("status", "")
            detail = payload.get("detail", "")
            key = f"tier:{tier}"
            if tier_status == "ok":
                self._rows[key] = ("[green]OK[/green]", detail)
            elif tier_status == "denied":
                _, hint = _COLLECTOR_LABELS.get(key, (tier, ""))
                self._rows[key] = ("[red]DENIED[/red]", hint)
            elif tier_status == "skipped":
                self._rows[key] = ("[dim]SKIPPED[/dim]", "")
            elif tier_status == "done":
                self._rows[key] = ("[dim]DONE[/dim]", detail)
            # "running" → not added to _rows yet, so build() shows spinner
            return

        # Regular collector finished
        if status == "ok":
            self._rows[collector_id] = (
                "[green]OK[/green]",
                self._detail_for(collector_id, payload),
            )
        else:
            _, hint = _COLLECTOR_LABELS.get(collector_id, (collector_id, ""))
            self._rows[collector_id] = ("[red]DENIED[/red]", hint)

    def mark_finished(self) -> None:
        self._finished = True

    @staticmethod
    def _detail_for(collector_id: str, stats: dict[str, Any]) -> str:
        if collector_id == "identity":
            return f"{stats.get('users_found', 0)} users, {stats.get('roles_found', 0)} roles"
        if collector_id == "policy":
            return f"{stats.get('policies_found', 0)} policies"
        if collector_id == "trust":
            return f"{stats.get('trust_relationships_found', 0)} trust policies"
        if collector_id == "resource":
            return f"{stats.get('s3_buckets', 0)} S3 buckets"
        return "done"

    def build_discovery_table(self) -> Table:
        """Return the Permission Discovery table."""
        table = Table(
            title="Permission Discovery",
            show_header=True,
            title_style="bold white",
            min_width=78,
        )
        table.add_column("#", style="dim", width=3, justify="right")
        table.add_column("Method", style="cyan", min_width=30)
        table.add_column("Status", justify="center", min_width=10)
        table.add_column("Details", style="dim", min_width=28)

        step = 0

        # ── Regular collectors ──────────────────────────────────────
        for cid in _COLLECTOR_ORDER:
            step += 1
            label, hint = _COLLECTOR_LABELS.get(cid, (cid, ""))
            if cid in self._rows:
                st, detail = self._rows[cid]
                table.add_row(str(step), label, st, detail)
            elif self._is_current_collector(cid):
                table.add_row(str(step), label, "[yellow]⠿[/yellow]", "[dim]running...[/dim]")
            else:
                table.add_row(str(step), label, "[dim]—[/dim]", "")

        # ── Permission resolution sub-tiers ─────────────────────────
        if self._perm_resolver_started or self._all_collectors_done():
            for tid in _TIER_ORDER:
                step += 1
                label, hint = _COLLECTOR_LABELS.get(tid, (tid, ""))

                if tid in self._rows:
                    st, detail = self._rows[tid]
                    table.add_row(str(step), label, st, detail)
                elif tid == "tier:bruteforce" and self._bf_done > 0:
                    # Live brute-force progress bar
                    pct = int(self._bf_done / self._bf_total * 100) if self._bf_total else 0
                    bar_filled = pct // 5
                    bar_empty = 20 - bar_filled
                    bar = f"[green]{'━' * bar_filled}[/green][dim]{'━' * bar_empty}[/dim]"
                    detail = f"{bar} {self._bf_done}/{self._bf_total}  [green]{self._bf_ok} ok[/green]"
                    table.add_row(str(step), label, "[yellow]RUNNING[/yellow]", detail)
                elif self._is_current_tier(tid):
                    table.add_row(str(step), label, "[yellow]⠿[/yellow]", "[dim]running...[/dim]")
                else:
                    table.add_row(str(step), label, "[dim]—[/dim]", "")

        return table

    def build_allowed_table(self) -> Table:
        """Return the live Allowed Permissions table (shown during brute-force)."""
        table = Table(
            title="Allowed Permissions (live)",
            show_header=True,
            title_style="bold green",
            min_width=50,
        )
        table.add_column("Permission", style="cyan", min_width=36)
        table.add_column("Status", justify="center", width=10)

        for action in self._allowed_perms:
            table.add_row(action, "[green]ALLOW[/green]")

        if not self._allowed_perms:
            table.add_row("[dim]waiting for results...[/dim]", "[dim]—[/dim]")

        return table

    def build(self) -> Table:
        """Return the combined renderable for Rich Live.

        During brute-force, returns a Group with both tables.
        Otherwise returns just the discovery table.
        """
        from rich.console import Group as RichGroup

        discovery = self.build_discovery_table()

        # Show the live allowed-perms table when brute-force is running
        bf_running = (
            "tier:bruteforce" not in self._rows
            and self._bf_done > 0
        )
        if bf_running or (self._allowed_perms and not self._finished):
            allowed = self.build_allowed_table()
            return RichGroup(discovery, "", allowed)  # type: ignore[return-value]

        return discovery

    def _all_collectors_done(self) -> bool:
        """All regular collectors have reported."""
        return all(c in self._rows for c in _COLLECTOR_ORDER)

    def _is_current_collector(self, cid: str) -> bool:
        for c in _COLLECTOR_ORDER:
            if c not in self._rows:
                return c == cid
        return False

    def _is_current_tier(self, tid: str) -> bool:
        for t in _TIER_ORDER:
            if t not in self._rows:
                return t == tid
        return False


def _show_permission_recon_final(env_model: Any) -> None:
    """Show the discovered-permissions table after recon completes."""
    pmap = env_model.permission_map
    # Show discovered permissions if we have any profiles with data
    has_perms = any(
        any(e.allowed for e in p.permissions.values())
        for p in pmap._profiles.values()
    )
    if has_perms:
        _show_discovered_permissions(pmap)


def _show_discovered_permissions(pmap: Any) -> None:
    """Show a table of permissions found via brute-force probing."""
    from atlas.core.permission_map import PermissionConfidence

    table = Table(
        title="Discovered Permissions",
        show_header=True,
        title_style="bold white",
    )
    table.add_column("Permission", style="cyan", min_width=30)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Confidence", justify="center", width=12)
    table.add_column("Source", style="dim")

    _conf_style = {
        "confirmed": "[green]CONFIRMED[/green]",
        "inferred": "[yellow]INFERRED[/yellow]",
        "heuristic": "[dim]HEURISTIC[/dim]",
        "unknown": "[dim]UNKNOWN[/dim]",
    }

    # Collect all allowed permissions across all profiles
    allowed: list[tuple[str, str, str]] = []
    for _arn, profile in pmap._profiles.items():
        for action, entry in profile.permissions.items():
            if entry.allowed:
                conf = entry.confidence.value if hasattr(entry.confidence, "value") else str(entry.confidence)
                source = entry.notes or (entry.source.value if hasattr(entry.source, "value") else str(entry.source))
                allowed.append((action, conf, source))

    # Sort: confirmed first, then by service:action
    allowed.sort(key=lambda x: (0 if x[1] == "confirmed" else 1, x[0]))

    # Show allowed (limit to 25 to keep it readable, show summary for rest)
    shown = 0
    for action, conf, source in allowed:
        if shown >= 25:
            break
        status = "[green]ALLOW[/green]"
        conf_display = _conf_style.get(conf, conf)
        # Truncate long source notes
        if len(source) > 40:
            source = source[:37] + "..."
        table.add_row(action, status, conf_display, source)
        shown += 1

    if len(allowed) > 25:
        table.add_row(
            f"[dim]... and {len(allowed) - 25} more[/dim]",
            "", "", "",
        )

    # Count by confidence
    confirmed = sum(1 for _, c, _ in allowed if c == "confirmed")
    inferred = sum(1 for _, c, _ in allowed if c == "inferred")

    console.print(table)
    console.print(
        f"  [bold]{len(allowed)}[/bold] permissions discovered"
        f"  ([green]{confirmed} confirmed[/green]"
        + (f", [yellow]{inferred} inferred[/yellow]" if inferred else "")
        + ")\n"
    )


def _show_findings(findings: list[Any]) -> None:
    """Display security findings in a table."""
    if not findings:
        return

    _sev_color = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }

    table = Table(title=f"Security Findings ({len(findings)})")
    table.add_column("ID", style="bold white", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Title", style="cyan")
    table.add_column("Resource", style="white")
    table.add_column("Description", style="dim")

    for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        x.severity.value if hasattr(x.severity, "value") else x.severity, 5
    )):
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        color = _sev_color.get(sev, "white")
        resource_name = f.resource_arn.split(":::")[-1] if ":::" in f.resource_arn else f.resource_arn.split("/")[-1]
        table.add_row(
            f.finding_id,
            f"[{color}]{sev.upper()}[/{color}]",
            f.title,
            resource_name,
            f.description[:80] + "..." if len(f.description) > 80 else f.description,
        )

    console.print(f"\n")
    console.print(table)


# ---------------------------------------------------------------------------
# Common CLI options
# ---------------------------------------------------------------------------
def _check_plan_staleness(case_name: str, is_execution: bool = False) -> None:
    """Warn if the plan data is stale.

    For simulate: yellow warning after 1h, suggest re-plan after 6h.
    For run: yellow warning after 1h, red warning + block after 6h (needs --force).
    """
    from atlas.core.cases import plan_age

    age = plan_age(case_name)
    if age is None:
        return

    hours = age / 3600
    minutes = age / 60

    if hours < 1:
        # Fresh enough — show age in the header
        if minutes < 1:
            console.print(f"  Plan Age  [green]{int(age)}s ago[/green]")
        else:
            console.print(f"  Plan Age  [green]{int(minutes)}m ago[/green]")
    elif hours < 6:
        console.print(f"  Plan Age  [yellow]{hours:.1f}h ago[/yellow]  [dim](consider re-running plan)[/dim]")
    else:
        console.print(f"  Plan Age  [bold red]{hours:.1f}h ago[/bold red]")
        console.print(f"  [yellow]Plan data may be stale — the AWS account may have changed.[/yellow]")
        console.print(f"  [dim]  Re-run:  atlas plan --case {case_name}[/dim]")
        if is_execution:
            return  # caller handles the --force check


ConfigOption = typer.Option(None, "--config", "-c", help="Path to atlas config YAML")
ProfileOption = typer.Option(None, "--profile", "-p", help="AWS profile name")
RegionOption = typer.Option("us-east-1", "--region", "-r", help="AWS region")
AccountOption = typer.Option(None, "--account", "-a", help="Allowed AWS account ID")
DryRunOption = typer.Option(False, "--dry-run", help="Dry run mode (no mutations)")
NoiseBudgetOption = typer.Option(10.0, "--noise-budget", "-n", help="Max detection cost budget")
VerboseOption = typer.Option(False, "--verbose", "-v", help="Show detailed logs")
TargetOption = typer.Option("", "--target", "-t", help="Target name or ARN for escalation")
AttackPathOption = typer.Option("", "--attack-path", help="Specific attack path by ID (e.g. AP-03)")
ExplainOption = typer.Option(False, "--explain", help="AI explanation of selected attack path")
CaseOption = typer.Option(..., "--case", help="Case name (required) — output at output/<case>/")

_CONFIG_FILE = Path.home() / ".atlas" / "config.json"


def _load_saved_config() -> dict[str, Any]:
    """Load saved Atlas defaults from ~/.atlas/config.json."""
    if _CONFIG_FILE.exists():
        return json.loads(_CONFIG_FILE.read_text())
    return {}


def _save_atlas_config(data: dict[str, Any]) -> None:
    """Save Atlas defaults to ~/.atlas/config.json."""
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(json.dumps(data, indent=2))


# ═══════════════════════════════════════════════════════════════════════════
# atlas config — set/show AWS profile and defaults
# ═══════════════════════════════════════════════════════════════════════════
@app.command()
def config(
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="AWS profile to use (from ~/.aws/credentials)"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Default AWS region"),
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    list_profiles: bool = typer.Option(False, "--list", "-l", help="List available AWS profiles"),
) -> None:
    """Set or show the default AWS profile and region for Atlas."""
    import configparser

    aws_creds_file = Path.home() / ".aws" / "credentials"
    aws_config_file = Path.home() / ".aws" / "config"

    # List available profiles
    if list_profiles:
        profiles = _get_aws_profiles(aws_creds_file, aws_config_file)
        if not profiles:
            console.print("\n[red]No AWS profiles found.[/red]")
            console.print(f"[dim]  Configure credentials at {aws_creds_file}[/dim]")
            return
        table = Table(title=f"AWS Profiles ({len(profiles)})")
        table.add_column("Profile", style="bold cyan")
        table.add_column("Source", style="dim")
        for name, source in profiles:
            table.add_row(name, source)
        console.print(f"\n")
        console.print(table)
        console.print(f"\n[dim]  Set with:  atlas config --profile <name>[/dim]")
        return

    # Show current config
    if show or (not profile and not region):
        saved = _load_saved_config()
        current_profile = saved.get("profile", "default")
        current_region = saved.get("region", "us-east-1")

        console.print(f"\n[bold]Atlas Configuration[/bold]  [dim]({_CONFIG_FILE})[/dim]\n")

        table = Table(show_header=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("AWS Profile", f"[bold]{current_profile}[/bold]")
        table.add_row("Region", current_region)
        console.print(table)

        # Validate the profile by calling STS
        console.print(f"\n[dim]Validating credentials...[/dim]")
        _validate_profile(current_profile, current_region)

        console.print(f"\n[dim]  Change with:  atlas config --profile <name> --region <region>[/dim]")
        console.print(f"[dim]  List profiles: atlas config --list[/dim]")
        return

    # Set profile / region
    saved = _load_saved_config()

    if profile:
        # Validate profile exists
        profiles = _get_aws_profiles(aws_creds_file, aws_config_file)
        profile_names = [p[0] for p in profiles]
        if profile not in profile_names:
            console.print(f"\n[red]Profile '{profile}' not found in AWS credentials.[/red]")
            console.print(f"[dim]  Available: {', '.join(profile_names) if profile_names else 'none'}[/dim]")
            console.print(f"[dim]  Configure at {aws_creds_file}[/dim]")
            raise typer.Exit(1)
        saved["profile"] = profile

    if region:
        saved["region"] = region

    _save_atlas_config(saved)

    console.print(f"\n[green]Configuration saved.[/green]\n")
    table = Table(show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("AWS Profile", f"[bold]{saved.get('profile', 'default')}[/bold]")
    table.add_row("Region", saved.get("region", "us-east-1"))
    console.print(table)

    # Validate
    console.print(f"\n[dim]Validating credentials...[/dim]")
    _validate_profile(saved.get("profile", "default"), saved.get("region", "us-east-1"))


def _get_aws_profiles(
    creds_file: Path,
    config_file: Path,
) -> list[tuple[str, str]]:
    """Parse AWS credentials and config files to list available profiles."""
    import configparser

    profiles: list[tuple[str, str]] = []
    seen: set[str] = set()

    # ~/.aws/credentials
    if creds_file.exists():
        cp = configparser.ConfigParser()
        cp.read(str(creds_file))
        for section in cp.sections():
            if section not in seen:
                profiles.append((section, "credentials"))
                seen.add(section)

    # ~/.aws/config (profiles are prefixed with "profile ")
    if config_file.exists():
        cp = configparser.ConfigParser()
        cp.read(str(config_file))
        for section in cp.sections():
            name = section.replace("profile ", "") if section.startswith("profile ") else section
            if name not in seen:
                profiles.append((name, "config"))
                seen.add(name)

    return sorted(profiles, key=lambda x: x[0])


def _validate_profile(profile: str, region: str) -> None:
    """Validate an AWS profile by calling STS GetCallerIdentity."""
    try:
        from atlas.core.config import AWSConfig
        from atlas.utils.aws import create_sync_session

        config = AWSConfig(
            profile=profile if (profile and profile != "default") else None,
            region=region,
        )
        session = create_sync_session(config)
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        table = Table(show_header=True)
        table.add_column("", style="cyan")
        table.add_column("", style="white")
        table.add_row("Account", identity["Account"])
        table.add_row("Identity", identity["Arn"].split("/")[-1])
        table.add_row("ARN", identity["Arn"])
        console.print(table)
        console.print(f"[green]  Credentials valid.[/green]")
    except Exception as exc:
        console.print(f"[red]  Credential validation failed: {exc}[/red]")
        console.print(f"[dim]  Check your AWS credentials for profile '{profile}'[/dim]")


# ═══════════════════════════════════════════════════════════════════════════
# atlas plan — recon + planning (the entry point)
# ═══════════════════════════════════════════════════════════════════════════
@app.command()
def plan(
    case: str = CaseOption,
    config_file: Optional[Path] = ConfigOption,
    profile: Optional[str] = ProfileOption,
    region: str = RegionOption,
    account: Optional[str] = AccountOption,
    noise_budget: float = NoiseBudgetOption,
    target: str = TargetOption,
    attack_path: str = AttackPathOption,
    explain: bool = ExplainOption,
    verbose: bool = VerboseOption,
) -> None:
    """Run recon + planning. Saves everything to output/<case>/plan/."""
    _setup(verbose)
    _show_banner()

    config = _load_config(config_file, profile, region, account, dry_run=True, noise_budget=noise_budget)
    if target:
        config.operation.target_privilege = target

    async def _run() -> None:
        from rich.status import Status
        from atlas.core.cases import plan_dir, save_plan
        from atlas.core.telemetry import TelemetryRecorder
        from atlas.planner.engine import PlannerEngine
        from atlas.recon.engine import ReconEngine

        recorder = TelemetryRecorder()
        pd = plan_dir(case)

        # Check if this is a replan (case already exists)
        old_paths: dict[str, dict[str, str]] = {}
        old_attack_paths_file = pd / "attack_paths.json"
        is_replan = old_attack_paths_file.exists()
        if is_replan:
            import json as _json
            old_data = _json.loads(old_attack_paths_file.read_text())
            for p in old_data:
                old_paths[p.get("chain", f"{p.get('attack','')}|{p.get('target','')}")] = p
            console.print(f"\n[bold]Case[/bold]  [cyan]{case}[/cyan]  →  output/{case}/plan/  [yellow](replan)[/yellow]")
        else:
            console.print(f"\n[bold]Case[/bold]  [cyan]{case}[/cyan]  →  output/{case}/plan/")

        # Recon — live table
        console.print("\n[bold cyan]═══ PERMISSIONS RECON ═══[/bold cyan]")
        import logging as _logging
        _prev_level = _logging.root.level
        _logging.root.setLevel(_logging.CRITICAL)  # suppress noisy errors

        live_tbl = _LiveReconTable()

        def _recon_progress(collector_id: str, status: str, payload: Any) -> None:
            live_tbl.on_progress(collector_id, status, payload)

        recon_engine = ReconEngine(config, recorder)

        async def _run_recon_with_live() -> Any:
            with Live(live_tbl.build(), console=console, refresh_per_second=4, transient=True) as live:
                import asyncio as _aio

                async def _refresh_loop() -> None:
                    while not live_tbl._finished:
                        live.update(live_tbl.build())
                        await _aio.sleep(0.25)

                refresh_task = _aio.create_task(_refresh_loop())
                try:
                    model = await recon_engine.run(progress_callback=_recon_progress)
                finally:
                    live_tbl.mark_finished()
                    await refresh_task
                    live.update(live_tbl.build())  # final render
                return model

        env_model = await _run_recon_with_live()
        _logging.root.setLevel(_prev_level)

        # Print the final (static) table so it stays on screen
        console.print(live_tbl.build_discovery_table())
        console.print("[green]  Recon complete.[/green]\n")
        _show_permission_recon_final(env_model)
        _print_summary("Environment", env_model.summary())
        _show_findings(env_model.findings)

        # Plan
        console.print("\n[bold yellow]═══ PLANNING ═══[/bold yellow]")
        with Status("[yellow]Building attack graph...[/yellow]", console=console, spinner="dots"):
            planner = PlannerEngine(config, recorder)
            result = planner.plan(env_model)
        console.print("[green]  Planning complete.[/green]")

        # Show all available attack paths
        path_map = _show_attack_paths(result.attack_graph, result.source_identity)

        # Save everything to output/<case>/plan/
        all_edges = result.attack_graph.edges
        save_plan(case, env_model, all_edges, result.source_identity, result.target)
        await recorder.flush_to_file(pd / "telemetry.jsonl")

        # Save attack paths JSON (chains)
        paths_data = []
        for pid, chain in path_map.items():
            noise_val = chain.max_noise_level.value if hasattr(chain.max_noise_level, "value") else str(chain.max_noise_level)
            chain_edges = []
            for e in chain.edges:
                chain_edges.append({
                    "edge_type": e.edge_type.value,
                    "source": e.source_arn,
                    "target": e.target_arn,
                })
            # For backward compat with replan diff, use first edge's attack type
            first_attack = chain.edges[0].edge_type.value if chain.edges else ""
            paths_data.append({
                "id": pid,
                "attack": first_attack,
                "target": chain.final_target_arn,
                "hops": chain.hop_count,
                "chain": chain.summary_text,
                "detection_cost": chain.total_detection_cost,
                "success_probability": chain.total_success_probability,
                "noise_level": noise_val,
                "edges": chain_edges,
            })
        (pd / "attack_paths.json").write_text(json.dumps(paths_data, indent=2, default=str))

        if result.plan:
            (pd / "attack_plan.json").write_text(
                json.dumps(result.plan.model_dump(), indent=2, default=str)
            )

        # Show diff if this is a replan
        if is_replan and old_paths:
            _show_plan_diff(old_paths, paths_data, path_map)

        console.print(f"\n[green]Saved to output/{case}/plan/[/green]")

        # If user selected a specific path, show chain detail
        if attack_path and attack_path.upper() in path_map:
            selected_chain = path_map[attack_path.upper()]
            _show_chain_detail(attack_path.upper(), selected_chain, env_model)

            if explain and selected_chain.hop_count == 1:
                await _explain_attack_path(selected_chain.edges[0], env_model)

        elif attack_path:
            console.print(f"\n[red]Unknown path ID '{attack_path}'. Use an ID from the table above.[/red]")

        # Show auto-selected plan
        if result.plan and not attack_path:
            matched_id = _resolve_path_id(result.plan, path_map)
            if matched_id and matched_id in path_map:
                _render_chain_viz(path_map[matched_id], matched_id)
            _show_plan(result.plan, path_id=matched_id)

        if result.reachable_targets:
            _show_reachable(result.reachable_targets)

        if explain and not attack_path:
            console.print("\n[yellow]Use --explain with --attack-path AP-XX to explain a specific path.[/yellow]")

        console.print(f"\n[dim]  Next:  atlas simulate --case {case} --attack-path AP-XX[/dim]")
        console.print(f"[dim]         atlas run --case {case} --attack-path AP-XX[/dim]")

    asyncio.run(_run())


# ═══════════════════════════════════════════════════════════════════════════
# atlas simulate — simulate from saved case (no AWS calls)
# ═══════════════════════════════════════════════════════════════════════════
@app.command()
def simulate(
    case: str = CaseOption,
    attack_path: str = AttackPathOption,
    verbose: bool = VerboseOption,
) -> None:
    """Simulate execution of an attack path from a saved case — no AWS calls."""
    _setup(verbose)

    from atlas.core.cases import load_case, sim_dir
    from atlas.core.models import AttackEdge

    try:
        case_data = load_case(case)
    except FileNotFoundError:
        console.print(f"\n[red]Case '{case}' not found.[/red]")
        console.print(f"[dim]  Run  atlas plan --case {case}  first.[/dim]")
        raise typer.Exit(1)

    env_model = case_data["env_model"]
    attack_edges: list[AttackEdge] = case_data["attack_edges"]
    source_identity = case_data["source_identity"]
    case_meta = case_data["case_meta"]

    console.print(f"\n[bold]Case[/bold]  [cyan]{case}[/cyan]  →  output/{case}/sim/")
    console.print(f"  Account   {case_meta.get('account_id', '?')}")
    console.print(f"  Identity  {source_identity.split('/')[-1]}")
    _check_plan_staleness(case)

    # Build path map from saved edges
    path_map, sorted_chains = _build_path_map(attack_edges, source_identity)

    if not path_map:
        console.print("\n[red]No attack paths found in this case.[/red]")
        raise typer.Exit(1)

    # Resolve which path to simulate
    if attack_path:
        ap_key = attack_path.upper()
        if ap_key not in path_map:
            _show_attack_paths_from_edges(sorted_chains)
            console.print(f"\n[red]Unknown path ID '{attack_path}'. Use an ID from the table above.[/red]")
            raise typer.Exit(1)
        selected_chain = path_map[ap_key]
        resolved_id = ap_key
    else:
        resolved_id = "AP-01"
        selected_chain = path_map[resolved_id]

    # Build plan from chain
    selected_plan = _chain_to_plan(selected_chain, source_identity)

    # Show visualization + plan + simulation
    _render_chain_viz(selected_chain, resolved_id)
    _show_plan(selected_plan, path_id=resolved_id)
    _simulate_execution(selected_plan)

    # Save simulation output
    sd = sim_dir(case)
    sim_data = {
        "case": case,
        "attack_path": resolved_id,
        "hops": selected_chain.hop_count,
        "chain": selected_chain.summary_text,
        "target": selected_chain.final_target_arn,
        "detection_cost": selected_chain.total_detection_cost,
        "success_probability": selected_chain.total_success_probability,
        "steps": [s.model_dump() for s in selected_plan.steps],
    }
    (sd / "simulation.json").write_text(json.dumps(sim_data, indent=2, default=str))

    console.print(f"\n[green]Saved to output/{case}/sim/[/green]")


# ═══════════════════════════════════════════════════════════════════════════
# atlas run — execute from saved case (uses AWS)
# ═══════════════════════════════════════════════════════════════════════════
@app.command()
def run(
    case: str = CaseOption,
    attack_path: str = AttackPathOption,
    dry_run: bool = DryRunOption,
    force: bool = typer.Option(False, "--force", help="Execute even if plan data is stale (>6h)"),
    config_file: Optional[Path] = ConfigOption,
    profile: Optional[str] = ProfileOption,
    region: str = RegionOption,
    account: Optional[str] = AccountOption,
    verbose: bool = VerboseOption,
) -> None:
    """Execute an attack path from a saved case. Output to output/<case>/run/."""
    _setup(verbose)
    _show_banner()

    from atlas.core.cases import load_case, run_dir
    from atlas.core.models import AttackEdge

    try:
        case_data = load_case(case)
    except FileNotFoundError:
        console.print(f"\n[red]Case '{case}' not found.[/red]")
        console.print(f"[dim]  Run  atlas plan --case {case}  first.[/dim]")
        raise typer.Exit(1)

    env_model = case_data["env_model"]
    attack_edges: list[AttackEdge] = case_data["attack_edges"]
    source_identity = case_data["source_identity"]
    case_meta = case_data["case_meta"]

    console.print(f"\n[bold]Case[/bold]  [cyan]{case}[/cyan]  →  output/{case}/run/")
    console.print(f"  Account   {case_meta.get('account_id', '?')}")
    console.print(f"  Identity  {source_identity.split('/')[-1]}")
    _check_plan_staleness(case, is_execution=True)

    # Block execution on very stale plans unless --force
    from atlas.core.cases import plan_age
    age = plan_age(case)
    if age and age > 6 * 3600 and not force:
        console.print(f"\n[bold red]Execution blocked[/bold red] — plan is {age / 3600:.1f}h old.")
        console.print(f"  The AWS environment may have changed significantly since recon.")
        console.print(f"  [dim]  Re-plan:   atlas plan --case {case}[/dim]")
        console.print(f"  [dim]  Override:  atlas run --case {case} --force[/dim]")
        raise typer.Exit(1)

    # Build path map from saved edges
    path_map, sorted_chains = _build_path_map(attack_edges, source_identity)

    if not path_map:
        console.print("\n[red]No attack paths found in this case.[/red]")
        raise typer.Exit(1)

    # Resolve which path to run
    if attack_path:
        ap_key = attack_path.upper()
        if ap_key not in path_map:
            _show_attack_paths_from_edges(sorted_chains)
            console.print(f"\n[red]Unknown path ID '{attack_path}'. Use an ID from the table above.[/red]")
            raise typer.Exit(1)
        selected_chain = path_map[ap_key]
        resolved_id = ap_key
    else:
        resolved_id = "AP-01"
        selected_chain = path_map[resolved_id]

    # Build plan from chain
    selected_plan = _chain_to_plan(selected_chain, source_identity)
    _render_chain_viz(selected_chain, resolved_id)
    _show_plan(selected_plan, path_id=resolved_id)

    if dry_run:
        console.print("\n[yellow]Dry-run mode — skipping execution.[/yellow]")
        return

    config = _load_config(config_file, profile, region, account, dry_run=False, noise_budget=10.0)

    async def _execute() -> None:
        from rich.status import Status
        from atlas.core.safety import SafetyGate
        from atlas.core.telemetry import TelemetryRecorder
        from atlas.executor.engine import ExecutorEngine
        from atlas.executor.session import SessionManager

        recorder = TelemetryRecorder()
        safety = SafetyGate(config.safety)
        rd = run_dir(case)

        # Execute
        console.print("\n[bold red]═══ EXECUTION ═══[/bold red]")
        session_mgr = SessionManager(config.aws)
        session_mgr.set_initial_identity(env_model.metadata.caller_arn)

        executor = ExecutorEngine(config, safety, recorder, session_mgr)
        with Status("[red]Executing attack plan...[/red]", console=console, spinner="dots"):
            exec_report = await executor.execute(selected_plan)

        console.print("[green]  Execution complete.[/green]")
        _print_summary("Execution Report", exec_report.summary())

        # Save to output/<case>/run/
        (rd / "execution_report.json").write_text(
            json.dumps(exec_report.summary(), indent=2, default=str)
        )
        await recorder.flush_to_file(rd / "telemetry.jsonl")

        # Show credential chain
        chain = session_mgr.credential_chain
        if chain:
            chain_table = Table(title="Credential Chain")
            chain_table.add_column("Step", justify="right", style="bold white")
            chain_table.add_column("Identity", style="cyan")
            chain_table.add_column("Method", style="magenta")
            for i, entry in enumerate(chain):
                chain_table.add_row(str(i + 1), entry["identity"], entry["source"])
            console.print(chain_table)

        console.print(f"\n[green]Saved to output/{case}/run/[/green]")

    asyncio.run(_execute())


# ═══════════════════════════════════════════════════════════════════════════
# atlas cases — list all saved cases
# ═══════════════════════════════════════════════════════════════════════════
@app.command()
def cases() -> None:
    """List all saved cases."""
    from atlas.core.cases import list_cases, plan_age

    all_cases = list_cases()
    if not all_cases:
        console.print("\n[yellow]No saved cases.[/yellow]")
        console.print("[dim]  Run  atlas plan --case <name>  to create one.[/dim]")
        return

    table = Table(title=f"Saved Cases ({len(all_cases)})")
    table.add_column("Name", style="bold cyan", no_wrap=True)
    table.add_column("Account", style="white", no_wrap=True)
    table.add_column("Region", style="white", no_wrap=True)
    table.add_column("Paths", justify="right", style="yellow")
    table.add_column("Findings", justify="right", style="red")
    table.add_column("Plan Age", justify="right", no_wrap=True)
    table.add_column("Sim", justify="center", style="dim")
    table.add_column("Run", justify="center", style="dim")

    for c in all_cases:
        name = c.get("name", "?")
        age = plan_age(name)
        if age is None:
            age_str = "?"
        elif age < 3600:
            age_str = f"[green]{int(age / 60)}m[/green]"
        elif age < 6 * 3600:
            age_str = f"[yellow]{age / 3600:.1f}h[/yellow]"
        else:
            age_str = f"[bold red]{age / 3600:.1f}h[/bold red]"

        table.add_row(
            name,
            c.get("account_id", "?"),
            c.get("region", "?"),
            str(c.get("attack_paths", 0)),
            str(c.get("findings", 0)),
            age_str,
            "[green]Yes[/green]" if c.get("has_sim") else "—",
            "[green]Yes[/green]" if c.get("has_run") else "—",
        )

    console.print(f"\n")
    console.print(table)
    console.print(f"\n[dim]  atlas explain --case <case> --attack-path AP-XX[/dim]")
    console.print(f"[dim]  atlas simulate --case <case> --attack-path AP-XX[/dim]")
    console.print(f"[dim]  atlas run --case <case> --attack-path AP-XX[/dim]")
    console.print(f"[dim]  atlas gui --case <case>[/dim]")
    console.print(f"[dim]  atlas delete-case <case>[/dim]")


# ═══════════════════════════════════════════════════════════════════════════
# atlas delete-case — remove a saved case
# ═══════════════════════════════════════════════════════════════════════════
@app.command("delete-case")
def delete_case_cmd(
    case: str = typer.Argument(..., help="Case name to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a saved case and its output directory."""
    from atlas.core.cases import delete_case, list_cases

    all_names = [c.get("name", "?") for c in list_cases()]
    if case not in all_names:
        console.print(f"\n[red]Case '{case}' not found.[/red]")
        console.print("[dim]  Run  atlas cases  to see available cases.[/dim]")
        raise typer.Exit(1)

    if not force:
        confirm = typer.confirm(f"Delete case '{case}' and output/{case}/?")
        if not confirm:
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(0)

    if delete_case(case):
        console.print(f"[green]Deleted case '{case}'.[/green]")
    else:
        console.print(f"[yellow]Case '{case}' was not found or already removed.[/yellow]")


# ═══════════════════════════════════════════════════════════════════════════
# atlas gui — Streamlit web UI for attack path exploration
# ═══════════════════════════════════════════════════════════════════════════
@app.command()
def gui(
    case: Optional[str] = typer.Option(None, "--case", "-c", help="Case name (pre-selects in dropdown)"),
) -> None:
    """Open the Atlas GUI — view attack paths in a web browser."""
    import subprocess

    gui_path = Path(__file__).resolve().parents[1] / "gui" / "app.py"
    if not gui_path.exists():
        console.print(f"[red]GUI app not found at {gui_path}[/red]")
        raise typer.Exit(1)

    args = ["streamlit", "run", str(gui_path), "--server.headless", "true"]
    if case:
        args.extend(["--", "--case", case])

    try:
        subprocess.run(args)
    except FileNotFoundError:
        console.print("[red]Streamlit not found. Install with: pip install streamlit[/red]")
        raise typer.Exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# atlas explain — explain from saved case (no AWS calls)
# ═══════════════════════════════════════════════════════════════════════════
@app.command()
def explain(
    case: str = CaseOption,
    attack_path: str = AttackPathOption,
) -> None:
    """Explain an attack path from a saved case — no AWS API calls."""
    from atlas.core.cases import load_case
    from atlas.core.models import AttackEdge

    try:
        case_data = load_case(case)
    except FileNotFoundError:
        console.print(f"\n[red]Case '{case}' not found.[/red]")
        console.print("[dim]  Run  atlas cases  to see available cases.[/dim]")
        raise typer.Exit(1)

    env_model = case_data["env_model"]
    attack_edges: list[AttackEdge] = case_data["attack_edges"]
    source_identity = case_data["source_identity"]
    case_meta = case_data["case_meta"]

    console.print(f"\n[bold]Case[/bold]  [cyan]{case}[/cyan]  →  output/{case}/")
    console.print(f"  Account   {case_meta.get('account_id', '?')}")
    console.print(f"  Identity  {source_identity.split('/')[-1]}")
    created_raw = case_meta.get("created_at", "?")
    if created_raw != "?":
        try:
            created_dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            created_raw = created_dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            pass
    console.print(f"  Created   {created_raw}")

    # Build path map
    path_map, sorted_chains = _build_path_map(attack_edges, source_identity)

    if not attack_path:
        _show_attack_paths_from_edges(sorted_chains)
        console.print(f"\n[dim]  Select a path to explain with  --attack-path AP-XX[/dim]")
        return

    ap_key = attack_path.upper()
    if ap_key not in path_map:
        console.print(f"\n[red]Unknown path ID '{attack_path}'. Available: AP-01 to AP-{len(path_map):02d}[/red]")
        raise typer.Exit(1)

    selected_chain = path_map[ap_key]

    # Show chain detail
    _show_chain_detail(ap_key, selected_chain, env_model)

    # Check cache first
    from atlas.core.cases import load_explanation, save_explanation

    cached = load_explanation(case, ap_key)
    if cached:
        console.print(f"\n[bold green]Explanation[/bold green] [dim](cached)[/dim]\n")
        for line in cached.split("\n"):
            console.print(f"  {line}")
        return

    # Not cached — generate from first edge (single-hop) or summarize chain
    if selected_chain.hop_count != 1:
        # Multi-hop: show a template explanation
        console.print(f"\n[bold green]Chain Explanation[/bold green]\n")
        console.print(f"  This is a {selected_chain.hop_count}-step attack chain:")
        console.print(f"  {selected_chain.summary_text}\n")
        for i, edge in enumerate(selected_chain.edges):
            action_name = _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value)
            console.print(f"  Step {i+1}: {action_name}")
            console.print(f"    From: {_short_name(edge.source_arn)}")
            console.print(f"    To:   {_short_name(edge.target_arn)}")
            console.print(f"    API:  {', '.join(edge.api_actions)}")
            console.print(f"    Cost: {edge.detection_cost:.4f}  |  Success: {edge.success_probability:.0%}")
            if edge.notes:
                console.print(f"    Note: {edge.notes}")
            console.print()
        total_text = f"Total detection cost: {selected_chain.total_detection_cost:.4f}, "
        total_text += f"Combined success probability: {selected_chain.total_success_probability:.0%}"
        console.print(f"  {total_text}")
        # Save to cache
        cache_text = f"{selected_chain.hop_count}-step chain: {selected_chain.summary_text}\n"
        for i, edge in enumerate(selected_chain.edges):
            action_name = _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value)
            cache_text += f"\nStep {i+1}: {action_name} ({_short_name(edge.source_arn)} → {_short_name(edge.target_arn)})"
            cache_text += f"\n  API: {', '.join(edge.api_actions)}"
            if edge.notes:
                cache_text += f"\n  {edge.notes}"
        save_explanation(case, ap_key, cache_text)
        return

    selected = selected_chain.edges[0]

    async def _run_explain() -> None:
        from rich.status import Status
        from atlas.planner.explainer import AttackPathExplainer

        explainer = AttackPathExplainer()

        source_info = {"type": _arn_type(selected.source_arn)}
        target_info = {"type": _arn_type(selected.target_arn)}
        if env_model.graph.has_node(selected.target_arn):
            target_info.update(env_model.graph.get_node_data(selected.target_arn))

        source_policies = [p["name"] for p in _get_identity_policies(selected.source_arn, env_model)]
        target_policies = [p["name"] for p in _get_identity_policies(selected.target_arn, env_model)]

        mode = "AI" if explainer.has_llm else "Template"
        with Status(f"[cyan]Generating explanation ({mode})...[/cyan]", console=console, spinner="dots"):
            explanation = await explainer.explain(
                selected, source_info, target_info,
                source_policies, target_policies,
            )

        save_explanation(case, ap_key, explanation)

        label = "[dim](AI-generated, saved)[/dim]" if explainer.has_llm else ""
        console.print(f"\n[bold green]Explanation[/bold green] {label}\n")
        for line in explanation.split("\n"):
            console.print(f"  {line}")

    asyncio.run(_run_explain())


# ═══════════════════════════════════════════════════════════════════════════
# atlas inspect — detection profile lookup
# ═══════════════════════════════════════════════════════════════════════════
@app.command()
def inspect(
    action: str = typer.Argument(
        ..., help="API action to inspect, e.g. 'iam:CreateAccessKey'"
    ),
) -> None:
    """Inspect detection profile for an AWS API action."""
    from atlas.core.models import LoggingState, CloudTrailConfig
    from atlas.planner.detection import DetectionScorer

    table = Table(title=f"Detection Profile  {action}")
    table.add_column("", style="cyan")
    table.add_column("Full Logging", style="white")
    table.add_column("Minimal Logging", style="white")

    postures = []
    for label, logging_state in [
        ("Full Logging", LoggingState(
            cloudtrail_trails=[
                CloudTrailConfig(trail_name="main", trail_arn="arn:aws:cloudtrail:us-east-1:123:trail/main", is_logging=True)
            ],
            guardduty={"is_enabled": True},
            config_recorder_enabled=True,
            security_hub_enabled=True,
            access_analyzer_enabled=True,
        )),
        ("Minimal Logging", LoggingState()),
    ]:
        scorer = DetectionScorer(logging_state)
        postures.append(scorer.explain(action))

    if postures:
        full, minimal = postures
        all_keys = list(dict.fromkeys(list(full.keys()) + list(minimal.keys())))
        for k in all_keys:
            if k == "factors":
                full_factors = "\n".join(full.get("factors", []))
                min_factors = "\n".join(minimal.get("factors", []))
                table.add_row("Factors", full_factors, min_factors)
            else:
                table.add_row(k.replace("_", " ").title(), str(full.get(k, "—")), str(minimal.get(k, "—")))

    console.print(f"\n")
    console.print(table)


# ═══════════════════════════════════════════════════════════════════════════
# atlas inspect-key — offline access key ID decoder
# ═══════════════════════════════════════════════════════════════════════════
@app.command("inspect-key")
def inspect_key(
    access_key_id: str = typer.Argument(
        ..., help="AWS access key ID to decode (e.g. ASIAY34FZKBOKMUTVV7A)"
    ),
) -> None:
    """Decode AWS account ID from an access key ID (offline, no API calls).

    This performs ZERO API calls — the account ID is extracted directly from
    the key ID using base32 decoding and bit-shifting.  Works for keys
    created after March 29, 2019.

    \b
    Research credit:
      - Aidan Steele: AWS Access Key ID Formats
      - Tal Be'ery: A short note on AWS KEY ID
    """
    from atlas.utils.key_decoder import classify_key

    info = classify_key(access_key_id)

    table = Table(title="Access Key Analysis")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Access Key ID", info.access_key_id)
    table.add_row("Prefix", f"{info.prefix} ({info.prefix_description})")
    table.add_row("Key Type",
                  "[yellow]Temporary (STS)[/]" if info.is_temporary
                  else "[green]Long-lived (IAM)[/]" if info.is_long_lived
                  else "[dim]Other[/]")
    table.add_row("Format", "[green]New (post-March 2019)[/]" if info.is_new_format
                  else "[yellow]Old (pre-March 2019)[/]")

    if info.account_id:
        table.add_row(
            "Account ID",
            f"[bold green]{info.account_id}[/]",
        )
        table.add_row("Decode Method", f"[green]{info.decode_method}[/] (zero API calls)")
    else:
        table.add_row(
            "Account ID",
            "[yellow]Cannot decode offline (old-format key)[/]",
        )
        table.add_row(
            "Suggestion",
            "[dim]Use sts:GetAccessKeyInfo from YOUR account "
            "(only logs in your account, not the target's)[/]",
        )

    console.print(f"\n")
    console.print(table)

    # Also show the security context
    console.print(f"\n")
    context = Panel(
        "[bold]Security Context[/]\n\n"
        "[cyan]Offline decode:[/] Account ID is encoded in the key ID itself.\n"
        "  - No API calls generated\n"
        "  - No CloudTrail events in ANY account\n"
        "  - Completely silent reconnaissance\n\n"
        "[cyan]API alternative (sts:GetAccessKeyInfo):[/]\n"
        "  - Logged ONLY in the caller's account\n"
        "  - NOT logged in the target's account\n"
        "  - Safe for red team scope validation\n\n"
        "[cyan]Key prefixes:[/]\n"
        "  AKIA = Long-lived IAM user key\n"
        "  ASIA = Temporary STS credentials\n"
        "  AROA = IAM Role unique ID\n"
        "  AIDA = IAM User unique ID",
        title="Technique: Get Account ID from Access Key",
        border_style="blue",
    )
    console.print(context)


# ═══════════════════════════════════════════════════════════════════════════
# Shared path map builder (used by simulate, run, explain)
# ═══════════════════════════════════════════════════════════════════════════
def _build_path_map(
    attack_edges: list[Any],
    source_identity: str,
) -> tuple[dict[str, Any], list[Any]]:
    """Build a chain map from saved edges using ChainFinder.

    Returns (path_map, sorted_chains) where each value is an AttackChain.
    """
    from atlas.planner.attack_graph import AttackGraph
    from atlas.planner.chain_finder import ChainFinder

    # Rebuild attack graph from saved edges
    ag = AttackGraph()
    for edge in attack_edges:
        ag.add_edge(edge)

    finder = ChainFinder(ag, max_depth=4, max_chains=50)
    chains = finder.find_chains(source_identity)

    path_map: dict[str, Any] = {}
    for i, chain in enumerate(chains):
        path_map[f"AP-{i + 1:02d}"] = chain

    return path_map, chains


# ═══════════════════════════════════════════════════════════════════════════
# Plan diff (replan comparison)
# ═══════════════════════════════════════════════════════════════════════════
def _show_plan_diff(
    old_paths: dict[str, dict[str, str]],
    new_paths_data: list[dict[str, Any]],
    new_path_map: dict[str, Any],
) -> None:
    """Show what changed between the old and new plan."""
    # Build signature: "attack|target" for single-hop backward compat
    # or "chain_desc" for multi-hop
    def _sig(p: dict[str, Any]) -> str:
        chain_text = p.get("chain", "")
        if chain_text:
            return chain_text
        return f"{p.get('attack', '')}|{p.get('target', '')}"

    new_keys: dict[str, dict[str, Any]] = {}
    for p in new_paths_data:
        new_keys[_sig(p)] = p

    old_sigs: dict[str, dict[str, Any]] = {}
    for p in old_paths.values():
        old_sigs[_sig(p)] = p

    added = [k for k in new_keys if k not in old_sigs]
    removed = [k for k in old_sigs if k not in new_keys]

    if not added and not removed:
        console.print(f"\n[green]No changes[/green] — attack paths are the same as the previous plan.")
        return

    table = Table(title="Plan Changes (Replan Diff)")
    table.add_column("Change", style="bold", no_wrap=True)
    table.add_column("Chain", style="cyan", no_wrap=True)
    table.add_column("Target", style="white", no_wrap=True)
    table.add_column("Hops", justify="center", no_wrap=True)

    for key in added:
        p = new_keys[key]
        chain_desc = p.get("chain", _ACTION_NAMES.get(p.get("attack", ""), "?"))
        target_short = _short_name(p.get("target", ""), max_len=28)
        table.add_row("[green]+ NEW[/green]", chain_desc, target_short, str(p.get("hops", 1)))

    for key in removed:
        p = old_sigs[key]
        chain_desc = p.get("chain", _ACTION_NAMES.get(p.get("attack", ""), "?"))
        target_short = _short_name(p.get("target", ""), max_len=28)
        table.add_row("[red]- GONE[/red]", chain_desc, target_short, str(p.get("hops", 1)))

    console.print(f"\n")
    console.print(table)
    console.print(f"\n  [dim]{len(added)} new path(s), {len(removed)} removed path(s)[/dim]")


# ═══════════════════════════════════════════════════════════════════════════
# Shared formatting helpers
# ═══════════════════════════════════════════════════════════════════════════
_ACTION_NAMES: dict[str, str] = {
    "can_assume": "Role Assumption",
    "can_create_key": "Access Key Creation",
    "can_attach_policy": "Policy Attachment",
    "can_put_policy": "Inline Policy Injection",
    "can_passrole": "PassRole Abuse",
    "can_modify_trust": "Trust Modification",
    "can_update_lambda": "Lambda Code Injection",
    "can_read_s3": "S3 Read Access",
    "can_write_s3": "S3 Write Access",
    "can_read_userdata": "EC2 User Data Disclosure",
    "can_enum_backup": "Backup Service Enumeration",
    "can_decode_key": "Access Key Account Decode",
    "can_loot_snapshot": "Public EBS Snapshot Loot",
    "can_steal_imds_creds": "IMDS Credential Theft",
    "can_ssm_session": "SSM Session / Command",
    "can_snapshot_volume": "EC2 Volume Snapshot Loot",
    "can_modify_userdata": "EC2 UserData Injection",
    "can_steal_lambda_creds": "Lambda Credential Theft",
    "can_steal_ecs_task_creds": "ECS Task Role Compromise",
    "can_access_via_resource_policy": "Resource Policy Misconfiguration",
    "can_get_federation_token": "GetFederationToken Persistence",
    "can_create_codebuild_github_runner": "CodeBuild GitHub Runner Persistence",
    "can_create_rogue_oidc_persistence": "Rogue OIDC IdP Persistence",
    "can_create_roles_anywhere_persistence": "IAM Roles Anywhere Persistence",
    "can_modify_s3_acl_persistence": "S3 ACL Persistence",
    "assume_role": "Assume Role",
    "create_access_key": "Create Access Key",
    "attach_policy": "Attach Policy",
    "put_inline_policy": "Put Inline Policy",
    "passrole_lambda": "PassRole + Lambda",
    "passrole_agentcore": "AgentCore Role Confusion",
    "modify_trust_policy": "Modify Trust Policy",
    "update_lambda_code": "Update Lambda Code",
    "read_s3": "Read S3 Bucket",
    "read_userdata": "Read EC2 User Data",
    "enum_backup": "Enumerate Backup Service",
    "decode_key_account": "Decode Key Account ID",
    "loot_public_snapshot": "Loot Public EBS Snapshot",
    "steal_imds_credentials": "Steal IMDS Credentials",
    "ssm_session": "SSM Session / Command",
    "snapshot_volume_loot": "Snapshot Volume Loot",
    "inject_userdata": "Inject EC2 UserData",
    "steal_lambda_credentials": "Steal Lambda Credentials",
    "steal_ecs_task_credentials": "Steal ECS Task Credentials",
    "access_via_resource_policy": "Access via Resource Policy",
    "write_s3": "Write S3 Bucket",
    "get_federation_token": "GetFederationToken Persistence",
    "codebuild_github_runner_persistence": "CodeBuild GitHub Runner Persistence",
    "rogue_oidc_persistence": "Rogue OIDC IdP Persistence",
    "roles_anywhere_persistence": "IAM Roles Anywhere Persistence",
    "s3_acl_persistence": "S3 ACL Persistence",
    "read_codebuild_env": "CodeBuild Env Credential Theft",
    "read_beanstalk_env": "Beanstalk Env Credential Theft",
    "pivot_via_beanstalk_creds": "Beanstalk Credential Pivot",
    "hijack_bedrock_agent": "Bedrock Agent Hijacking",
    "can_modify_cloudtrail_event_selectors": "CloudTrail Event Selectors Evasion",
    "modify_cloudtrail_event_selectors": "Modify CloudTrail Event Selectors",
    "can_create_admin_user": "Create Admin User",
    "can_create_backdoor_role": "Create Backdoor Role",
    "create_admin_user": "Create Admin User",
    "create_backdoor_role": "Create Backdoor Role",
    "can_backdoor_lambda": "Lambda Resource Policy Backdoor",
    "backdoor_lambda": "Backdoor Lambda Function",
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
}


def _noise_label(noise: str) -> str:
    labels = {
        "silent": "[green]Silent[/green]",
        "low": "[green]Low[/green]",
        "medium": "[yellow]Medium[/yellow]",
        "high": "[red]High[/red]",
        "critical": "[bold red]Critical[/bold red]",
    }
    return labels.get(noise, noise)


def _arn_type(arn: str) -> str:
    if arn.startswith("external::"):
        return "External"
    if ":user/" in arn:
        return "User"
    if ":role/" in arn:
        if "/aws-service-role/" in arn:
            return "Service Role"
        return "Role"
    if ":group/" in arn:
        return "Group"
    if ":policy/" in arn:
        return "Policy"
    if "s3:::" in arn or ":s3:" in arn:
        return "S3 Bucket"
    if ":instance/" in arn:
        return "EC2"
    if ":function:" in arn:
        return "Lambda"
    if ":root" in arn:
        return "Root"
    return "Other"


def _short_name(arn: str, max_len: int = 35) -> str:
    if arn.startswith("external::"):
        label = {"external::ec2-imds-ssrf": "External (EC2 IMDS SSRF)"}.get(
            arn, arn.replace("external::", "External: ")
        )
        return label[:max_len] + "..." if len(label) > max_len else label
    name = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
    if len(name) > max_len:
        name = name[: max_len - 3] + "..."
    return name


# ═══════════════════════════════════════════════════════════════════════════
# Policy extraction from environment graph
# ═══════════════════════════════════════════════════════════════════════════
def _get_identity_policies(arn: str, env_model: Any) -> list[dict[str, str]]:
    from atlas.core.types import EdgeType

    policies: list[dict[str, str]] = []

    for target_arn, edge_data in env_model.graph.outgoing(arn):
        if edge_data.get("edge_type") == EdgeType.HAS_POLICY.value:
            policy_name = target_arn.split("/")[-1]
            is_aws = ":aws:policy/" in target_arn
            policies.append({
                "name": policy_name,
                "arn": target_arn,
                "type": "AWS Managed" if is_aws else "Customer Managed",
            })

    if env_model.graph.has_node(arn):
        node_data = env_model.graph.get_node_data(arn)
        for inline_name in node_data.get("inline_policy_names", []):
            policies.append({
                "name": inline_name,
                "arn": "",
                "type": "Inline",
            })

    return policies


def _show_policies_table(title: str, policies: list[dict[str, str]]) -> None:
    if not policies:
        return
    table = Table(title=title)
    table.add_column("Policy", style="white", no_wrap=True)
    table.add_column("Type", style="magenta", no_wrap=True)
    for p in policies:
        table.add_row(p["name"], p["type"])
    console.print(table)


def _get_resource_policy(arn: str, env_model: Any) -> tuple[str, dict | None]:
    """Return (label, policy) for trust policy (roles) or bucket policy (S3)."""
    if not env_model.graph.has_node(arn):
        return "", None
    data = env_model.graph.get_node_data(arn)
    if ":role/" in arn and "/aws-service-role/" not in arn:
        policy = data.get("trust_policy") or {}
        if policy:
            return "Trust Policy", policy
    if "s3:::" in arn or ":s3:" in arn:
        policy = data.get("bucket_policy")
        if policy:
            return "Bucket Policy", policy
    return "", None


def _show_resource_policy(title: str, policy: dict) -> None:
    """Display a resource policy (trust or bucket) as formatted JSON."""
    if not policy:
        return
    import json
    try:
        text = json.dumps(policy, indent=2, default=str)
    except (TypeError, ValueError):
        text = str(policy)
    if len(text) > 2000:
        text = text[:2000] + "\n  ... (truncated)"
    console.print(f"\n[bold]{title}[/bold]")
    for line in text.split("\n"):
        console.print(f"  [dim]{line}[/dim]")


def _render_chain_viz(chain: Any, path_id: str = "") -> None:
    """Render an attack chain as ASCII visualization."""
    max_name = 26
    nodes: list[str] = [_short_name(chain.source_arn, max_len=max_name)]
    edge_labels: list[str] = []

    for edge in chain.edges:
        nodes.append(_short_name(edge.target_arn, max_len=max_name))
        if edge.api_actions:
            label = ", ".join(edge.api_actions)
        else:
            label = _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value)
        edge_labels.append(label)

    # Build ASCII diagram: box → arrow → box → arrow → ...
    def _box(txt: str, indent: str = "  ") -> str:
        content_w = max(len(txt), 8)
        pad = "─" * (content_w + 2)
        return f"{indent}┌{pad}┐\n{indent}│ {txt:<{content_w}} │\n{indent}└{pad}┘"

    title = f"  Chain {path_id}" if path_id else "  Attack Chain"
    console.print(f"\n[bold cyan]{title}[/bold cyan]")
    console.print(f"[bold white]{_box(nodes[0])}[/bold white]")
    for i, label in enumerate(edge_labels):
        console.print("       │")
        console.print(f"       │  [dim]{label}[/dim]")
        console.print("       ▼")
        console.print(f"[bold white]{_box(nodes[i + 1])}[/bold white]")


def _show_chain_detail(path_id: str, chain: Any, env_model: Any) -> None:
    """Show detailed view of an attack chain (single or multi-hop)."""
    _render_chain_viz(chain, path_id)

    if chain.hop_count == 1:
        # Single-hop: show like before
        edge = chain.edges[0]
        detail = Table(title=f"Attack Path {path_id}")
        detail.add_column("", style="cyan")
        detail.add_column("", style="white")
        detail.add_row("Attack Type", _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value))
        detail.add_row("Source", _short_name(edge.source_arn))
        detail.add_row("Target", _short_name(edge.target_arn))
        detail.add_row("Target Type", _arn_type(edge.target_arn))
        detail.add_row("Detection Cost", f"{edge.detection_cost:.4f}")
        noise_val = edge.noise_level.value if hasattr(edge.noise_level, "value") else str(edge.noise_level)
        detail.add_row("Noise Level", _noise_label(noise_val))
        detail.add_row("Success Probability", f"{edge.success_probability:.0%}")
        detail.add_row("Guardrail Status", edge.guardrail_status.title())
        detail.add_row("API Actions", ", ".join(edge.api_actions))
        if edge.notes:
            detail.add_row("Notes", edge.notes)
        console.print(f"\n")
        console.print(detail)

        source_policies = _get_identity_policies(edge.source_arn, env_model)
        _show_policies_table(f"Policies  {_short_name(edge.source_arn)} (Source)", source_policies)

        target_policies = _get_identity_policies(edge.target_arn, env_model)
        _show_policies_table(f"Policies  {_short_name(edge.target_arn)} (Target)", target_policies)

        label, resource_policy = _get_resource_policy(edge.target_arn, env_model)
        if label and resource_policy:
            _show_resource_policy(f"{label}  {_short_name(edge.target_arn)} (Target)", resource_policy)
    else:
        # Multi-hop: show chain steps table
        noise_val = chain.max_noise_level.value if hasattr(chain.max_noise_level, "value") else str(chain.max_noise_level)
        header = Table(title=f"Attack Chain {path_id}  ({chain.hop_count} hops)")
        header.add_column("", style="cyan")
        header.add_column("", style="white")
        header.add_row("Chain", chain.summary_text)
        header.add_row("Final Target", _short_name(chain.final_target_arn))
        header.add_row("Final Target Type", _arn_type(chain.final_target_arn))
        header.add_row("Total Detection Cost", f"{chain.total_detection_cost:.4f}")
        header.add_row("Max Noise Level", _noise_label(noise_val))
        header.add_row("Combined Success", f"{chain.total_success_probability:.0%}")
        console.print(f"\n")
        console.print(header)

        # Steps table
        steps_table = Table(title="Chain Steps")
        steps_table.add_column("Hop", justify="right", style="bold white")
        steps_table.add_column("Action", style="cyan")
        steps_table.add_column("From", style="white")
        steps_table.add_column("To", style="white")
        steps_table.add_column("Cost", justify="right", style="yellow")
        steps_table.add_column("Noise", justify="center")
        steps_table.add_column("Success", justify="right", style="green")

        for i, edge in enumerate(chain.edges):
            en = edge.noise_level.value if hasattr(edge.noise_level, "value") else str(edge.noise_level)
            steps_table.add_row(
                str(i + 1),
                _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value),
                _short_name(edge.source_arn),
                _short_name(edge.target_arn),
                f"{edge.detection_cost:.4f}",
                _noise_label(en),
                f"{edge.success_probability:.0%}",
            )
        console.print(steps_table)

        # Policies for source and final target
        source_policies = _get_identity_policies(chain.source_arn, env_model)
        _show_policies_table(f"Policies  {_short_name(chain.source_arn)} (Source)", source_policies)

        target_policies = _get_identity_policies(chain.final_target_arn, env_model)
        _show_policies_table(f"Policies  {_short_name(chain.final_target_arn)} (Final Target)", target_policies)

        label, resource_policy = _get_resource_policy(chain.final_target_arn, env_model)
        if label and resource_policy:
            _show_resource_policy(f"{label}  {_short_name(chain.final_target_arn)} (Final Target)", resource_policy)


# Keep legacy helper for backward compat
def _show_path_detail(path_id: str, edge: Any, env_model: Any) -> None:
    from atlas.core.models import AttackChain
    chain = AttackChain(edges=[edge], total_detection_cost=edge.detection_cost,
                        total_success_probability=edge.success_probability, hop_count=1)
    _show_chain_detail(path_id, chain, env_model)


async def _explain_attack_path(edge: Any, env_model: Any) -> None:
    from rich.status import Status
    from atlas.planner.explainer import AttackPathExplainer

    explainer = AttackPathExplainer()

    source_info = {"type": _arn_type(edge.source_arn)}
    target_info = {"type": _arn_type(edge.target_arn)}
    if env_model.graph.has_node(edge.target_arn):
        target_info.update(env_model.graph.get_node_data(edge.target_arn))

    source_policies = [p["name"] for p in _get_identity_policies(edge.source_arn, env_model)]
    target_policies = [p["name"] for p in _get_identity_policies(edge.target_arn, env_model)]

    mode = "AI" if explainer.has_llm else "Template"
    with Status(f"[cyan]Generating explanation ({mode})...[/cyan]", console=console, spinner="dots"):
        explanation = await explainer.explain(
            edge, source_info, target_info,
            source_policies, target_policies,
        )

    label = "[dim](AI-generated)[/dim]" if explainer.has_llm else ""
    console.print(f"\n[bold green]Explanation[/bold green] {label}\n")
    for line in explanation.split("\n"):
        console.print(f"  {line}")


# ═══════════════════════════════════════════════════════════════════════════
# Attack Paths table (now chain-aware)
# ═══════════════════════════════════════════════════════════════════════════
def _show_attack_paths(attack_graph: Any, source_arn: str) -> dict[str, Any]:
    """Discover and display attack chains (single + multi-hop).

    Includes chains from current identity and from external entry points
    (e.g. external::ec2-imds-ssrf for CloudGoat cloud_breach_s3).
    """
    from atlas.planner.chain_finder import ChainFinder

    finder = ChainFinder(attack_graph, max_depth=4, max_chains=50)
    chains = finder.find_chains(source_arn)

    # Also find chains from external entry points (anonymous attacker scenarios)
    external_sources = ["external::ec2-imds-ssrf"]
    for ext in external_sources:
        if attack_graph.raw.has_node(ext) and attack_graph.raw.out_degree(ext) > 0:
            ext_chains = finder.find_chains(ext)
            # Deduplicate by (final_target, edge sequence)
            seen = {(c.final_target_arn, tuple(e.edge_type.value for e in c.edges)) for c in chains}
            for c in ext_chains:
                key = (c.final_target_arn, tuple(e.edge_type.value for e in c.edges))
                if key not in seen:
                    seen.add(key)
                    chains.append(c)

    # Sort by detection cost, then by source (external first for visibility)
    def _chain_sort_key(c: Any) -> tuple[float, int]:
        from_priority = 0 if c.source_arn.startswith("external::") else 1
        return (c.total_detection_cost, from_priority)

    chains.sort(key=_chain_sort_key)

    if not chains:
        console.print("\n[red]No attack paths found from current identity.[/red]")
        return {}

    path_map: dict[str, Any] = {}
    return _show_chains_table(chains, path_map)


def _show_chains_table(chains: list[Any], path_map: dict[str, Any]) -> dict[str, Any]:
    """Render the attack chains table. Populates and returns path_map."""
    table = Table(title=f"Available Attack Paths ({len(chains)} total)")
    table.add_column("ID", style="bold white", no_wrap=True, min_width=5)
    table.add_column("From", style="magenta", no_wrap=True, min_width=18)
    table.add_column("Cost", justify="right", style="yellow", no_wrap=True, min_width=7)
    table.add_column("Chain", style="cyan", no_wrap=True, min_width=20)
    table.add_column("Final Target", style="white", no_wrap=True)
    table.add_column("Type", style="magenta", no_wrap=True)
    table.add_column("Noise", justify="center", no_wrap=True)
    table.add_column("Success", justify="right", style="green", no_wrap=True)

    for i, chain in enumerate(chains):
        path_id = f"AP-{i + 1:02d}"
        path_map[path_id] = chain

        noise_val = chain.max_noise_level.value if hasattr(chain.max_noise_level, "value") else str(chain.max_noise_level)

        # Build chain description
        if chain.hop_count == 1:
            edge = chain.edges[0]
            chain_desc = _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value)
        else:
            parts = []
            for e in chain.edges:
                parts.append(_ACTION_NAMES.get(e.edge_type.value, e.edge_type.value))
            chain_desc = " → ".join(parts)

        table.add_row(
            path_id,
            _short_name(chain.source_arn, max_len=20),
            f"{chain.total_detection_cost:.4f}",
            chain_desc,
            _short_name(chain.final_target_arn, max_len=28),
            _arn_type(chain.final_target_arn),
            _noise_label(noise_val),
            f"{chain.total_success_probability:.0%}",
        )

    console.print(f"\n")
    console.print(table)
    return path_map


def _show_attack_paths_from_edges(sorted_chains: list[Any]) -> None:
    """Show chains table from pre-built list (for saved cases)."""
    path_map: dict[str, Any] = {}
    _show_chains_table(sorted_chains, path_map)


# ═══════════════════════════════════════════════════════════════════════════
# Plan display
# ═══════════════════════════════════════════════════════════════════════════
def _resolve_path_id(plan: Any, path_map: dict[str, Any]) -> str | None:
    """Try to match an auto-generated plan back to an AP-XX chain."""
    if not plan or not plan.steps or not path_map:
        return None
    first_step = plan.steps[0]
    action_to_edge = {
        "assume_role": "can_assume",
        "create_access_key": "can_create_key",
        "attach_policy": "can_attach_policy",
        "put_inline_policy": "can_put_policy",
        "passrole_lambda": "can_passrole",
        "passrole_agentcore": "can_passrole_agentcore",
        "modify_trust_policy": "can_modify_trust",
        "update_lambda_code": "can_update_lambda",
    }
    expected_edge = action_to_edge.get(first_step.action_type, "")
    for pid, chain in path_map.items():
        if chain.edges and chain.edges[0].edge_type.value == expected_edge and chain.edges[0].target_arn == first_step.target_arn:
            return pid
    return None


def _show_plan(plan: Any, path_id: str | None = None) -> None:
    title = "Selected Plan"
    if path_id:
        title = f"Selected Plan  —  {path_id}"

    table = Table(title=title)
    table.add_column("Step", justify="right", style="bold white")
    table.add_column("Action", style="cyan")
    table.add_column("From", style="white")
    table.add_column("To", style="white")
    table.add_column("Cost", justify="right", style="yellow")
    table.add_column("Noise", justify="center")

    for i, step in enumerate(plan.steps):
        noise_val = step.noise_level.value if hasattr(step.noise_level, "value") else str(step.noise_level)
        table.add_row(
            str(i + 1),
            _ACTION_NAMES.get(step.action_type, step.action_type),
            _short_name(step.source_arn),
            _short_name(step.target_arn),
            f"{step.detection_cost:.4f}",
            _noise_label(noise_val),
        )

    console.print(f"\n")
    console.print(table)


def _show_reachable(targets: list[dict[str, Any]]) -> None:
    if not targets:
        return
    table = Table(title=f"Reachable Targets ({len(targets)})")
    table.add_column("Target", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Hops", justify="right")
    table.add_column("Detection Cost", justify="right", style="yellow")
    table.add_column("Success", justify="right", style="green")
    for t in targets[:20]:
        arn = t["target"]
        table.add_row(
            _short_name(arn),
            _arn_type(arn),
            str(t["hops"]),
            f"{t['detection_cost']:.4f}",
            f"{t['success_probability']:.1%}",
        )
    console.print(f"\n")
    console.print(table)


def _simulate_execution(plan: Any) -> None:
    table = Table(title="Simulation")
    table.add_column("Step", justify="right", style="bold white")
    table.add_column("Action", style="cyan")
    table.add_column("From", style="white")
    table.add_column("To", style="white")
    table.add_column("Cost", justify="right", style="yellow")
    table.add_column("Noise", justify="center")
    table.add_column("Cumulative", justify="right", style="yellow")

    cumulative_cost = 0.0
    for i, step in enumerate(plan.steps):
        cumulative_cost += step.detection_cost
        noise_val = step.noise_level.value if hasattr(step.noise_level, "value") else str(step.noise_level)
        table.add_row(
            str(i + 1),
            _ACTION_NAMES.get(step.action_type, step.action_type),
            _short_name(step.source_arn),
            _short_name(step.target_arn),
            f"{step.detection_cost:.4f}",
            _noise_label(noise_val),
            f"{cumulative_cost:.4f}",
        )

    console.print(f"\n")
    console.print(table)


# ═══════════════════════════════════════════════════════════════════════════
# Chain-to-plan converter (handles single and multi-hop chains)
# ═══════════════════════════════════════════════════════════════════════════
_EDGE_TO_ACTION: dict[str, str] = {
    "can_assume": "assume_role",
    "can_create_key": "create_access_key",
    "can_attach_policy": "attach_policy",
    "can_put_policy": "put_inline_policy",
    "can_passrole": "passrole_lambda",
    "can_passrole_agentcore": "passrole_agentcore",
    "can_modify_trust": "modify_trust_policy",
    "can_update_lambda": "update_lambda_code",
    "can_read_s3": "read_s3",
    "can_write_s3": "write_s3",
    "can_read_userdata": "read_userdata",
    "can_steal_imds_creds": "steal_imds_credentials",
    "can_ssm_session": "ssm_session",
    "can_snapshot_volume": "snapshot_volume_loot",
    "can_modify_userdata": "inject_userdata",
    "can_steal_lambda_creds": "steal_lambda_credentials",
    "can_steal_ecs_task_creds": "steal_ecs_task_credentials",
    "can_access_via_resource_policy": "access_via_resource_policy",
    "can_enum_backup": "enum_backup",
    "can_decode_key": "decode_key_account",
    "can_loot_snapshot": "loot_public_snapshot",
    "can_read_codebuild_env": "read_codebuild_env",
    "can_read_beanstalk_env": "read_beanstalk_env",
    "can_pivot_via_beanstalk_creds": "pivot_via_beanstalk_creds",
    "can_hijack_bedrock_agent": "hijack_bedrock_agent",
}


def _chain_to_plan(chain: Any, source_arn: str) -> Any:
    """Convert an AttackChain (single or multi-hop) into an AttackPlan."""
    import uuid
    from atlas.core.models import AttackPlan, PlannedAction

    plan_id = uuid.uuid4().hex[:12]
    pace_map = {"silent": 1.0, "low": 3.0, "medium": 10.0, "high": 30.0, "critical": 60.0}

    steps: list[PlannedAction] = []
    prev_id: str | None = None

    for i, edge in enumerate(chain.edges):
        noise_val = edge.noise_level.value if hasattr(edge.noise_level, "value") else str(edge.noise_level)
        pace = pace_map.get(noise_val, 10.0)
        step_id = f"{plan_id}-step-{i:02d}"

        step = PlannedAction(
            action_id=step_id,
            action_type=_EDGE_TO_ACTION.get(edge.edge_type.value, edge.edge_type.value),
            source_arn=edge.source_arn,
            target_arn=edge.target_arn,
            api_calls=edge.api_actions,
            parameters=edge.conditions,
            detection_cost=edge.detection_cost,
            success_probability=edge.success_probability,
            noise_level=edge.noise_level,
            pace_hint_seconds=pace,
            stealth_notes=edge.notes,
            rollback_type=None,
            depends_on=[prev_id] if prev_id else [],
        )
        steps.append(step)
        prev_id = step_id

    # Build objective
    if chain.hop_count == 1:
        edge = chain.edges[0]
        objective = f"{_ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value)} on {_short_name(edge.target_arn)}"
    else:
        objective = chain.objective

    return AttackPlan(
        plan_id=plan_id,
        strategy="user_selected",
        objective=objective,
        steps=steps,
        total_detection_cost=chain.total_detection_cost,
        estimated_success_probability=chain.total_success_probability,
        reasoning=[chain.summary_text],
        alternative_paths=0,
    )


# Keep backward compatibility alias
def _edge_to_plan(edge: Any, source_arn: str) -> Any:
    """Legacy: wrap a single edge into a plan. Use _chain_to_plan for chains."""
    from atlas.core.models import AttackChain
    chain = AttackChain(
        edges=[edge],
        total_detection_cost=edge.detection_cost,
        total_success_probability=edge.success_probability,
        hop_count=1,
    )
    return _chain_to_plan(chain, source_arn)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app()
