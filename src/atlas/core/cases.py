"""
atlas.core.cases
~~~~~~~~~~~~~~~~
Case management — all Atlas output is stored under output/<case_name>/.

Directory structure:
  output/<case>/
    case.json           — case metadata
    plan/               — recon + planning output
      env_model.json
      attack_edges.json
      attack_paths.json
      attack_plan.json
      plan_result.json
      findings.json
      telemetry.jsonl
    sim/                — simulation output (if run)
      simulation.json
      telemetry.jsonl
    run/                — execution output (if run)
      execution_report.json
      telemetry.jsonl
    explanations.json   — cached AI/template explanations
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _output_dir() -> Path:
    """Return the project-level output directory, creating it if needed."""
    d = Path("output")
    d.mkdir(parents=True, exist_ok=True)
    return d


def case_dir(name: str) -> Path:
    """Return the directory for a specific case, creating it if needed."""
    d = _output_dir() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def plan_dir(name: str) -> Path:
    """Return the plan subdirectory for a case."""
    d = case_dir(name) / "plan"
    d.mkdir(parents=True, exist_ok=True)
    return d


def sim_dir(name: str) -> Path:
    """Return the simulation subdirectory for a case."""
    d = case_dir(name) / "sim"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_dir(name: str) -> Path:
    """Return the run/execution subdirectory for a case."""
    d = case_dir(name) / "run"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_plan(
    name: str,
    env_model: Any,
    attack_edges: list[Any],
    source_identity: str,
    target: str,
) -> Path:
    """Save plan results to output/<case>/plan/. Returns the plan directory."""
    pd = plan_dir(name)

    # Environment model
    (pd / "env_model.json").write_text(
        json.dumps(env_model.to_dict(), indent=2, default=str)
    )

    # Attack graph edges
    edges_data = [e.model_dump() for e in attack_edges]
    (pd / "attack_edges.json").write_text(
        json.dumps(edges_data, indent=2, default=str)
    )

    # Findings
    if hasattr(env_model, "findings") and env_model.findings:
        findings_data = [f.model_dump() for f in env_model.findings]
        (pd / "findings.json").write_text(
            json.dumps(findings_data, indent=2, default=str)
        )

    # Plan result metadata
    plan_meta = {
        "source_identity": source_identity,
        "target": target,
    }
    (pd / "plan_result.json").write_text(
        json.dumps(plan_meta, indent=2, default=str)
    )

    # Case-level metadata
    case_meta = {
        "name": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "account_id": env_model.metadata.account_id,
        "region": env_model.metadata.region,
        "caller_arn": env_model.metadata.caller_arn,
        "attack_paths": len(edges_data),
        "findings": len(env_model.findings) if hasattr(env_model, "findings") else 0,
    }
    (case_dir(name) / "case.json").write_text(
        json.dumps(case_meta, indent=2, default=str)
    )

    return pd


def load_case(name: str) -> dict[str, Any]:
    """Load a saved case from output/<case>/plan/.

    Returns a dict with:
      - "env_model": EnvironmentModel
      - "attack_edges": list of AttackEdge
      - "source_identity": str
      - "target": str
      - "case_meta": dict
    """
    from atlas.core.models import AttackEdge
    from atlas.recon.engine import EnvironmentModel

    cd = _output_dir() / name
    pd = cd / "plan"
    if not pd.exists():
        raise FileNotFoundError(
            f"Case '{name}' not found. Run  atlas plan --case {name}  first."
        )

    # Load env model
    env_data = json.loads((pd / "env_model.json").read_text())
    env_model = EnvironmentModel.from_dict(env_data)

    # Load attack edges
    edges_file = pd / "attack_edges.json"
    attack_edges = []
    if edges_file.exists():
        edges_data = json.loads(edges_file.read_text())
        attack_edges = [AttackEdge(**e) for e in edges_data]

    # Load plan metadata
    plan_meta_file = pd / "plan_result.json"
    plan_meta = {}
    if plan_meta_file.exists():
        plan_meta = json.loads(plan_meta_file.read_text())

    # Load case metadata
    case_meta_file = cd / "case.json"
    case_meta = json.loads(case_meta_file.read_text()) if case_meta_file.exists() else {"name": name}

    return {
        "env_model": env_model,
        "attack_edges": attack_edges,
        "source_identity": plan_meta.get("source_identity", ""),
        "target": plan_meta.get("target", ""),
        "case_meta": case_meta,
    }


def list_cases() -> list[dict[str, Any]]:
    """List all saved cases with their metadata."""
    output = _output_dir()
    results = []
    for sub in sorted(output.iterdir()):
        if not sub.is_dir():
            continue
        # Must have a plan/ subdirectory to be a valid case
        if not (sub / "plan").is_dir():
            continue
        meta_file = sub / "case.json"
        if meta_file.exists():
            meta = json.loads(meta_file.read_text())
            # Check which phases exist
            meta["has_sim"] = (sub / "sim").is_dir()
            meta["has_run"] = (sub / "run").is_dir()
            results.append(meta)
    return results


def plan_age(name: str) -> float | None:
    """Return how many seconds ago the plan was created, or None if unknown."""
    cd = _output_dir() / name
    meta_file = cd / "case.json"
    if not meta_file.exists():
        return None
    meta = json.loads(meta_file.read_text())
    created = meta.get("created_at")
    if not created:
        return None
    try:
        created_dt = datetime.fromisoformat(created)
        now = datetime.now(timezone.utc)
        return (now - created_dt).total_seconds()
    except (ValueError, TypeError):
        return None


def delete_case(name: str) -> bool:
    """Delete a saved case.  Returns True if deleted."""
    import shutil
    cd = _output_dir() / name
    if cd.exists():
        shutil.rmtree(cd)
        return True
    return False


# ---------------------------------------------------------------------------
# Explanation cache (stored at case level, not inside plan/)
# ---------------------------------------------------------------------------
def _explanations_file(name: str) -> Path:
    """Return the path to the explanations cache file for a case."""
    return case_dir(name) / "explanations.json"


def load_explanation(name: str, path_id: str) -> str | None:
    """Load a cached explanation for a specific attack path."""
    f = _explanations_file(name)
    if not f.exists():
        return None
    cache: dict[str, str] = json.loads(f.read_text())
    return cache.get(path_id.upper())


def save_explanation(name: str, path_id: str, text: str) -> None:
    """Save an explanation to the case cache."""
    f = _explanations_file(name)
    cache: dict[str, str] = {}
    if f.exists():
        cache = json.loads(f.read_text())
    cache[path_id.upper()] = text
    f.write_text(json.dumps(cache, indent=2))
