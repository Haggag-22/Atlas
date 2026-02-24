"""
atlas.knowledge.pathfinding_loader
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Load and convert pathfinding.cloud attack paths into Atlas format.

pathfinding.cloud (Datadog) provides 65+ verified AWS IAM privilege escalation
paths in machine-readable YAML. This module fetches, parses, and converts them
to Atlas attack patterns for the attack graph builder.

Usage:
    patterns = load_pathfinding_patterns()
    # Returns list of dicts compatible with attack_patterns.yaml format
"""

from __future__ import annotations

import json
import re
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog
import yaml

from atlas.core.types import EdgeType

_DATA_DIR = Path(__file__).parent / "data"
_PATHFINDING_DIR = _DATA_DIR / "pathfinding"
_PATHFINDING_INDEX = _PATHFINDING_DIR / "paths_index.json"
_PATHFINDING_BASE = "https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main"

logger = structlog.get_logger(__name__)

# Mapping: pathfinding path id -> (Atlas edge_type, target_type, target_identity_type, target_role_key)
# target_type: account | identity | resource
# target_role_key: for resource targets that escalate to role (e.g. service_role_arn)
_PATHFINDING_TO_ATLAS: dict[str, tuple[str, str, str | None, str | None]] = {
    # IAM self-escalation & principal-access
    "iam-001": ("can_create_policy_version", "identity", "iam_policy", None),
    "iam-002": ("can_set_default_policy_version", "identity", "iam_policy", None),
    "iam-003": ("can_attach_policy", "identity", "iam_user", None),
    "iam-004": ("can_attach_policy", "identity", "iam_role", None),
    "iam-005": ("can_attach_policy", "identity", "iam_group", None),
    "iam-006": ("can_put_policy", "identity", "iam_user", None),
    "iam-007": ("can_put_policy", "identity", "iam_role", None),
    "iam-008": ("can_put_policy", "identity", "iam_group", None),
    "iam-009": ("can_create_key", "identity", "iam_user", None),
    "iam-010": ("can_modify_trust", "identity", "iam_role", None),
    "iam-011": ("can_create_login_profile", "identity", "iam_user", None),
    "iam-012": ("can_update_login_profile", "identity", "iam_user", None),
    "iam-013": ("can_add_user_to_group", "identity", "iam_group", None),
    "iam-014": ("can_create_admin_user", "account", None, None),
    "iam-015": ("can_create_backdoor_role", "account", None, None),
    "iam-016": ("can_delete_permissions_boundary", "identity", "iam_role", None),
    "iam-017": ("can_delete_permissions_boundary", "identity", "iam_user", None),
    "iam-018": ("can_put_permissions_boundary", "identity", "iam_role", None),
    "iam-019": ("can_put_permissions_boundary", "identity", "iam_user", None),
    "iam-020": ("can_delete_or_detach_policy", "identity", "iam_role", None),
    "iam-021": ("can_delete_or_detach_policy", "identity", "iam_user", None),
    # EC2
    "ec2-001": ("can_passrole_ec2", "identity", "iam_role", None),
    "ec2-002": ("can_read_userdata", "resource", None, None),
    "ec2-003": ("can_modify_userdata", "resource", None, None),
    "ec2-004": ("can_ec2_instance_connect", "resource", None, None),
    "ec2instanceconnect-003": ("can_ec2_instance_connect", "resource", None, None),
    # Lambda
    "lambda-001": ("can_passrole", "identity", "iam_role", None),
    "lambda-002": ("can_update_lambda", "resource", None, None),
    "lambda-003": ("can_update_lambda_config", "resource", None, None),
    "lambda-004": ("can_backdoor_lambda", "resource", None, None),
    "lambda-005": ("can_steal_lambda_creds", "resource", None, None),
    "lambda-006": ("can_passrole", "identity", "iam_role", None),
    # CloudFormation
    "cloudformation-001": ("can_passrole_cloudformation", "identity", "iam_role", None),
    "cloudformation-002": ("can_passrole_cloudformation", "identity", "iam_role", None),
    "cloudformation-003": ("has_access_to", "resource", None, None),
    "cloudformation-004": ("has_access_to", "resource", None, None),
    "cloudformation-005": ("has_access_to", "resource", None, None),
    # ECS
    "ecs-001": ("can_passrole_ecs", "identity", "iam_role", None),
    "ecs-002": ("can_steal_ecs_task_creds", "resource", None, None),
    "ecs-003": ("can_backdoor_ecs_task", "identity", "iam_role", None),
    "ecs-004": ("can_passrole_ecs", "identity", "iam_role", None),
    "ecs-005": ("can_passrole_ecs", "identity", "iam_role", None),
    "ecs-006": ("can_passrole_ecs", "identity", "iam_role", None),
    # Glue
    "glue-001": ("can_passrole_glue", "identity", "iam_role", None),
    "glue-002": ("can_update_glue_dev_endpoint", "resource", None, None),
    "glue-003": ("can_passrole_glue", "identity", "iam_role", None),
    "glue-004": ("can_passrole_glue", "identity", "iam_role", None),
    "glue-005": ("can_passrole_glue", "identity", "iam_role", None),
    "glue-006": ("can_passrole_glue", "identity", "iam_role", None),
    # CodeBuild: 001=PassRole+CreateProject+StartBuild, 002=StartBuild override, 003=StartBuildBatch, 004=BatchGetProjects env
    "codebuild-001": ("can_passrole", "identity", "iam_role", None),
    "codebuild-002": ("has_access_to", "resource", None, "service_role_arn"),  # StartBuild+buildspec override
    "codebuild-003": ("has_access_to", "resource", None, "service_role_arn"),  # StartBuildBatch+override
    "codebuild-004": ("can_read_codebuild_env", "resource", None, "service_role_arn"),
    # SageMaker
    "sagemaker-001": ("can_modify_sagemaker_lifecycle", "resource", None, None),
    "sagemaker-002": ("can_passrole", "identity", "iam_role", None),
    "sagemaker-003": ("can_modify_sagemaker_lifecycle", "resource", None, None),
    "sagemaker-004": ("can_modify_sagemaker_lifecycle", "resource", None, None),
    "sagemaker-005": ("can_modify_sagemaker_lifecycle", "resource", None, None),
    # SSM
    "ssm-001": ("can_ssm_session", "resource", None, None),
    "ssm-002": ("can_enable_ssm_via_tags", "resource", None, None),
    # STS
    "sts-001": ("can_get_federation_token", "account", None, None),
    # DataPipeline
    "datapipeline-001": ("can_passrole", "identity", "iam_role", None),
    # Bedrock / BEDROCK-AGENTCORE
    "bedrock-001": ("can_passrole_agentcore", "identity", "iam_role", None),
    "bedrock-002": ("can_hijack_bedrock_agent", "resource", None, None),
    # AppRunner
    "apprunner-001": ("can_passrole", "identity", "iam_role", None),
    "apprunner-002": ("can_passrole", "identity", "iam_role", None),
}


def _fetch_pathfinding_index() -> list[dict[str, str]]:
    """Fetch the list of pathfinding YAML paths from GitHub."""
    try:
        url = f"{_PATHFINDING_BASE}/.github/paths-manifest.json"
        # Fallback: build from directory listing
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
            return data.get("paths", [])
    except Exception:
        pass

    # Build from known structure
    services = [
        "apprunner", "bedrock", "cloudformation", "codebuild", "datapipeline",
        "ec2", "ec2-instance-connect", "ecs", "glue", "iam", "lambda",
        "sagemaker", "ssm", "sts",
    ]
    paths = []
    for svc in services:
        try:
            api_url = f"https://api.github.com/repos/DataDog/pathfinding.cloud/contents/data/paths/{svc}"
            req = urllib.request.Request(api_url, headers={"Accept": "application/vnd.github.v3+json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                items = json.load(resp)
                for item in items:
                    if item.get("name", "").endswith(".yaml"):
                        path = f"data/paths/{svc}/{item['name']}"
                        paths.append({"path": path, "name": item["name"]})
        except Exception as e:
            logger.debug("pathfinding_fetch_service_failed", service=svc, error=str(e))
    return paths


def _extract_exploitation_commands(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract exploitation commands from awscli and pacu steps."""
    steps = []
    for tool in ("awscli", "pacu"):
        for item in raw.get("exploitationSteps", {}).get(tool, []):
            cmd = item.get("command", "")
            desc = item.get("description", "")
            step_num = item.get("step", len(steps) + 1)
            if cmd:
                steps.append({"tool": tool, "step": step_num, "command": cmd, "description": desc})
    return steps


def _extract_visualization_code(visualization: dict[str, Any] | None) -> list[str]:
    """Extract code blocks from attackVisualization node/edge descriptions."""
    if not visualization:
        return []
    code_blocks = []
    for node in visualization.get("nodes", []) + visualization.get("edges", []):
        desc = node.get("description", "") or ""
        # Match ```...``` code blocks
        for m in re.finditer(r"```(?:\w+)?\s*\n(.*?)```", desc, re.DOTALL):
            block = m.group(1).strip()
            if block and len(block) < 2000:  # Skip huge blocks
                code_blocks.append(block)
    return code_blocks[:5]  # Limit to 5 snippets


def _parse_pathfinding_yaml(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a single pathfinding YAML into Atlas pattern format (with full path data)."""
    path_id = raw.get("id")
    if not path_id:
        return None

    perms_raw = raw.get("permissions", {})
    perms = perms_raw.get("required", [])
    if not perms:
        return None

    required = []
    resource_constraints = []  # (permission, constraint) for required perms
    for p in perms:
        if isinstance(p, dict) and "permission" in p:
            required.append(p["permission"])
            if p.get("resourceConstraints"):
                resource_constraints.append((p["permission"], p["resourceConstraints"]))
        elif isinstance(p, str):
            required.append(p)

    # Additional permissions (helpful for recon, not required)
    additional_perms = []
    for p in perms_raw.get("additional", []):
        if isinstance(p, dict) and "permission" in p:
            additional_perms.append({
                "permission": p["permission"],
                "resourceConstraints": p.get("resourceConstraints", ""),
            })
        elif isinstance(p, str):
            additional_perms.append({"permission": p, "resourceConstraints": ""})

    if not required:
        return None

    mapping = _PATHFINDING_TO_ATLAS.get(path_id)
    if mapping:
        edge_type, target_type, target_identity_type, target_role_key = mapping
    else:
        # Auto-derive for unmapped paths: never skip a pathfinding path
        edge_type, target_type, target_identity_type, target_role_key = _derive_mapping_from_permissions(
            path_id, required, raw.get("services", [])
        )
        if not edge_type:
            return None

    # Validate edge_type exists in EdgeType enum
    try:
        EdgeType(edge_type)
    except ValueError:
        return None

    # Determine target_resource_type for resource targets
    target_resource_type = None
    if target_type == "resource":
        services = raw.get("services", [])
        if "ec2" in services or "ec2-instance-connect" in services:
            target_resource_type = "ec2_instance"
        elif "lambda" in services:
            target_resource_type = "lambda_function"
        elif "s3" in services:
            target_resource_type = "s3_bucket"
        elif "glue" in services:
            target_resource_type = "ec2_instance"  # Glue dev endpoint
        elif "codebuild" in services:
            target_resource_type = "codebuild_project"
        elif "sagemaker" in services:
            target_resource_type = "ec2_instance"
        elif "ssm" in services:
            target_resource_type = "ec2_instance"
        elif "bedrock" in services or "bedrock-agentcore" in services:
            target_resource_type = "bedrock_agent"
        elif "cloudformation" in services:
            target_resource_type = "cloudformation_stack"
        else:
            target_resource_type = "ec2_instance"  # Default for resource

    target_resolution = "self"
    if target_role_key or "passrole" in edge_type.lower() or "steal" in edge_type.lower() or "read_codebuild" in edge_type.lower():
        target_resolution = "role_arn"

    # Full pathfinding data for LLM grounding, CLI, and encyclopedia
    viz = raw.get("attackVisualization", {})
    exploitation_steps = _extract_exploitation_commands(raw)
    code_snippets = _extract_visualization_code(viz)

    return {
        "id": f"pathfinding_{path_id}",
        "edge_type": edge_type,
        "required_permissions": required,
        "target_type": target_type,
        "target_identity_type": target_identity_type,
        "target_resource_type": target_resource_type,
        "target_resolution": target_resolution,
        "target_role_key": target_role_key or "role_arn",
        "success_probability": 0.85,
        "notes": raw.get("description", "")[:200] + ("..." if len(raw.get("description", "")) > 200 else ""),
        "_pathfinding_id": path_id,
        "_pathfinding_name": raw.get("name", ""),
        "_pathfinding_category": raw.get("category", ""),
        "_pathfinding_services": raw.get("services", []),
        # Full pathfinding content
        "_pathfinding_description": raw.get("description", ""),
        "_pathfinding_prerequisites": raw.get("prerequisites", {}),
        "_pathfinding_recommendation": raw.get("recommendation", ""),
        "_pathfinding_references": raw.get("references", []),
        "_pathfinding_related_paths": raw.get("relatedPaths", []),
        "_pathfinding_exploitation_steps": exploitation_steps,
        "_pathfinding_code_snippets": code_snippets,
        "_pathfinding_attack_visualization": viz,
        "_pathfinding_learning_environments": raw.get("learningEnvironments", {}),
        "_pathfinding_detection_tools": raw.get("detectionTools", {}),
        "_pathfinding_limitations": raw.get("limitations", ""),
        "_pathfinding_discovery_attribution": raw.get("discoveryAttribution", {}),
        "_pathfinding_detection_rules": raw.get("detectionRules", []),
        "_pathfinding_resource_constraints": resource_constraints,
        "_pathfinding_additional_permissions": additional_perms,
    }


def _derive_mapping_from_permissions(
    path_id: str,
    required: list[str],
    services: list[str],
) -> tuple[str, str, str | None, str | None]:
    """Auto-derive Atlas mapping from pathfinding permissions when no explicit mapping exists."""
    req_set = set(required)
    # PassRole + service Create* -> can_passrole to role
    if "iam:PassRole" in req_set:
        for perm in req_set:
            if perm != "iam:PassRole" and ":" in perm:
                return ("can_passrole", "identity", "iam_role", None)
    # codebuild:StartBuild / StartBuildBatch -> has_access_to codebuild_project
    if "codebuild:StartBuild" in req_set or "codebuild:StartBuildBatch" in req_set:
        return ("has_access_to", "resource", None, "service_role_arn")
    # codebuild:BatchGetProjects -> can_read_codebuild_env
    if "codebuild:BatchGetProjects" in req_set:
        return ("can_read_codebuild_env", "resource", None, "service_role_arn")
    # Fallback: has_access_to for resource-based paths
    if services and "iam" not in services:
        return ("has_access_to", "resource", None, None)
    return ("", "", None, None)  # Skip if we can't derive


def sync_pathfinding_data() -> Path:
    """Fetch pathfinding YAML files from GitHub and save locally.

    Returns the directory containing the synced data.
    """
    _PATHFINDING_DIR.mkdir(parents=True, exist_ok=True)

    # Use recursive tree to get all YAML paths
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/DataDog/pathfinding.cloud/git/trees/main?recursive=1",
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.load(resp)
            paths = [
                t["path"]
                for t in data.get("tree", [])
                if t["path"].startswith("data/paths/") and t["path"].endswith(".yaml")
            ]
    except Exception as e:
        logger.warning("pathfinding_fetch_tree_failed", error=str(e))
        paths = []

    index = []
    for rel_path in sorted(paths):
        try:
            url = f"{_PATHFINDING_BASE}/{rel_path}"
            req = urllib.request.Request(url, headers={"Accept": "text/plain"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw_yaml = resp.read().decode()
                data = yaml.safe_load(raw_yaml)
                if data:
                    local_path = _PATHFINDING_DIR / Path(rel_path).name
                    local_path.write_text(raw_yaml)
                    index.append({"path": rel_path, "id": data.get("id", "")})
        except Exception as e:
            logger.debug("pathfinding_fetch_file_failed", path=rel_path, error=str(e))

    (_PATHFINDING_DIR / "paths_index.json").write_text(json.dumps({"paths": index}, indent=2))
    load_pathfinding_patterns.cache_clear()
    logger.info("pathfinding_sync_complete", count=len(index))
    return _PATHFINDING_DIR


@lru_cache(maxsize=1)
def load_pathfinding_patterns() -> list[dict[str, Any]]:
    """Load pathfinding paths and convert to Atlas attack patterns.

    First checks for locally synced data. If missing, attempts to sync from GitHub.
    Returns patterns compatible with load_attack_patterns() format.
    """
    patterns = []
    yaml_files = list(_PATHFINDING_DIR.glob("*.yaml")) if _PATHFINDING_DIR.exists() else []

    if not yaml_files:
        # Try to sync
        try:
            sync_pathfinding_data()
            yaml_files = list(_PATHFINDING_DIR.glob("*.yaml"))
        except Exception as e:
            logger.debug("pathfinding_sync_failed", error=str(e))
            return []

    for yf in yaml_files:
        try:
            raw = yaml.safe_load(yf.read_text())
            if not raw:
                continue
            converted = _parse_pathfinding_yaml(raw)
            if converted:
                patterns.append(converted)
        except Exception as e:
            logger.debug("pathfinding_parse_failed", file=str(yf), error=str(e))

    return patterns


def get_pathfinding_path(path_id: str) -> dict[str, Any] | None:
    """Get full pathfinding path data by path_id (e.g. 'iam-001', 'lambda-001')."""
    patterns = load_pathfinding_patterns()
    for p in patterns:
        if p.get("_pathfinding_id") == path_id:
            return p
    return None


def load_pathfinding_full() -> list[dict[str, Any]]:
    """Load all pathfinding paths with full content (description, exploitation steps, etc.)."""
    return load_pathfinding_patterns()


def get_pathfinding_context_for_llm(
    edge_type: str | None = None,
    permissions: list[str] | None = None,
    limit: int = 5,
    include_commands: bool = True,
) -> str:
    """Get pathfinding path descriptions for LLM grounding.

    Returns a string of relevant pathfinding path descriptions to include
    in LLM prompts. Matches by edge_type or by permissions overlap.
    When neither is provided, returns a sample of common paths.
    Includes exploitation commands and code snippets when include_commands=True.
    """
    patterns = load_pathfinding_patterns()
    if not patterns:
        return ""

    relevant = []
    if edge_type or permissions:
        for p in patterns:
            if edge_type and p.get("edge_type") == edge_type:
                relevant.append(p)
            elif permissions:
                req = set(p.get("required_permissions", []))
                if req and req.issubset(set(permissions)):
                    relevant.append(p)
    if not relevant:
        # No match: return sample of high-value paths for general context
        priority_ids = ("iam-001", "iam-009", "ec2-001", "lambda-001", "iam-010")
        for pid in priority_ids:
            for p in patterns:
                if p.get("_pathfinding_id") == pid:
                    relevant.append(p)
                    break
        if not relevant:
            relevant = patterns[:limit]

    lines = ["## Verified attack paths (pathfinding.cloud):"]
    for p in relevant[:limit]:
        name = p.get("_pathfinding_name", p.get("id", ""))
        desc = p.get("_pathfinding_description", p.get("notes", ""))[:150]
        perms = ", ".join(p.get("required_permissions", [])[:5])
        lines.append(f"- **{name}**: {desc} (requires: {perms})")
        limitations = p.get("_pathfinding_limitations", "")
        if limitations:
            lines.append(f"  Limitations: {limitations[:120]}{'...' if len(limitations) > 120 else ''}")
        if include_commands:
            steps = p.get("_pathfinding_exploitation_steps", [])
            if steps:
                awscli_steps = [s for s in steps if s.get("tool") == "awscli"][:3]
                for s in awscli_steps:
                    cmd = s.get("command", "").strip()
                    if cmd:
                        lines.append(f"  Command: `{cmd[:120]}{'...' if len(cmd) > 120 else ''}`")
            code_lines = p.get("_pathfinding_code_snippets", [])[:2]
            for c in code_lines:
                lines.append(f"  Code: `{c[:100]}{'...' if len(c) > 100 else ''}`")
    return "\n".join(lines)
