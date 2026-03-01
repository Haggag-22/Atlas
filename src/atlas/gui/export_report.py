"""
atlas.gui.export_report
~~~~~~~~~~~~~~~~~~~~~~~
Export Atlas case data to JSON format for the k8scout-style web UI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from atlas.core.cases import load_case
from atlas.core.models import AttackEdge
from atlas.planner.attack_graph import AttackGraph
from atlas.planner.chain_finder import ChainFinder


# Edge type -> severity for derived findings
_EDGE_SEVERITY: dict[str, str] = {
    "can_assume": "CRITICAL",
    "can_create_key": "CRITICAL",
    "can_modify_trust": "CRITICAL",
    "can_attach_policy": "CRITICAL",
    "can_put_policy": "CRITICAL",
    "can_create_admin_user": "CRITICAL",
    "can_create_backdoor_role": "CRITICAL",
    "can_steal_imds_creds": "CRITICAL",
    "can_stop_cloudtrail": "CRITICAL",
    "can_delete_cloudtrail": "CRITICAL",
    "can_passrole": "HIGH",
    "can_passrole_ec2": "HIGH",
    "can_passrole_ecs": "HIGH",
    "can_update_lambda": "HIGH",
    "can_backdoor_lambda": "HIGH",
    "can_read_s3": "MEDIUM",
    "can_write_s3": "MEDIUM",
    "can_read_userdata": "HIGH",
    "can_ssm_session": "HIGH",
    "can_get_ec2_password_data": "HIGH",
    "can_ec2_instance_connect": "HIGH",
    "can_ec2_serial_console_ssh": "HIGH",
    "can_snapshot_volume": "MEDIUM",
    "can_access_via_resource_policy": "MEDIUM",
    "can_self_signup_cognito": "HIGH",
    "can_takeover_cloudfront_origin": "HIGH",
    "can_get_federation_token": "CRITICAL",
    "can_create_roles_anywhere_persistence": "CRITICAL",
    "can_create_rogue_oidc_persistence": "CRITICAL",
    "can_assume_via_oidc_misconfig": "HIGH",
    "can_obtain_creds_via_cognito_identity_pool": "HIGH",
    "can_hijack_bedrock_agent": "HIGH",
    "can_enable_ssm_via_tags": "HIGH",
    "can_backdoor_ecs_task": "HIGH",
    "can_steal_lambda_creds": "HIGH",
    "can_steal_ecs_task_creds": "HIGH",
    "can_read_codebuild_env": "HIGH",
    "can_read_beanstalk_env": "HIGH",
    "can_pivot_via_beanstalk_creds": "HIGH",
    "can_modify_userdata": "HIGH",
    "can_update_lambda_config": "HIGH",
    "can_modify_sagemaker_lifecycle": "HIGH",
    "can_create_eks_access_entry": "HIGH",
    "can_add_user_to_group": "HIGH",
    "can_create_policy_version": "HIGH",
    "can_set_default_policy_version": "HIGH",
    "can_delete_or_detach_policy": "HIGH",
    "can_delete_permissions_boundary": "HIGH",
    "can_put_permissions_boundary": "HIGH",
    "can_create_eventbridge_rule": "MEDIUM",
    "can_modify_guardduty_detector": "CRITICAL",
    "can_modify_guardduty_ip_trust_list": "HIGH",
    "can_stop_cloudtrail": "CRITICAL",
    "can_delete_cloudtrail": "CRITICAL",
    "can_update_cloudtrail_config": "HIGH",
    "can_modify_cloudtrail_bucket_lifecycle": "HIGH",
    "can_modify_cloudtrail_event_selectors": "HIGH",
    "can_delete_dns_logs": "HIGH",
    "can_leave_organization": "CRITICAL",
    "can_remove_vpc_flow_logs": "HIGH",
    "can_enumerate_ses": "LOW",
    "can_open_security_group_ingress": "HIGH",
    "can_share_ami": "MEDIUM",
    "can_share_ebs_snapshot": "MEDIUM",
    "can_share_rds_snapshot": "MEDIUM",
    "can_invoke_bedrock_model": "LOW",
    "can_access_efs_from_ec2": "MEDIUM",
    "can_modify_s3_acl_persistence": "HIGH",
    "can_create_codebuild_github_runner": "HIGH",
}
_DEFAULT_SEVERITY = "MEDIUM"

# Node type -> display kind
_NODE_KIND: dict[str, str] = {
    "iam_user": "User",
    "iam_role": "Role",
    "iam_group": "Group",
    "iam_policy": "Policy",
    "s3_bucket": "S3",
    "ec2_instance": "EC2",
    "lambda_function": "Lambda",
    "rds_instance": "RDS",
    "kms_key": "KMS",
    "secrets_manager": "Secret",
    "ssm_parameter": "SSM",
    "cloudformation_stack": "CFN",
    "backup_plan": "Backup",
    "ebs_snapshot": "EBS",
    "ecs_task_definition": "ECS",
    "efs_file_system": "EFS",
    "ecr_repository": "ECR",
    "cognito_user_pool": "Cognito",
    "cognito_identity_pool": "Cognito",
    "cloudfront_distribution": "CloudFront",
    "codebuild_project": "CodeBuild",
    "elasticbeanstalk_environment": "Beanstalk",
    "bedrock_agent": "Bedrock",
    "account": "Account",
    "credential": "Credential",
}
_DEFAULT_KIND = "Resource"


def _short_name(arn: str, max_len: int = 35) -> str:
    name = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
    if len(name) > max_len:
        name = name[: max_len - 3] + "..."
    return name


def _arn_to_kind(arn: str, node_type: str | None) -> str:
    if node_type:
        return _NODE_KIND.get(node_type, _DEFAULT_KIND)
    if ":user/" in arn:
        return "User"
    if ":role/" in arn:
        return "Role"
    if ":group/" in arn:
        return "Group"
    if ":policy/" in arn:
        return "Policy"
    if "s3:::" in arn or ":s3:" in arn:
        return "S3"
    if ":function:" in arn:
        return "Lambda"
    if ":instance/" in arn and ":role/" not in arn:
        return "EC2"
    if ":db:" in arn or "rds" in arn.lower():
        return "RDS"
    if ":key/" in arn:
        return "KMS"
    if ":secret:" in arn:
        return "Secret"
    if ":parameter" in arn:
        return "SSM"
    if ":stack/" in arn:
        return "CFN"
    return _DEFAULT_KIND


def _edge_risk_score(edge_type: str) -> float:
    sev = _EDGE_SEVERITY.get(edge_type, _DEFAULT_SEVERITY)
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(sev, 5.0)


def _is_service_role(arn: str) -> bool:
    if "/aws-service-role/" in arn:
        return True
    name = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
    return name.startswith("AWSServiceRoleFor") if name else False


def export_case_to_report(case_name: str) -> dict[str, Any]:
    """Convert Atlas case data to the web UI report format."""
    case_data = load_case(case_name)
    env_model = case_data["env_model"]
    attack_edges: list[AttackEdge] = case_data["attack_edges"]
    source_identity = case_data.get("source_identity", "") or env_model.metadata.caller_arn
    case_meta = case_data.get("case_meta", {})

    # Build attack chains
    ag = AttackGraph()
    for edge in attack_edges:
        ag.add_edge(edge)
    finder = ChainFinder(ag, max_depth=4, max_chains=50)
    chains = finder.find_chains(source_identity)

    # Collect all node ARNs from edges + graph
    node_arns: set[str] = set()
    for e in attack_edges:
        node_arns.add(e.source_arn)
        node_arns.add(e.target_arn)
    node_arns.add(source_identity)

    # Build graph nodes from env_model.graph
    node_by_id: dict[str, dict] = {}
    for nid, attrs in env_model.graph.raw.nodes(data=True):
        node_type = attrs.get("node_type", "")
        label = attrs.get("label", _short_name(nid))
        node_by_id[nid] = {
            "id": nid,
            "name": label,
            "kind": _arn_to_kind(nid, node_type),
            "arn": nid,
            "node_type": node_type,
            "risk_score": 0.0,
            "data": attrs.get("data", {}),
        }

    # Add any ARNs from edges not in graph
    for arn in node_arns:
        if arn not in node_by_id:
            node_by_id[arn] = {
                "id": arn,
                "name": _short_name(arn),
                "kind": _arn_to_kind(arn, None),
                "arn": arn,
                "node_type": "",
                "risk_score": 0.0,
                "data": {},
            }

    # Compute risk scores from edges (max incoming/outgoing)
    for e in attack_edges:
        score = _edge_risk_score(e.edge_type.value)
        for arn in (e.source_arn, e.target_arn):
            if arn in node_by_id:
                node_by_id[arn]["risk_score"] = max(
                    node_by_id[arn]["risk_score"], score
                )

    # Mark source identity
    if source_identity in node_by_id:
        node_by_id[source_identity]["is_source"] = True

    nodes = list(node_by_id.values())

    # Build graph edges (from attack_edges, exclude structural)
    structural = {"has_policy", "has_inline_policy", "has_permission_boundary"}
    edges = []
    for e in attack_edges:
        if e.edge_type.value in structural:
            continue
        if _is_service_role(e.source_arn) or _is_service_role(e.target_arn):
            continue
        edges.append({
            "source": e.source_arn,
            "target": e.target_arn,
            "kind": e.edge_type.value,
            "api_actions": e.api_actions or [],
            "detection_cost": e.detection_cost,
            "success_probability": e.success_probability,
            "notes": e.notes or "",
        })

    # Risk findings: from env_model.findings + derived from high-risk edges
    findings = []
    for f in getattr(env_model, "findings", []) or []:
        fd = f.model_dump() if hasattr(f, "model_dump") else dict(f)
        sev = str(fd.get("severity", "MEDIUM")).upper().replace(" ", "_")
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev = "MEDIUM"
        findings.append({
            "rule_id": fd.get("finding_id", "FINDING"),
            "severity": sev,
            "score": {"CRITICAL": 10, "HIGH": 7.5, "MEDIUM": 5, "LOW": 2.5}.get(sev, 5),
            "title": fd.get("title", ""),
            "description": fd.get("description", ""),
            "remediation": fd.get("remediation", ""),
            "affected_nodes": [fd.get("resource_arn", "")],
            "evidence": fd.get("details", {}),
        })

    # Derive findings from critical/high edges
    seen_edge_findings: set[str] = set()
    for e in attack_edges:
        if e.edge_type.value in structural:
            continue
        sev = _EDGE_SEVERITY.get(e.edge_type.value, _DEFAULT_SEVERITY)
        if sev not in ("CRITICAL", "HIGH"):
            continue
        key = f"{e.edge_type.value}:{e.source_arn}:{e.target_arn}"
        if key in seen_edge_findings:
            continue
        seen_edge_findings.add(key)
        action_name = e.edge_type.value.replace("_", " ").title()
        findings.append({
            "rule_id": f"EDGE-{e.edge_type.value.upper()}",
            "severity": sev,
            "score": _edge_risk_score(e.edge_type.value),
            "title": f"Identity can {action_name}",
            "description": f"From {_short_name(e.source_arn)} to {_short_name(e.target_arn)}. "
            + (e.notes or ""),
            "remediation": "Apply least-privilege. Remove unnecessary permissions.",
            "affected_nodes": [e.source_arn, e.target_arn],
            "evidence": {"api_actions": e.api_actions, "edge_type": e.edge_type.value},
        })

    # Attack paths
    attack_paths = []
    for i, chain in enumerate(chains):
        path_nodes = [chain.source_arn]
        path_edges = []
        for edge in chain.edges:
            path_nodes.append(edge.target_arn)
            path_edges.append(edge.edge_type.value)
        attack_paths.append({
            "id": f"AP-{i + 1:02d}",
            "nodes": path_nodes,
            "edges": path_edges,
            "hop_count": chain.hop_count,
            "summary": chain.summary_text,
            "detection_cost": chain.total_detection_cost,
            "success_probability": chain.total_success_probability,
            "chain": chain.model_dump() if hasattr(chain, "model_dump") else {},
        })

    return {
        "meta": {
            "tool": "atlas",
            "version": "2.0",
            "case": case_name,
            "account_id": case_meta.get("account_id", env_model.metadata.account_id),
            "region": case_meta.get("region", env_model.metadata.region),
            "source_identity": source_identity,
            "timestamp": case_meta.get("created_at", ""),
        },
        "identity": {
            "username": source_identity,
            "arn": source_identity,
        },
        "graph": {"nodes": nodes, "edges": edges},
        "risk_findings": findings,
        "attack_paths": attack_paths,
        "raw": {
            "attack_edges": [e.model_dump() for e in attack_edges],
            "chains": [c.model_dump() for c in chains],
        },
    }


def export_report_to_file(case_name: str, out_path: str | Path) -> Path:
    """Export case to a JSON file for the web UI."""
    report = export_case_to_report(case_name)
    path = Path(out_path)
    path.write_text(json.dumps(report, indent=2, default=str))
    return path
