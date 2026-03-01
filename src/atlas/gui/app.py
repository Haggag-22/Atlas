"""
atlas.gui.app
~~~~~~~~~~~~~
BloodHound-style GUI for Atlas — query-first, graph visualization, path analysis.
"""

from __future__ import annotations

import asyncio
import csv
import html
import io
import sys
from typing import Any

import streamlit as st

from atlas.core.cases import load_case, list_cases, load_explanation, save_explanation
from atlas.core.models import AttackChain, AttackEdge
from atlas.core.types import EdgeType
from atlas.knowledge.api_profiles import load_attack_patterns
from atlas.planner.attack_graph import AttackGraph
from atlas.planner.chain_finder import ChainFinder
from atlas.query.engine import QueryEngine

# Structural edges to exclude from graph (add noise, not attack steps)
_STRUCTURAL_EDGE_TYPES = frozenset({"has_policy", "has_inline_policy", "has_permission_boundary"})
# Low-impact techniques to exclude — focus on critical/dangerous paths
_NOISE_EDGE_TYPES = frozenset({"can_decode_key"})  # Access Key Account Decode
# IAM users to exclude (login/management accounts that add noise)
_EXCLUDED_IDENTITIES = frozenset({"mac_hacker", "windows_hacker", "hacker_role"})


def _is_excluded_identity(arn: str) -> bool:
    """True if ARN is an excluded identity (e.g. mac_hacker, windows_hacker, hacker_role)."""
    if not arn:
        return False
    name = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
    return name in _EXCLUDED_IDENTITIES


def _is_service_role_arn(arn: str) -> bool:
    """True if ARN is an AWS service role (noise for user-deployed resources)."""
    if "/aws-service-role/" in arn:
        return True
    name = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
    if name.startswith("AWSServiceRoleFor"):
        return True
    return False

# BloodHound-style edge colors by type (danger level)
_EDGE_COLORS: dict[str, str] = {
    "can_assume": "#ef4444",
    "can_create_key": "#f97316",
    "can_attach_policy": "#f97316",
    "can_put_policy": "#f97316",
    "can_modify_trust": "#ef4444",
    "can_passrole": "#eab308",
    "can_passrole_ec2": "#eab308",
    "can_passrole_ecs": "#eab308",
    "can_update_lambda": "#22c55e",
    "can_read_s3": "#3b82f6",
    "can_write_s3": "#3b82f6",
    "can_steal_imds_creds": "#ef4444",
    "can_ssm_session": "#eab308",
    "can_stop_cloudtrail": "#ef4444",
    "can_delete_cloudtrail": "#ef4444",
    "has_policy": "#64748b",
    "trusts": "#94a3b8",
}
_DEFAULT_EDGE_COLOR = "#64748b"  # slate

# Node colors by type (BloodHound-style)
_NODE_COLORS: dict[str, str] = {
    "user": "#60a5fa",
    "role": "#4ade80",
    "group": "#a78bfa",
    "root": "#fbbf24",
    "policy": "#64748b",
    "s3": "#38bdf8",
    "lambda": "#34d399",
    "ec2": "#f472b6",
    "default": "#94a3b8",
}

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
    "assume_role": "Assume Role",
    "create_access_key": "Create Access Key",
    "attach_policy": "Attach Policy",
    "put_inline_policy": "Put Inline Policy",
    "passrole_lambda": "PassRole + Lambda",
    "modify_trust_policy": "Modify Trust Policy",
    "update_lambda_code": "Update Lambda Code",
    "read_s3": "Read S3 Bucket",
    "write_s3": "Write S3 Bucket",
    "read_userdata": "Read EC2 User Data",
    "enum_backup": "Enumerate Backup Service",
    "decode_key_account": "Decode Key Account ID",
    "loot_public_snapshot": "Loot Public EBS Snapshot",
    "can_passrole_ec2": "PassRole + EC2",
    "can_passrole_ecs": "PassRole + ECS",
    "can_update_lambda_config": "Lambda Config Update",
    "can_steal_imds_creds": "IMDS Credential Theft",
    "can_ssm_session": "SSM Session",
    "can_snapshot_volume": "EC2 Volume Snapshot",
    "can_modify_userdata": "EC2 UserData Injection",
    "can_steal_lambda_creds": "Lambda Credential Theft",
    "can_steal_ecs_task_creds": "ECS Task Credential Theft",
    "can_read_codebuild_env": "CodeBuild Env Theft",
    "can_read_beanstalk_env": "Beanstalk Env Theft",
    "can_pivot_via_beanstalk_creds": "Beanstalk Credential Pivot",
    "can_hijack_bedrock_agent": "Bedrock Agent Hijacking",
    "can_access_via_resource_policy": "Resource Policy Misconfig",
    "can_assume_via_oidc_misconfig": "OIDC Trust Abuse",
    "can_self_signup_cognito": "Cognito Self-Signup",
    "can_takeover_cloudfront_origin": "CloudFront Takeover",
    "can_get_ec2_password_data": "EC2 Get Password Data",
    "can_ec2_instance_connect": "EC2 Instance Connect",
    "can_ec2_serial_console_ssh": "EC2 Serial Console",
    "can_open_security_group_ingress": "Open Security Group",
    "can_share_ami": "Share AMI",
    "can_share_ebs_snapshot": "Share EBS Snapshot",
    "can_share_rds_snapshot": "Share RDS Snapshot",
    "can_invoke_bedrock_model": "Bedrock InvokeModel",
    "can_delete_dns_logs": "Delete DNS Logs",
    "can_leave_organization": "Leave Organization",
    "can_remove_vpc_flow_logs": "Remove VPC Flow Logs",
    "can_enumerate_ses": "Enumerate SES",
    "can_modify_sagemaker_lifecycle": "SageMaker Lifecycle",
    "can_create_eks_access_entry": "EKS Create Access Entry",
    "can_create_admin_user": "Create Admin User",
    "can_create_backdoor_role": "Create Backdoor Role",
    "can_backdoor_lambda": "Lambda Backdoor",
    "can_stop_cloudtrail": "CloudTrail Stop",
    "can_delete_cloudtrail": "CloudTrail Delete",
    "can_update_cloudtrail_config": "CloudTrail Config Update",
    "can_modify_cloudtrail_bucket_lifecycle": "CloudTrail Bucket Lifecycle",
    "can_modify_cloudtrail_event_selectors": "CloudTrail Event Selectors",
    "can_get_federation_token": "GetFederationToken",
    "can_create_roles_anywhere_persistence": "Roles Anywhere Persistence",
    "can_obtain_creds_via_cognito_identity_pool": "Cognito Identity Pool Creds",
    "can_backdoor_ecs_task": "ECS Task Definition Backdoor",
    "can_enable_ssm_via_tags": "SSM via CreateTags",
    "can_access_efs_from_ec2": "EFS Access from EC2",
}


def _action_name(edge_type: str) -> str:
    return _ACTION_NAMES.get(edge_type, edge_type.replace("_", " ").title())


def _download_csv(rows: list[dict[str, Any]], filename: str, key_suffix: str = "") -> None:
    """Render a download button for CSV export."""
    if not rows:
        return
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    st.download_button("📥 Export CSV", buf.getvalue(), filename, mime="text/csv", key=f"dl_{key_suffix}")


def _short_name(arn: str, max_len: int = 35) -> str:
    name = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
    if len(name) > max_len:
        name = name[: max_len - 3] + "..."
    return name


def _arn_type(arn: str) -> str:
    if ":user/" in arn:
        return "User"
    if ":role/" in arn:
        return "Role"
    if ":group/" in arn:
        return "Group"
    if ":policy/" in arn:
        return "Policy"
    if "s3:::" in arn or ":s3:" in arn:
        return "S3 Bucket"
    if ":function:" in arn:
        return "Lambda"
    if ":instance/" in arn:
        return "EC2 Instance"
    return "Other"


def _node_color(arn: str, is_source: bool = False, is_highlighted: bool = False) -> str:
    """BloodHound-style node color by type."""
    if is_highlighted:
        return "#fbbf24"  # amber highlight
    if is_source:
        return "#4ade80"  # green source
    if ":root" in arn:
        return _NODE_COLORS["root"]
    if ":user/" in arn:
        return _NODE_COLORS["user"]
    if ":role/" in arn:
        return _NODE_COLORS["role"]
    if ":group/" in arn:
        return _NODE_COLORS["group"]
    if ":policy/" in arn:
        return _NODE_COLORS["policy"]
    if "s3:::" in arn or ":s3:" in arn:
        return _NODE_COLORS["s3"]
    if ":function:" in arn:
        return _NODE_COLORS["lambda"]
    if ":instance/" in arn:
        return _NODE_COLORS["ec2"]
    return _NODE_COLORS["default"]


def _build_path_map(
    attack_edges: list[AttackEdge],
    source_identity: str,
) -> tuple[dict[str, Any], list[AttackChain]]:
    """Build chain map from saved edges."""
    ag = AttackGraph()
    for edge in attack_edges:
        ag.add_edge(edge)

    finder = ChainFinder(ag, max_depth=4, max_chains=50)
    chains = finder.find_chains(source_identity)

    # Exclude chains that start from or pass through excluded identities
    def _chain_has_excluded(chain: AttackChain) -> bool:
        if _is_excluded_identity(chain.source_arn):
            return True
        for edge in chain.edges:
            if _is_excluded_identity(edge.target_arn):
                return True
        return False

    chains = [c for c in chains if not _chain_has_excluded(c)]

    path_map: dict[str, Any] = {}
    for i, chain in enumerate(chains):
        path_map[f"AP-{i + 1:02d}"] = chain

    return path_map, chains


def _chain_viz_text(chain: AttackChain, path_id: str = "") -> str:
    """Return ASCII chain visualization as string."""
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

    def _box(txt: str, indent: str = "  ") -> str:
        content_w = max(len(txt), 8)
        pad = "─" * (content_w + 2)
        return f"{indent}┌{pad}┐\n{indent}│ {txt:<{content_w}} │\n{indent}└{pad}┘"

    lines = []
    title = f"Chain {path_id}" if path_id else "Attack Chain"
    lines.append(f"  {title}\n")
    lines.append(_box(nodes[0]) + "\n")
    for i, label in enumerate(edge_labels):
        lines.append("       │\n")
        lines.append(f"       │  {label}\n")
        lines.append("       ▼\n")
        lines.append(_box(nodes[i + 1]) + "\n")

    return "".join(lines)


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
            policies.append({"name": inline_name, "arn": "", "type": "Inline"})

    return policies


def _get_resource_policy(arn: str, env_model: Any) -> tuple[str, dict | None]:
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


def _parse_cli_case() -> str | None:
    """Parse --case <name> from sys.argv (from atlas gui --case X)."""
    args = sys.argv[1:] if len(sys.argv) > 1 else []
    for i, a in enumerate(args):
        if a == "--case" and i + 1 < len(args):
            return args[i + 1]
    return None


def _generate_multi_hop_explanation(chain: AttackChain) -> str:
    """Build template explanation for multi-hop chains."""
    lines = [f"This is a {chain.hop_count}-step attack chain:", chain.summary_text, ""]
    for i, edge in enumerate(chain.edges):
        action_name = _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value)
        lines.append(f"Step {i+1}: {action_name}")
        lines.append(f"  From: {_short_name(edge.source_arn)}")
        lines.append(f"  To:   {_short_name(edge.target_arn)}")
        lines.append(f"  API:  {', '.join(edge.api_actions)}")
        lines.append(f"  Cost: {edge.detection_cost:.4f}  |  Success: {edge.success_probability:.0%}")
        if edge.notes:
            lines.append(f"  Note: {edge.notes}")
        lines.append("")
    total_text = f"Total detection cost: {chain.total_detection_cost:.4f}, "
    total_text += f"Combined success probability: {chain.total_success_probability:.0%}"
    lines.append(total_text)
    return "\n".join(lines)


async def _generate_single_hop_explanation(
    edge: Any,
    env_model: Any,
) -> str:
    """Generate AI or template explanation for single-hop path."""
    from atlas.planner.explainer import AttackPathExplainer

    explainer = AttackPathExplainer()
    source_info = {"type": _arn_type(edge.source_arn)}
    target_info = {"type": _arn_type(edge.target_arn)}
    if env_model.graph.has_node(edge.target_arn):
        target_info.update(env_model.graph.get_node_data(edge.target_arn))

    source_policies = [p["name"] for p in _get_identity_policies(edge.source_arn, env_model)]
    target_policies = [p["name"] for p in _get_identity_policies(edge.target_arn, env_model)]

    return await explainer.explain(
        edge, source_info, target_info,
        source_policies, target_policies,
    )


def _build_attack_context(
    chain: AttackChain,
    env_model: Any,
    explanation: str | None,
) -> str:
    """Build context string for AI Q&A about this attack path."""
    import json

    lines = [
        "ATTACK PATH CONTEXT",
        "=" * 40,
        f"Chain: {chain.summary_text}",
        f"Hops: {chain.hop_count}",
        f"Total detection cost: {chain.total_detection_cost:.4f}",
        f"Combined success probability: {chain.total_success_probability:.0%}",
        "",
        "STEPS:",
    ]
    for i, edge in enumerate(chain.edges):
        action = _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value)
        lines.append(f"  Step {i+1}: {action}")
        lines.append(f"    From: {_short_name(edge.source_arn)} ({_arn_type(edge.source_arn)})")
        lines.append(f"    To:   {_short_name(edge.target_arn)} ({_arn_type(edge.target_arn)})")
        lines.append(f"    API:  {', '.join(edge.api_actions)}")
        lines.append(f"    Cost: {edge.detection_cost:.4f}  |  Success: {edge.success_probability:.0%}")
        if edge.notes:
            lines.append(f"    Note: {edge.notes}")
        lines.append("")

    # Source policies
    source_policies = _get_identity_policies(chain.source_arn, env_model)
    if source_policies:
        lines.append(f"Source policies ({_short_name(chain.source_arn)}):")
        for p in source_policies:
            lines.append(f"  - {p['name']} ({p['type']})")
        lines.append("")

    # Final target policies
    target_policies = _get_identity_policies(chain.final_target_arn, env_model)
    if target_policies:
        lines.append(f"Target policies ({_short_name(chain.final_target_arn)}):")
        for p in target_policies:
            lines.append(f"  - {p['name']} ({p['type']})")
        lines.append("")

    # Resource policy (trust or bucket) - truncated
    label, resource_policy = _get_resource_policy(chain.final_target_arn, env_model)
    if label and resource_policy:
        lines.append(f"{label}:")
        lines.append(json.dumps(resource_policy, indent=2, default=str)[:1500])
        if len(json.dumps(resource_policy, default=str)) > 1500:
            lines.append("  ... (truncated)")
        lines.append("")

    if explanation:
        lines.append("EXPLANATION:")
        lines.append(explanation[:2000])
        if len(explanation) > 2000:
            lines.append("  ... (truncated)")

    return "\n".join(lines)


async def _ask_ai_about_path(
    question: str,
    context: str,
    chat_history: list[dict[str, str]],
    api_key: str,
) -> str:
    """Call OpenAI to answer a question about the attack path."""
    try:
        import openai
    except ImportError:
        return "Install the `openai` package to enable Q&A: `pip install openai`"

    client = openai.AsyncOpenAI(api_key=api_key)

    system_prompt = (
        "You are an expert AWS cloud security analyst. The user is viewing an attack path "
        "in Atlas and has questions about it. Use ONLY the provided context to answer. "
        "Be concise, technical, and practical. If the question is outside the context, "
        "say so and suggest what they might look at. Keep answers under 200 words unless "
        "the user asks for more detail."
    )

    messages = [{"role": "system", "content": f"{system_prompt}\n\nCONTEXT:\n{context}"}]
    for msg in chat_history[-10:]:  # Last 10 turns for context
        messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": question})

    response = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.3,
        max_tokens=500,
    )

    return response.choices[0].message.content or "No response generated."


def _filter_graph_edges(
    attack_edges: list[AttackEdge],
    *,
    path_edges: list[tuple[str, str]] | None = None,
    focus_nodes: set[str] | None = None,
    exclude_structural: bool = True,
    exclude_service_roles: bool = True,
) -> list[AttackEdge]:
    """Return edges to show — simplified for readability."""
    path_set = {(a, b) for a, b in (path_edges or [])}
    focus = focus_nodes or set()

    def _keep_edge(e: AttackEdge) -> bool:
        if e.edge_type.value in _NOISE_EDGE_TYPES:
            return False
        if _is_excluded_identity(e.source_arn) or _is_excluded_identity(e.target_arn):
            return False
        if exclude_service_roles:
            if _is_service_role_arn(e.source_arn) or _is_service_role_arn(e.target_arn):
                return False
        return True

    edges = attack_edges
    if path_set:
        edges = [e for e in edges if (e.source_arn, e.target_arn) in path_set]
    elif focus and len(focus) <= 20:
        edges = [e for e in edges if e.source_arn in focus and e.target_arn in focus]
    elif exclude_structural:
        edges = [e for e in edges if e.edge_type.value not in _STRUCTURAL_EDGE_TYPES]
    edges = [e for e in edges if _keep_edge(e)]
    return edges


def _render_pyvis_graph(
    attack_edges: list[AttackEdge],
    source_identity: str,
    *,
    highlight_nodes: set[str] | None = None,
    highlight_edges: list[tuple[str, str]] | None = None,
) -> str:
    """Build BloodHound-style interactive attack graph using pyvis."""
    try:
        from pyvis.network import Network
    except ImportError:
        return ""

    highlight_nodes = highlight_nodes or set()
    highlight_edges_set = set()
    if highlight_edges:
        highlight_edges_set = {(a, b) for a, b in highlight_edges}

    net = Network(
        height="600px",
        width="100%",
        bgcolor="#1a1d24",
        font_color="#e2e8f0",
        directed=True,
    )
    node_count = len({arn for e in attack_edges for arn in (e.source_arn, e.target_arn)})
    # Tune physics: more nodes = stronger repulsion, longer springs
    spring_len = min(180, 80 + node_count)
    grav = -120 - node_count * 2

    net.set_options(f"""
    var options = {{
      "nodes": {{
        "font": {{"size": 11, "color": "#e2e8f0"}},
        "borderWidth": 2,
        "shadow": false
      }},
      "edges": {{
        "arrows": {{"to": {{"enabled": true}}}},
        "smooth": {{"type": "continuous"}},
        "width": 1.2
      }},
      "physics": {{
        "enabled": true,
        "solver": "forceAtlas2Based",
        "forceAtlas2Based": {{
          "gravitationalConstant": {grav},
          "springLength": {spring_len},
          "springConstant": 0.08,
          "damping": 0.4,
          "avoidOverlap": 0.5
        }}
      }}
    }}
    """)

    seen: set[str] = set()
    base_size = 18 if node_count > 25 else 22
    hl_size = 24 if node_count > 25 else 28
    label_len = 20 if node_count > 30 else 28
    for e in attack_edges:
        for arn in (e.source_arn, e.target_arn):
            if arn not in seen:
                seen.add(arn)
                label = _short_name(arn, max_len=label_len)
                is_source = arn == source_identity
                is_hl = arn in highlight_nodes
                color = _node_color(arn, is_source=is_source, is_highlighted=is_hl)
                size = hl_size if (is_source or is_hl) else base_size
                net.add_node(
                    arn,
                    label=html.escape(label),
                    color=color,
                    size=size,
                    borderWidth=3 if is_hl else 2,
                    borderWidthSelected=4,
                )
        edge_color = _EDGE_COLORS.get(e.edge_type.value, _DEFAULT_EDGE_COLOR)
        is_hl_edge = (e.source_arn, e.target_arn) in highlight_edges_set
        if is_hl_edge:
            edge_color = "#fbbf24"
        label = _action_name(e.edge_type.value)
        net.add_edge(
            e.source_arn,
            e.target_arn,
            title=html.escape(label),
            color=edge_color,
            width=3 if is_hl_edge else 1.5,
        )

    return net.generate_html()


def main() -> None:
    st.set_page_config(page_title="Atlas", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

    # Deprecation notice — new k8scout-style GUI is the default
    st.error(
        "**Deprecated:** This is the old Streamlit GUI. Use the new k8scout-style interface instead: "
        "run `atlas gui` in your terminal (port 8050). Close this tab and run `atlas gui`."
    )
    st.markdown("""
    <style>
    .stApp { background: linear-gradient(180deg, #0a0d12 0%, #0f1419 50%, #0a0d12 100%); }
    [data-testid="stMetricValue"] { color: #4ade80; font-weight: 600; }
    [data-testid="stSidebar"] { min-width: 280px !important; }
    .stSidebar { background: linear-gradient(180deg, #131820 0%, #0a0d12 100%); }
    .stSidebar .stSelectbox label, .stSidebar label { color: #94a3b8 !important; white-space: normal !important; }
    .stSidebar [data-testid="stMarkdown"] { overflow: visible !important; }
    h1, h2, h3 { color: #e2e8f0 !important; }
    div[data-testid="stExpander"] { background: rgba(26, 31, 38, 0.8); border-radius: 8px; border: 1px solid #334155; }
    .stDataFrame { border-radius: 8px; overflow: hidden; }
    </style>
    """, unsafe_allow_html=True)
    st.title("🛡️ Atlas — Attack Path Explorer")

    case_from_cli = _parse_cli_case()
    all_cases = list_cases()

    if not all_cases:
        st.error("No saved cases found. Run `atlas plan --case <name>` first.")
        st.info("Then run `atlas gui --case <name>` to view attack paths.")
        return

    case_names = [c.get("name", "?") for c in all_cases]
    if case_from_cli and case_from_cli in case_names:
        default_idx = case_names.index(case_from_cli)
    else:
        default_idx = 0

    case_name = st.sidebar.selectbox(
        "Case",
        options=case_names,
        index=default_idx,
        key="case_select",
    )

    try:
        case_data = load_case(case_name)
    except FileNotFoundError as e:
        st.error(str(e))
        return

    env_model = case_data["env_model"]
    attack_edges = case_data["attack_edges"]
    source_identity = case_data["source_identity"]
    case_meta = case_data["case_meta"]

    path_map, chains = _build_path_map(attack_edges, source_identity)
    principals = (
        {e.source_arn for e in attack_edges}
        | {e.target_arn for e in attack_edges}
        | {source_identity}
    )
    principals_sorted = sorted(principals, key=lambda a: (_short_name(a), a))

    if not path_map:
        st.warning("No attack paths found for this case.")
        return

    # --- Top stats bar ---
    quietest = min(chains, key=lambda c: c.total_detection_cost)
    max_hops = max(c.hop_count for c in chains)
    st.markdown("---")
    stat_col1, stat_col2, stat_col3, stat_col4, stat_col5 = st.columns(5)
    with stat_col1:
        st.metric("Attack paths", len(chains), help="Total discovered paths")
    with stat_col2:
        st.metric("Source", _short_name(source_identity, max_len=18), help="Starting identity")
    with stat_col3:
        st.metric("Max hops", max_hops, help="Longest path length")
    with stat_col4:
        st.metric("Quietest cost", f"{quietest.total_detection_cost:.4f}", help="Lowest detection cost path")
    with stat_col5:
        st.metric("Account", case_meta.get("account_id", "—")[:12], help="AWS account ID")
    st.markdown("---")

    # --- BloodHound-style query sidebar (dropdown) ---
    st.sidebar.divider()
    st.sidebar.subheader("Queries")
    query_options = [
        ("shortest", "Shortest path to admin"),
        ("who_admin", "Who can reach admin"),
        ("blast", "Blast radius"),
        ("external", "External trusts"),
        ("wildcards", "Wildcard permissions"),
        ("privileged", "Privileged principals"),
    ]
    query_labels = {q[0]: q[1] for q in query_options}
    query_id = st.sidebar.selectbox(
        "Query",
        options=[q[0] for q in query_options],
        format_func=lambda x: query_labels.get(x, x),
        key="query_select",
    )

    principal_for_blast = source_identity
    if query_id == "blast":
        default_idx = principals_sorted.index(source_identity) if source_identity in principals_sorted else 0
        principal_for_blast = st.sidebar.selectbox(
            "From principal",
            options=principals_sorted,
            format_func=_short_name,
            index=default_idx,
            key="blast_principal",
        )

    simple_graph = st.sidebar.checkbox(
        "Simple graph",
        value=True,
        help="Show only attack paths (hide policy links). Uncheck for full graph.",
        key="simple_graph",
    )

    api_key_from_env = __import__("os").environ.get("OPENAI_API_KEY", "")
    api_key_override = st.sidebar.text_input(
        "OpenAI API key",
        type="password",
        placeholder="sk-...",
        key="api_key_input",
    )
    api_key = api_key_from_env or (api_key_override or "")

    # --- Run query ---
    engine = QueryEngine.from_case(case_name)
    query_result: dict[str, Any] | None = None
    highlight_nodes: set[str] = set()
    highlight_edges: list[tuple[str, str]] = []

    if query_id == "shortest":
        query_result = engine.shortest_path_to_admin()
        if query_result:
            highlight_nodes = set(query_result.get("path_nodes", []))
            highlight_edges = query_result.get("path_edges", [])
    elif query_id == "who_admin":
        rows = engine.who_can_reach_admin()
        query_result = {"results": rows}
        if rows:
            first = rows[0]
            highlight_nodes = set(first.get("path_nodes", []))
            highlight_edges = first.get("path_edges", [])
    elif query_id == "blast":
        rows = engine.blast_radius(principal_for_blast)
        query_result = {"principal": principal_for_blast, "results": rows}
        # Only highlight when few targets — otherwise graph becomes unreadable yellow blob
        if len(rows) <= 12:
            highlight_nodes = {principal_for_blast} | {r["target"] for r in rows}
        else:
            highlight_nodes = {principal_for_blast}  # Just highlight source
    elif query_id == "external":
        rows = engine.external_trusts()
        query_result = {"results": rows}
    elif query_id == "wildcards":
        rows = engine.wildcard_permissions()
        query_result = {"results": rows}
    elif query_id == "privileged":
        rows = engine.privileged_unused_principals()
        query_result = {"results": rows}

    # --- Simplify graph for readability ---
    path_edges_for_filter = highlight_edges if (query_id in ("shortest", "who_admin") and highlight_edges) else None
    focus_for_filter = highlight_nodes if (query_id == "blast" and 1 < len(highlight_nodes) <= 20) else None
    graph_edges = _filter_graph_edges(
        attack_edges,
        path_edges=path_edges_for_filter,
        focus_nodes=focus_for_filter,
        exclude_structural=simple_graph,
        exclude_service_roles=True,
    )
    if not graph_edges:
        graph_edges = _filter_graph_edges(
            attack_edges, exclude_structural=simple_graph, exclude_service_roles=True
        )

    # --- Main: Graph (prominent) + Query results ---
    st.subheader("Attack graph")
    if len(graph_edges) < len(attack_edges):
        st.caption(f"Showing {len(graph_edges)} edges (simplified from {len(attack_edges)})")
    html_graph = _render_pyvis_graph(
        graph_edges,
        source_identity,
        highlight_nodes=highlight_nodes if highlight_nodes else None,
        highlight_edges=highlight_edges if highlight_edges else None,
    )
    if html_graph:
        st.components.v1.html(html_graph, height=650, scrolling=True)
    else:
        st.info("Install `pyvis` to enable interactive graph: `pip install pyvis`")

    st.divider()
    query_label = query_labels.get(query_id, query_id)
    st.subheader(f"📋 Query results — {query_label}")
    with st.container():
        if query_result:
            if query_id == "shortest":
                r = query_result
                st.metric("Path", r.get("path_summary", "—"))
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Hops", r.get("hops", "—"))
                with col2:
                    st.metric("Detection cost", r.get("detection_cost", "—"))
                with col3:
                    st.metric("Success", f"{r.get('success_probability', 0):.0%}")
            elif query_id == "who_admin":
                rows = query_result.get("results", [])
                if rows:
                    st.metric("Principals", len(rows), help="Can reach admin")
                    df_data = [{"Source": _short_name(r["source"]), "Path": r.get("path_summary", ""), "Hops": r["hops"], "Cost": r["detection_cost"]} for r in rows]
                    st.dataframe(df_data, use_container_width=True, hide_index=True)
                    _download_csv(df_data, f"who_can_reach_admin_{case_name}.csv", key_suffix="who_admin")
                else:
                    st.caption("No principals can reach admin.")
            elif query_id == "blast":
                rows = query_result.get("results", [])
                st.caption(f"From: {_short_name(query_result.get('principal', ''))}")
                if rows:
                    st.metric("Reachable", len(rows), help="Targets within max depth")
                    df_data = [{"Target": _short_name(r["target"]), "Hops": r["hops"], "Cost": r["detection_cost"], "Success": f"{r['success_probability']:.0%}"} for r in rows]
                    st.dataframe(df_data, use_container_width=True, hide_index=True)
                    _download_csv(df_data, f"blast_radius_{case_name}.csv", key_suffix="blast")
                else:
                    st.caption("No reachable targets.")
            elif query_id == "external":
                rows = query_result.get("results", [])
                if rows:
                    st.metric("Roles", len(rows), help="With external trust")
                    df_data = [{"Role": _short_name(r["role_arn"]), "Principal": r.get("principal", "—")} for r in rows]
                    st.dataframe(df_data, use_container_width=True, hide_index=True)
                    _download_csv(df_data, f"external_trusts_{case_name}.csv", key_suffix="external")
                else:
                    st.caption("No external trusts found.")
            elif query_id == "wildcards":
                rows = query_result.get("results", [])
                if rows:
                    st.metric("Identities", len(rows), help="With wildcard perms")
                    df_data = [{"Identity": _short_name(r["identity"]), "Type": r.get("type", "—"), "Source": r.get("source", "—")} for r in rows]
                    st.dataframe(df_data, use_container_width=True, hide_index=True)
                    _download_csv(df_data, f"wildcards_{case_name}.csv", key_suffix="wildcards")
                else:
                    st.caption("No wildcard permissions found.")
            elif query_id == "privileged":
                rows = query_result.get("results", [])
                if rows:
                    st.metric("Principals", len(rows), help="With escalation perms")
                    df_data = [{"Identity": _short_name(r["identity"]), "Last used": r.get("last_used", "—"), "Note": r.get("note", "—")} for r in rows]
                    st.dataframe(df_data, use_container_width=True, hide_index=True)
                    _download_csv(df_data, f"privileged_principals_{case_name}.csv", key_suffix="privileged")
                else:
                    st.caption("No privileged principals found.")
        else:
            st.caption("Select a query to see results.")

    # --- Tabs for paths, permissions, patterns (collapsed) ---
    with st.expander("Attack paths & details", expanded=False):
        path_options = [(pid, f"{pid}: {chain.summary_text}") for pid, chain in path_map.items()]
        path_id = st.selectbox(
            "Select attack path",
            options=[p[0] for p in path_options],
            format_func=lambda x: next(l for pid, l in path_options if pid == x),
            key="path_select",
        )
        selected_chain = path_map[path_id]

    # Tab: Attack Paths (existing content)
    with st.expander("Path details", expanded=False):
        st.subheader(f"Chain {path_id}")
        st.code(_chain_viz_text(selected_chain, path_id), language=None)

        # Details
        if selected_chain.hop_count == 1:
            edge = selected_chain.edges[0]
            st.subheader("Path details")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Attack type", _action_name(edge.edge_type.value))
                st.metric("Source", _short_name(edge.source_arn))
                st.metric("Target", _short_name(edge.target_arn))
                st.metric("Target type", _arn_type(edge.target_arn))
            with col2:
                st.metric("Detection cost", f"{edge.detection_cost:.4f}")
                st.metric("Success probability", f"{edge.success_probability:.0%}")
                st.metric("Guardrail status", edge.guardrail_status.title())
                st.metric("API actions", ", ".join(edge.api_actions) if edge.api_actions else "—")
            if edge.notes:
                st.caption("Notes")
                st.text(edge.notes)

            st.subheader(f"Policies — {_short_name(edge.source_arn)} (Source)")
            source_policies = _get_identity_policies(edge.source_arn, env_model)
            if source_policies:
                st.dataframe(
                    [{"Policy": p["name"], "Type": p["type"]} for p in source_policies],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.caption("None")

            st.subheader(f"Policies — {_short_name(edge.target_arn)} (Target)")
            target_policies = _get_identity_policies(edge.target_arn, env_model)
            if target_policies:
                st.dataframe(
                    [{"Policy": p["name"], "Type": p["type"]} for p in target_policies],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.caption("None")

            label, resource_policy = _get_resource_policy(edge.target_arn, env_model)
            if label and resource_policy:
                st.subheader(f"{label} — {_short_name(edge.target_arn)}")
                st.json(resource_policy)
        else:
            # Multi-hop
            st.subheader("Chain summary")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Chain", selected_chain.summary_text)
                st.metric("Final target", _short_name(selected_chain.final_target_arn))
                st.metric("Final target type", _arn_type(selected_chain.final_target_arn))
            with col2:
                st.metric("Total detection cost", f"{selected_chain.total_detection_cost:.4f}")
                st.metric("Combined success", f"{selected_chain.total_success_probability:.0%}")

            st.subheader("Chain steps")
            steps_data = []
            for i, edge in enumerate(selected_chain.edges):
                steps_data.append({
                    "Hop": i + 1,
                    "Action": _action_name(edge.edge_type.value),
                    "From": _short_name(edge.source_arn),
                    "To": _short_name(edge.target_arn),
                    "Cost": f"{edge.detection_cost:.4f}",
                    "Success": f"{edge.success_probability:.0%}",
                })
            st.dataframe(steps_data, use_container_width=True, hide_index=True)

            st.subheader(f"Policies — {_short_name(selected_chain.source_arn)} (Source)")
            source_policies = _get_identity_policies(selected_chain.source_arn, env_model)
            if source_policies:
                st.dataframe(
                    [{"Policy": p["name"], "Type": p["type"]} for p in source_policies],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.caption("None")

            st.subheader(f"Policies — {_short_name(selected_chain.final_target_arn)} (Final target)")
            target_policies = _get_identity_policies(selected_chain.final_target_arn, env_model)
            if target_policies:
                st.dataframe(
                    [{"Policy": p["name"], "Type": p["type"]} for p in target_policies],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.caption("None")

            label, resource_policy = _get_resource_policy(selected_chain.final_target_arn, env_model)
            if label and resource_policy:
                st.subheader(f"{label} — {_short_name(selected_chain.final_target_arn)}")
                st.json(resource_policy)

        st.divider()
        st.subheader("Explanation")
        ap_key = path_id.upper()
        cached = load_explanation(case_name, ap_key)
        if cached:
            st.caption("(cached)")
            st.markdown(cached)
            explanation_text = cached
        else:
            with st.spinner("Generating explanation..."):
                if selected_chain.hop_count == 1:
                    explanation_text = asyncio.run(
                        _generate_single_hop_explanation(selected_chain.edges[0], env_model)
                    )
                else:
                    explanation_text = _generate_multi_hop_explanation(selected_chain)
                save_explanation(case_name, ap_key, explanation_text)
            st.markdown(explanation_text)

        st.divider()
        st.subheader("Ask about this attack path")
        if not api_key:
            st.info("Set `OPENAI_API_KEY` in your environment, or paste your key above to enable Q&A.")
        else:
            chat_key = f"chat_{case_name}_{path_id}"
            if chat_key not in st.session_state:
                st.session_state[chat_key] = []

            for msg in st.session_state[chat_key]:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

            if prompt := st.chat_input("Ask a question about this attack path..."):
                st.session_state[chat_key].append({"role": "user", "content": prompt})
                with st.chat_message("user"):
                    st.markdown(prompt)

                with st.chat_message("assistant"):
                    with st.spinner("Thinking..."):
                        context = _build_attack_context(
                            selected_chain, env_model, explanation_text
                        )
                        reply = asyncio.run(
                            _ask_ai_about_path(
                                prompt, context, st.session_state[chat_key][:-1], api_key
                            )
                        )
                    st.markdown(reply)
                st.session_state[chat_key].append({"role": "assistant", "content": reply})
                st.rerun()

            if st.session_state[chat_key]:
                if st.button("Clear chat", key=f"clear_{chat_key}"):
                    st.session_state[chat_key] = []
                    st.rerun()

    # Permissions & pattern registry (collapsed)
    with st.expander("Permission matrix", expanded=False):
        techniques: dict[str, set[str]] = {}
        for e in attack_edges:
            src = _short_name(e.source_arn)
            tech = _action_name(e.edge_type.value)
            techniques.setdefault(src, set()).add(tech)
        rows = []
        for src in sorted(techniques.keys()):
            for tech in sorted(techniques[src]):
                rows.append({"Identity": src, "Technique": tech})
        if rows:
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.caption("No permission data.")

    with st.expander("Attack pattern registry", expanded=False):
        patterns = load_attack_patterns()
        filter_svc = st.text_input("Filter by service or permission", key="pattern_filter")
        pattern_rows = []
        for p in patterns:
            perms = ", ".join(p.get("required_permissions", []))
            if filter_svc and filter_svc.lower() not in (perms + p.get("id", "")).lower():
                continue
            pattern_rows.append({
                "ID": p.get("id", ""),
                "Edge type": p.get("edge_type", ""),
                "Permissions": perms,
                "Target": p.get("target_type", ""),
                "Success": f"{p.get('success_probability', 0) * 100:.0f}%",
                "Notes": (p.get("notes", "") or "")[:60],
            })
        if pattern_rows:
            st.dataframe(pattern_rows, use_container_width=True, hide_index=True)
        else:
            st.caption("No patterns match filter.")

    # Sidebar metadata
    with st.sidebar:
        st.caption("Case metadata")
        st.markdown(f"""
**Acct:** `{case_meta.get("account_id", "?")}`  
**Identity:** `{_short_name(source_identity, max_len=22)}`  
**Output:** `output/{case_name}/`
""")
        st.divider()
        st.caption("Q&A / AI")
        if api_key_from_env:
            st.success("API key: from env")
        elif api_key_override:
            st.success("API key: from input")
        else:
            st.warning("API key: not set")


if __name__ == "__main__":
    main()
