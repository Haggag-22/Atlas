"""
atlas.gui.app
~~~~~~~~~~~~~
Streamlit GUI for Atlas — view attack paths and chain details.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import streamlit as st

from atlas.core.cases import load_case, list_cases, load_explanation, save_explanation
from atlas.core.models import AttackChain, AttackEdge
from atlas.core.types import EdgeType
from atlas.planner.attack_graph import AttackGraph
from atlas.planner.chain_finder import ChainFinder

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
}


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
    if "s3:::" in arn or ":s3:" in arn:
        return "S3 Bucket"
    if ":function:" in arn:
        return "Lambda"
    if ":instance/" in arn:
        return "EC2 Instance"
    return "Other"


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


def main() -> None:
    st.set_page_config(page_title="Atlas", page_icon="🛡️", layout="wide")
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

    case_name = st.selectbox(
        "Select case",
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

    if not path_map:
        st.warning("No attack paths found for this case.")
        return

    # Build dropdown options: "AP-01: user → role" etc.
    path_options = []
    for pid, chain in path_map.items():
        label = f"{pid}: {chain.summary_text}"
        path_options.append((pid, label))

    path_id = st.selectbox(
        "Select attack path",
        options=[p[0] for p in path_options],
        format_func=lambda x: next(l for pid, l in path_options if pid == x),
        key="path_select",
    )

    selected_chain = path_map[path_id]

    st.divider()

    # Chain visualization
    st.subheader(f"Chain {path_id}")
    st.code(_chain_viz_text(selected_chain, path_id), language=None)

    # Details
    if selected_chain.hop_count == 1:
        edge = selected_chain.edges[0]
        st.subheader("Path details")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Attack type", _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value))
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

        # Policies
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
                "Action": _ACTION_NAMES.get(edge.edge_type.value, edge.edge_type.value),
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

    # Explanation section
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

    # Q&A section
    st.divider()
    st.subheader("Ask about this attack path")
    api_key_from_env = __import__("os").environ.get("OPENAI_API_KEY", "")
    api_key_override = st.text_input(
        "OpenAI API key (optional — used if env var not set)",
        type="password",
        placeholder="sk-...",
        key="api_key_input",
        help="Paste your key here if OPENAI_API_KEY isn't inherited by the GUI.",
    )
    api_key = api_key_from_env or (api_key_override or "")
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

    # Sidebar metadata
    with st.sidebar:
        st.caption("Case metadata")
        st.write("**Account**", case_meta.get("account_id", "?"))
        st.write("**Identity**", source_identity.split("/")[-1])
        st.write("**Output**", f"output/{case_name}/")
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
