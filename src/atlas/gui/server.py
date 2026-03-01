"""
atlas.gui.server
~~~~~~~~~~~~~~~~
HTTP server for the k8scout-style web UI.
Serves static files and provides /api/case/<name> for case data.
"""

from __future__ import annotations

import asyncio
import json
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from atlas.gui.export_report import export_case_to_report


def _run_explain(case_name: str, path_id: str, api_key: str, model: str = "gpt-4o-mini") -> str:
    """Generate AI explanation for an attack path."""
    from atlas.core.cases import load_case
    from atlas.planner.chain_finder import ChainFinder
    from atlas.planner.attack_graph import AttackGraph
    from atlas.planner.explainer import AttackPathExplainer
    from atlas.gui.export_report import _is_excluded_identity

    case_data = load_case(case_name)
    attack_edges = case_data["attack_edges"]
    source_identity = case_data.get("source_identity", "")
    env_model = case_data["env_model"]

    ag = AttackGraph()
    for e in attack_edges:
        ag.add_edge(e)
    finder = ChainFinder(ag, max_depth=4, max_chains=50)
    chains = finder.find_chains(source_identity)

    def _chain_has_excluded(c):
        if _is_excluded_identity(c.source_arn):
            return True
        for e in c.edges:
            if _is_excluded_identity(e.target_arn):
                return True
        return False

    chains = [c for c in chains if not _chain_has_excluded(c)]

    ap_key = path_id.upper()
    chain = next((c for i, c in enumerate(chains) if f"AP-{i + 1:02d}" == ap_key), None)
    if not chain or not chain.edges:
        return "Attack path not found."

    explainer = AttackPathExplainer()
    if api_key:
        import os
        os.environ["OPENAI_API_KEY"] = api_key
        explainer._api_key = api_key

    edge = chain.edges[0]
    source_info = {"type": "unknown"}
    target_info = {"type": "unknown"}
    if env_model.graph.has_node(edge.target_arn):
        target_info.update(env_model.graph.get_node_data(edge.target_arn))

    def _get_policies(arn: str) -> list[str]:
        policies = []
        for target_arn, edge_data in env_model.graph.outgoing(arn):
            if edge_data.get("edge_type") == "has_policy":
                policies.append(target_arn.split("/")[-1])
        return policies[:5]

    source_policies = _get_policies(edge.source_arn)
    target_policies = _get_policies(edge.target_arn)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(
            explainer.explain(edge, source_info, target_info, source_policies, target_policies, model=model)
        )
    finally:
        loop.close()


def _get_web_dir() -> Path:
    """Return the web/ directory (alongside this module)."""
    return Path(__file__).resolve().parent / "web"


class AtlasGUIHandler(SimpleHTTPRequestHandler):
    """Request handler that serves web/ and /api/case/<name>."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.web_dir = _get_web_dir()
        super().__init__(*args, directory=str(self.web_dir), **kwargs)

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/cases":
            try:
                from atlas.core.cases import list_cases
                cases = list_cases()
                self._send_json({"cases": [c.get("name", "") for c in cases if c.get("name")]})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if path.startswith("/api/case/"):
            case_name = path.split("/api/case/", 1)[-1].strip("/")
            if case_name:
                try:
                    report = export_case_to_report(case_name)
                    self._send_json(report)
                    return
                except FileNotFoundError as e:
                    self.send_error(404, str(e))
                    return
                except Exception as e:
                    self.send_error(500, str(e))
                    return

        if path == "/" or path == "/index.html" or path == "":
            path = "/graph.html"

        self.path = path
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/explain":
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len)
                data = json.loads(body) if body else {}
                case_name = data.get("case_name", "")
                path_id = data.get("path_id", "")
                api_key = data.get("api_key", "")
                model = data.get("model", "gpt-4o-mini")
                if not case_name or not path_id:
                    self._send_json({"error": "case_name and path_id required"}, 400)
                    return
                result = _run_explain(case_name, path_id, api_key, model=model)
                self._send_json({"explanation": result})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return
        self.send_error(404)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default logging."""
        pass


def run_server(port: int = 8050, open_browser: bool = True, case_name: str | None = None) -> None:
    """Run the Atlas GUI server."""
    web_dir = _get_web_dir()
    if not web_dir.exists():
        raise FileNotFoundError(f"Web directory not found: {web_dir}")

    server = HTTPServer(("127.0.0.1", port), AtlasGUIHandler)
    url = f"http://127.0.0.1:{port}/graph.html"
    if case_name:
        url += f"?case={case_name}"

    print(f"Atlas GUI: {url}")
    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        print("\nServer stopped.")
