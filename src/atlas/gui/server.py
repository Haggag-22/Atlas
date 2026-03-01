"""
atlas.gui.server
~~~~~~~~~~~~~~~~
HTTP server for the k8scout-style web UI.
Serves static files and provides /api/case/<name> for case data.
"""

from __future__ import annotations

import json
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from atlas.gui.export_report import export_case_to_report


def _get_web_dir() -> Path:
    """Return the web/ directory (alongside this module)."""
    return Path(__file__).resolve().parent / "web"


class AtlasGUIHandler(SimpleHTTPRequestHandler):
    """Request handler that serves web/ and /api/case/<name>."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.web_dir = _get_web_dir()
        super().__init__(*args, directory=str(self.web_dir), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path.startswith("/api/case/"):
            case_name = path.split("/api/case/", 1)[-1].strip("/")
            if case_name:
                try:
                    report = export_case_to_report(case_name)
                    body = json.dumps(report, default=str).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
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
