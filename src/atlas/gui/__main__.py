"""
Run the Atlas GUI: python -m atlas.gui
This launches the k8scout-style web UI (port 8050), not Streamlit.
"""
from __future__ import annotations

from atlas.core.cases import list_cases
from atlas.gui.server import run_server

if __name__ == "__main__":
    all_cases = list_cases()
    if not all_cases:
        print("No saved cases found. Run: atlas plan --case <name>")
        raise SystemExit(1)
    case = all_cases[0].get("name", "")
    run_server(port=8050, open_browser=True, case_name=case)
