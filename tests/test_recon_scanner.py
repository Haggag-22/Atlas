"""Tests for recon scanner."""

import tempfile
from pathlib import Path

import pytest

from atlas.recon.scanner import ReconFinding, ReconScanner


def test_scan_file_empty() -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("no secrets here\n")
        path = Path(f.name)
    try:
        scanner = ReconScanner()
        findings = scanner.scan_path(path)
        assert isinstance(findings, list)
    finally:
        path.unlink(missing_ok=True)


def test_scan_file_with_pattern() -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tf", delete=False) as f:
        f.write('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')
        path = Path(f.name)
    try:
        scanner = ReconScanner()
        findings = scanner.scan_path(path)
        assert len(findings) >= 1
        assert any(getattr(f, "finding_type", "") == "leaked_secret" for f in findings)
    finally:
        path.unlink(missing_ok=True)


def test_recon_finding_model() -> None:
    f = ReconFinding(finding_type="misconfig", category="s3_public", path="/foo/bar", severity="high")
    assert f.finding_type == "misconfig"
    assert f.path == "/foo/bar"
    assert f.model_dump()
