"""Scan local paths and Git repos for leaked secrets and misconfig patterns."""

import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ReconFinding(BaseModel):
    """Normalized finding from recon scan."""

    finding_type: str = Field(..., description="e.g. leaked_secret, misconfig")
    category: str = Field("", description="e.g. aws_key, terraform_tfvars")
    path: str = ""
    line_number: int | None = None
    snippet: str = ""
    severity: str = "medium"
    normalized_input: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured data to feed campaign (e.g. region, key type).",
    )


# Patterns: name, regex, category, severity
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "aws_access_key",
        re.compile(r"(?:AKIA|AIDA)[A-Z0-9]{16}"),
        "aws_key",
        "high",
    ),
    (
        "aws_secret_key_like",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        "aws_secret",
        "high",
    ),
    (
        "generic_secret_assign",
        re.compile(r"(?i)(?:secret|password|api_key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"),
        "generic_secret",
        "medium",
    ),
]

MISCONFIG_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "s3_public_acl",
        re.compile(r"PublicRead|acl.*public", re.IGNORECASE),
        "s3_public",
    ),
    (
        "wildcard_principal",
        re.compile(r"['\"]Principal['\"]\s*:\s*['\"]\*['\"]|Principal.*AWS.*\*"),
        "iam_wildcard",
    ),
    (
        "wildcard_action",
        re.compile(r"['\"]Action['\"]\s*:\s*['\"]\*['\"]"),
        "iam_wildcard_action",
    ),
]


class ReconScanner:
    """Scans provided paths (local dirs / Git repos) for secrets and misconfigs."""

    def __init__(
        self,
        exclude_patterns: list[str] | None = None,
        max_file_size: int = 1_000_000,
    ) -> None:
        self.exclude_patterns = exclude_patterns or [
            "*.pyc", ".git/*", "node_modules/*", "__pycache__/*"
        ]
        self.max_file_size = max_file_size

    def _should_skip(self, path: Path) -> bool:
        try:
            if path.is_dir():
                return True
            if path.stat().st_size > self.max_file_size:
                return True
            path_str = str(path)
            parts = path.parts
            for pat in self.exclude_patterns:
                normalized = pat.replace("/*", "").strip("/")
                if normalized in parts or normalized in path_str:
                    return True
                if path.match(pat):
                    return True
        except OSError:
            return True
        return False

    def scan_path(self, root: Path) -> list[ReconFinding]:
        """Scan a single path (file or directory)."""
        findings: list[ReconFinding] = []
        if root.is_file():
            findings.extend(self._scan_file(root))
            return findings
        for path in root.rglob("*"):
            if self._should_skip(path):
                continue
            findings.extend(self._scan_file(path))
        return findings

    def _scan_file(self, path: Path) -> list[ReconFinding]:
        findings: list[ReconFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings
        path_str = str(path)
        for name, pattern, category, severity in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                line_num = text[: m.start()].count("\n") + 1
                snippet = text[max(0, m.start() - 20) : m.end() + 20].replace("\n", " ")
                norm: dict[str, Any] = {
                    "pattern_name": name,
                    "category": category,
                }
                if "aws" in name.lower():
                    norm["hint"] = "aws_credentials"
                findings.append(
                    ReconFinding(
                        finding_type="leaked_secret",
                        category=category,
                        path=path_str,
                        line_number=line_num,
                        snippet=snippet,
                        severity=severity,
                        normalized_input=norm,
                    )
                )
        for name, pattern, category in MISCONFIG_PATTERNS:
            for m in pattern.finditer(text):
                line_num = text[: m.start()].count("\n") + 1
                snippet = text[max(0, m.start() - 30) : m.end() + 30].replace("\n", " ")
                findings.append(
                    ReconFinding(
                        finding_type="misconfig",
                        category=category,
                        path=path_str,
                        line_number=line_num,
                        snippet=snippet,
                        severity="medium",
                        normalized_input={"pattern_name": name, "category": category},
                    )
                )
        return findings
