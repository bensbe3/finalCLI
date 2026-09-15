"""
scanners/secrets_scanner.py — hardcoded secrets, via Gitleaks.

RECEIVES:  "*" — every collected file. That is the routing contract
           WORKING, not a hole: every scanner gets exactly what it
           declared, and this one declared everything.
PRODUCES:  list[Finding] with the secret value MASKED — a real secret
           is never copied into the report or stored on a Finding
CALLED BY: main.py, through the Scanner contract

Gitleaks walks the target directory itself, so the shared exclude list
reaches it as a generated native config (allowlisted paths) — see
excludes.gitleaks_config_path(). Its JSON report is written into the
report dir, which is itself excluded, so the tool can never flag its
own output on a re-scan.
"""

from __future__ import annotations

import json
from pathlib import Path

from models import Finding, Severity
from scanners.base import (
    Scanner,
    ScannerFailed,
    capture_snippet,
    describe_failure,
    relative_posix,
    run_tool,
)


class SecretsScanner(Scanner):
    label = "Secrets scan (Gitleaks)"
    scan_type = "secrets"
    file_types = {"*"}
    tool_cmd = "gitleaks"

    def run(self, files: list[Path], target: Path, excludes) -> list[Finding]:
        # Gitleaks walks the whole target itself, so it does not expose a
        # count directly comparable with the router's selected-file count.
        self.last_files_scanned = None
        self.last_warnings = []
        if self.skip_if_unavailable():
            return []
        if not files:
            print(f"  {self.label}: no files collected - nothing to do")
            return []

        report_json = excludes.report_dir / "gitleaks_findings.json"
        # Never let output from an earlier run masquerade as the result of
        # this run if Gitleaks fails before replacing its report.
        try:
            report_json.unlink(missing_ok=True)
        except OSError as error:
            raise ScannerFailed(
                f"could not remove the previous gitleaks report: {error}")
        argv = [
            self.tool_cmd, "dir", str(target),
            "--config", str(excludes.gitleaks_config_path()),
            "--report-format", "json",
            "--report-path", str(report_json),
            "--redact",          # gitleaks itself never records the value
            "--exit-code", "0",  # findings are results, not an error
            "--no-banner",
        ]
        result = run_tool(argv, timeout=300)
        if not report_json.is_file():
            # No report file means gitleaks did not complete. Returning an
            # empty list would read as "no secrets found".
            raise ScannerFailed(
                f"gitleaks produced no report ({describe_failure(result)})")

        try:
            leaks = json.loads(
                report_json.read_text(encoding="utf-8") or "[]")
        except (OSError, json.JSONDecodeError, TypeError) as error:
            raise ScannerFailed(
                f"gitleaks produced an unreadable report: {error}")

        findings = self.parse(leaks, target)
        if result.returncode != 0:
            raise ScannerFailed(
                f"gitleaks did not complete ({describe_failure(result)})",
                findings)
        return findings

    def parse(self, leaks: list[dict], target: Path) -> list[Finding]:
        """Turn Gitleaks' JSON into Findings with masked snippets."""
        # Secrets cluster together - a config file often holds several on
        # consecutive lines. Collect every secret location per file FIRST,
        # so each snippet can mask all of them, not just its own line.
        # Without this, the two lines of context around one masked secret
        # would print the neighbouring secrets in full.
        masks_by_file = collect_masks(leaks)

        findings: list[Finding] = []
        for leak in leaks:
            path = Path(leak.get("File", ""))
            line = int(leak.get("StartLine", 0))
            rule_id = leak.get("RuleID", "")

            findings.append(
                Finding(
                    file=relative_posix(path, target),
                    line=line,
                    rule_id=rule_id,
                    message=leak.get("Description", "Hardcoded secret detected"),
                    severity=Severity.HIGH,
                    # specific rules (aws-..., github-...) are strong signals;
                    # entropy-based "generic" rules need more manual triage
                    confidence="medium" if "generic" in rule_id else "high",
                    tool="gitleaks",
                    scan_type=self.scan_type,
                    cwe="CWE-798",
                    snippet=capture_snippet(
                        path, line, masks=masks_by_file.get(str(path), {})),
                )
            )
        return findings


def collect_masks(leaks: list[dict]) -> dict[str, dict[int, tuple[int, int]]]:
    """file -> {line: (start_col, end_col)} for every secret found.

    A leak with no usable columns is masked to the end of the line, which
    is the safe direction to be wrong in.
    """
    masks: dict[str, dict[int, tuple[int, int]]] = {}
    for leak in leaks:
        file_key = str(Path(leak.get("File", "")))
        line = int(leak.get("StartLine", 0))
        start_col = int(leak.get("StartColumn", 0))
        end_col = int(leak.get("EndColumn", 0))
        columns = (start_col, end_col) if start_col and end_col else (1, 10_000)
        masks.setdefault(file_key, {})[line] = columns
    return masks
