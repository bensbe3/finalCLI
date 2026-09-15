"""
scanners/dependency_scanner.py — known CVEs in dependencies, via Trivy.

RECEIVES:  the lockfiles the router selected for it (bucketed by exact
           filename, e.g. "package-lock.json" — see collector.py)
PRODUCES:  list[Finding] whose identity is (package, advisory_id),
           NEVER a line number — lockfile lines shift for unrelated
           reasons and would fake "new"/"fixed" vulnerabilities.
           Also copies Trivy VendorIDs into Finding.advisory_aliases so
           a GHSA can still receive KEV/EPSS enrichment via its CVE.
CALLED BY: main.py, through the Scanner contract

Trivy is pointed at each routed lockfile individually, so it only ever
sees exactly what the router selected. The line stored on a Finding is
for DISPLAY only (where the package appears in the lockfile); the
fingerprint in models.py ignores it by design.

Keep file_types in sync with collector.LOCKFILE_NAMES: the collector must
bucket a lockfile by exact name before this scanner can declare it.
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
    extract_cwe,
    relative_posix,
    run_tool,
)


class DependencyScanner(Scanner):
    label = "Dependency scan - known CVEs (Trivy)"
    scan_type = "dependencies"
    file_types = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "pipfile.lock",
        "poetry.lock",
        "requirements.txt",
        "gemfile.lock",
        "cargo.lock",
        "go.mod",
        "packages.lock.json",
        "packages.config",
        "pom.xml",
        "conan.lock",
        "mix.lock",
        "pubspec.lock",
        "podfile.lock",
        "package.resolved",
        "manifest.toml",
    }
    tool_cmd = "trivy"

    def run(self, files: list[Path], target: Path, excludes) -> list[Finding]:
        self.last_files_scanned = 0
        self.last_warnings = []
        if self.skip_if_unavailable():
            return []
        if not files:
            print(f"  {self.label}: no lockfiles found - nothing to do")
            return []

        findings: list[Finding] = []
        failures: list[str] = []
        for lockfile in files:
            argv = [
                self.tool_cmd, "fs",
                "--scanners", "vuln",
                "--format", "json",
                "--quiet",
            ] + excludes.trivy_args() + [str(lockfile)]
            # Shorter than the default: trivy's slow path is downloading its
            # vulnerability database, and a user should hear about that in
            # minutes rather than waiting out a ten-minute stall.
            result = run_tool(argv, timeout=300)
            if not result.stdout.strip():
                # Most often: trivy could not download its vulnerability
                # database. Reporting "0 CVEs" here would be a lie.
                failures.append(f"{lockfile.name} ({describe_failure(result)})")
                continue
            try:
                output = json.loads(result.stdout)
            except (json.JSONDecodeError, TypeError):
                failures.append(
                    f"{lockfile.name} (trivy returned invalid JSON; "
                    f"{describe_failure(result)})")
                continue
            findings += self.parse(output, lockfile, target)
            self.last_files_scanned += 1
            if result.returncode != 0:
                failures.append(
                    f"{lockfile.name} ({describe_failure(result)})")

        if failures:
            raise ScannerFailed(
                "trivy could not scan " + "; ".join(failures), findings)
        return findings

    def parse(self, output: dict, lockfile: Path, target: Path) -> list[Finding]:
        """Turn Trivy's JSON into Findings keyed on (package, advisory)."""
        findings: list[Finding] = []
        for result in output.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                package = vuln.get("PkgName", "")
                advisory = vuln.get("VulnerabilityID", "")
                aliases = [
                    str(alias).strip().upper()
                    for alias in vuln.get("VendorIDs", []) or []
                    if str(alias).strip()
                    and str(alias).strip().upper() != advisory.upper()
                ]
                aliases = list(dict.fromkeys(aliases))
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                title = vuln.get("Title", "") or vuln.get("Description", "")[:120]

                message = f"{package} {installed}: {title}".strip()
                if fixed:
                    message += f" (fixed in {fixed})"

                # Display-only: where the package appears in the lockfile.
                line = find_line(lockfile, package)
                findings.append(
                    Finding(
                        file=relative_posix(lockfile, target),
                        line=line,
                        rule_id=advisory,
                        message=message,
                        severity=Severity.from_text(vuln.get("Severity", "")),
                        confidence="high",  # advisory-database match, not a pattern
                        tool="trivy",
                        scan_type=self.scan_type,
                        cwe=extract_cwe(vuln.get("CweIDs", [])),
                        snippet=capture_snippet(lockfile, line) if line else "",
                        package=package,
                        advisory_id=advisory,
                        advisory_aliases=aliases,
                    )
                )
        return findings


def find_line(path: Path, needle: str) -> int:
    """First line containing `needle`, streaming the file. 0 if absent."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for number, text in enumerate(handle, start=1):
                if needle in text:
                    return number
    except OSError:
        pass
    return 0
