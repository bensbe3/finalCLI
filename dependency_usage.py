"""
dependency_usage.py — conservative source evidence for vulnerable packages.

RECEIVES:  consolidated findings, target path, and already-collected FileSet
PRODUCES:  the same findings with dependency usage evidence attached
CALLED BY: main.py

This is NOT reachability analysis. It looks only for direct import/reference
evidence that can be mapped reliably from a package name. Finding a reference
proves use, but not use of the vulnerable function. Finding no reference never
means "unreachable": frameworks and transitive dependencies may load packages
without an application importing them directly.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from models import FileSet, Finding


MAX_EVIDENCE = 5

JAVASCRIPT_LOCKS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
PYTHON_LOCKS = {"pipfile.lock", "poetry.lock", "requirements.txt"}
RUBY_LOCKS = {"gemfile.lock"}
RUST_LOCKS = {"cargo.lock"}
GO_LOCKS = {"go.mod"}

SOURCE_SUFFIXES = {
    "javascript": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"},
    "composer": {".php", ".php5", ".phtml"},
    "python": {".py"},
    "ruby": {".rb"},
    "rust": {".rs"},
    "go": {".go"},
}

QUOTED_IMPORT = re.compile(
    r"""(?:from\s+|require\s*\(\s*|import\s*\(\s*|import\s+)["']([^"']+)["']"""
)
PYTHON_IMPORT = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)")
RUBY_REQUIRE = re.compile(r"""^\s*require(?:_relative)?\s*["']([^"']+)["']""")
RUST_USE = re.compile(r"^\s*(?:use|extern\s+crate)\s+([A-Za-z_]\w*)")
QUOTED_VALUE = re.compile(r"""["']([^"']+)["']""")

FOUND_NOTE = (
    "Application source directly imports or references this package. This "
    "proves package use, not that the vulnerable function is reachable."
)
NOT_FOUND_NOTE = (
    "No direct source reference was found. Frameworks and transitive "
    "dependencies may still load it; this is not proof that it is unreachable."
)


def enrich(findings: list[Finding], fileset: FileSet,
           target: Path) -> list[Finding]:
    """Attach conservative package-usage evidence without another file walk."""
    dependencies = [finding for finding in findings if finding.advisory_id]
    if not dependencies:
        return findings

    composer_namespaces = load_composer_namespaces(fileset)
    groups: dict[str, list[Finding]] = defaultdict(list)

    for finding in dependencies:
        ecosystem = ecosystem_of(finding.file)
        if ecosystem == "composer" and not composer_namespaces.get(finding.package):
            finding.usage_status = "mapping unavailable"
            finding.usage_note = (
                "Composer metadata did not provide a PSR namespace for this "
                "package, so direct source usage could not be checked reliably."
            )
        elif ecosystem:
            groups[ecosystem].append(finding)
        else:
            finding.usage_status = "not supported"
            finding.usage_note = (
                "Direct package-to-source usage analysis is not implemented "
                "for this lockfile ecosystem."
            )

    for ecosystem, group in groups.items():
        scan_sources(ecosystem, group, fileset, target, composer_namespaces)
        for finding in group:
            if finding.usage_evidence:
                finding.usage_status = "direct reference found"
                finding.usage_note = FOUND_NOTE
            else:
                finding.usage_status = "no direct reference found"
                finding.usage_note = NOT_FOUND_NOTE

    return findings


def ecosystem_of(lockfile: str) -> str:
    """Infer only from the routed lockfile name, never from project guesses."""
    name = Path(lockfile).name.lower()
    if name in JAVASCRIPT_LOCKS:
        return "javascript"
    if name == "composer.lock":
        return "composer"
    if name in PYTHON_LOCKS:
        return "python"
    if name in RUBY_LOCKS:
        return "ruby"
    if name in RUST_LOCKS:
        return "rust"
    if name in GO_LOCKS:
        return "go"
    return ""


def scan_sources(ecosystem: str, findings: list[Finding], fileset: FileSet,
                 target: Path,
                 composer_namespaces: dict[str, list[str]]) -> None:
    """Read each relevant source file once and record path:line evidence."""
    suffixes = SOURCE_SUFFIXES[ecosystem]
    sources = [
        path for path in fileset.all_files()
        if path.suffix.lower() in suffixes
    ]
    for path in sources:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    for finding in findings:
                        if len(finding.usage_evidence) >= MAX_EVIDENCE:
                            continue
                        if line_references(
                                line, finding.package, ecosystem,
                                composer_namespaces.get(finding.package, [])):
                            finding.usage_evidence.append(
                                f"{relative_path(path, target)}:{line_number}")
        except OSError:
            continue


def line_references(line: str, package: str, ecosystem: str,
                    namespaces: list[str]) -> bool:
    """Return True only for an ecosystem-specific direct reference."""
    if ecosystem == "javascript":
        return any(
            value == package or value.startswith(package + "/")
            for value in QUOTED_IMPORT.findall(line)
        )
    if ecosystem == "composer":
        return any(namespace.rstrip("\\") + "\\" in line
                   for namespace in namespaces)
    if ecosystem == "python":
        match = PYTHON_IMPORT.search(line)
        import_name = package.replace("-", "_").split(".", 1)[0]
        return bool(match and match.group(1).split(".", 1)[0] == import_name)
    if ecosystem == "ruby":
        match = RUBY_REQUIRE.search(line)
        return bool(match and (
            match.group(1) == package or match.group(1).startswith(package + "/")
        ))
    if ecosystem == "rust":
        match = RUST_USE.search(line)
        return bool(match and match.group(1) == package.replace("-", "_"))
    if ecosystem == "go":
        return any(
            value == package or value.startswith(package + "/")
            for value in QUOTED_VALUE.findall(line)
        )
    return False


def load_composer_namespaces(fileset: FileSet) -> dict[str, list[str]]:
    """Read Composer's own package-to-namespace declarations."""
    namespaces: dict[str, list[str]] = defaultdict(list)
    for lockfile in fileset.get("composer.lock"):
        try:
            data = json.loads(lockfile.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        packages = (data.get("packages", []) or []) + (
            data.get("packages-dev", []) or [])
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = str(package.get("name", ""))
            autoload = package.get("autoload", {}) or {}
            if not isinstance(autoload, dict):
                continue
            for mapping_name in ("psr-4", "psr-0"):
                mapping = autoload.get(mapping_name, {}) or {}
                if not isinstance(mapping, dict):
                    continue
                for namespace in mapping:
                    if namespace and namespace not in namespaces[name]:
                        namespaces[name].append(namespace)
    return dict(namespaces)


def relative_path(path: Path, target: Path) -> str:
    """Stable source path relative to the scanned target."""
    try:
        return path.resolve().relative_to(target.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
