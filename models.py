"""
models.py — the shared data shapes used by every stage of the pipeline.

RECEIVES:  nothing (defines data structures only)
PRODUCES:  Severity, Finding, FileSet
CALLED BY: imported by every other module

This is the only module everyone imports. It contains no logic beyond
the data itself — the one exception is Finding.fingerprint, because a
finding's identity is a property OF the finding, not of whoever holds it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    """Ordered so that comparisons work: Severity.CRITICAL > Severity.LOW."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def from_text(cls, text: str) -> "Severity":
        """Map the severity words used by external tools onto our scale."""
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "error": cls.HIGH,       # semgrep says ERROR
            "medium": cls.MEDIUM,
            "warning": cls.MEDIUM,   # semgrep says WARNING
            "moderate": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "unknown": cls.LOW,
        }
        return mapping.get(text.strip().lower(), Severity.LOW)


@dataclass
class Finding:
    """One security finding, complete the moment a scanner returns it.

    A Finding leaves its scanner with the snippet already attached
    (captured at scan time). Later stages fill enrichment fields:
      * consolidator.py + knowledge.py      -> owasp / remediation / scenario
      * consolidator.py + exploitability.py -> KEV / EPSS (CVE or CVE alias)
      * dependency_usage.py                 -> direct-import evidence
    """

    file: str                 # path relative to the scanned folder, "/" separators
    line: int                 # 1-based; 0 when meaningless (dependency findings)
    rule_id: str              # the tool's rule/check id
    message: str              # what the tool said
    severity: Severity
    tool: str                 # which tool found it: semgrep / trivy / gitleaks
    scan_type: str = ""       # scanner route: php / js / python / dependencies / secrets
    confidence: str = "medium"   # high | medium | low
    cwe: str = ""             # e.g. "CWE-89"
    snippet: str = ""         # vulnerable line +/- 2 lines, captured at scan time

    # Only set on dependency findings (from Trivy):
    package: str = ""         # e.g. "lodash"
    advisory_id: str = ""     # e.g. "CVE-2020-8203" or "GHSA-..."
    advisory_aliases: list[str] = field(default_factory=list)  # e.g. VendorIDs CVEs
    # Enrichment — filled in by dependency_usage.py (never a reachability verdict):
    usage_status: str = "not analysed"
    usage_note: str = ""
    usage_evidence: list[str] = field(default_factory=list)

    # Enrichment — filled in by consolidator.py via knowledge.py:
    owasp: str = ""
    remediation: str = ""
    scenario: str = ""

    # Enrichment — filled in by consolidator.py via exploitability.py.
    # These answer "is this being attacked in the real world?", which the
    # tool's own severity cannot. Defaults say UNKNOWN, never "safe".
    # Non-CVE advisories stay "not applicable" unless Trivy supplied a CVE alias.
    exploit_status: str = "unknown"   # actively exploited | likely | unlikely | ...
    epss: float | None = None         # probability 0..1 of attack in 30 days
    epss_percentile: float | None = None
    kev: bool = False                 # on CISA's exploited-in-the-wild list
    exploit_note: str = ""            # one plain sentence for the report

    @property
    def fingerprint(self) -> tuple:
        """Stable identity used for deduplication (and future history).

        Dependency findings are keyed on (package, advisory) — NEVER on a
        line number, because a lockfile line can shift for unrelated
        reasons and would fake a "new"/"fixed" vulnerability.
        """
        if self.advisory_id:
            return ("dep", self.package, self.advisory_id)
        return ("code", self.file, self.line, self.rule_id)


@dataclass
class FileSet:
    """Every file in the target folder, grouped by type. Built once by
    collector.py; read by router.py and dependency_usage.py. Holds paths
    only — never contents.

    Bucket keys are either an extension (".php") or an exact special
    filename ("package-lock.json" — lockfiles are grouped by name so the
    dependency scanner can declare exactly which lockfiles it wants).
    """

    buckets: dict[str, list[Path]] = field(default_factory=dict)

    def add(self, key: str, path: Path) -> None:
        self.buckets.setdefault(key, []).append(path)

    def get(self, key: str) -> list[Path]:
        return self.buckets.get(key, [])

    def all_files(self) -> list[Path]:
        every: list[Path] = []
        for paths in self.buckets.values():
            every.extend(paths)
        return sorted(every)

    def count(self) -> int:
        return sum(len(paths) for paths in self.buckets.values())
