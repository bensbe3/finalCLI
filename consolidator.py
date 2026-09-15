"""
consolidator.py — merges every scanner's findings into one honest list.

RECEIVES:  the list[Finding] from each scanner that ran, plus (optionally)
           the exploitability Catalogue main.py fetched
PRODUCES:  one deduplicated, enriched, priority-sorted list[Finding]
CALLED BY: main.py

Four jobs, nothing more:
  1. dedupe on finding.fingerprint — identity is a property OF the
     finding (models.py), so this module never type-checks what it holds;
     when duplicates collide, the higher severity wins
  2. enrich with knowledge.py — owasp / remediation / scenario, from the CWE
  3. enrich with exploitability.py — is this CVE (or Trivy CVE alias) being
     attacked in the wild?
  4. sort — what is actually being exploited first, then by severity

(Direct-import evidence is attached afterwards by dependency_usage.py —
 that step is deliberately separate so this module stays about merge +
 CWE/KEV enrichment only.)

WHY THE SORT CHANGED: a tool's severity describes a class of bug in general.
Twenty findings marked HIGH give a reader no way to choose. Real-world
exploitation data does, so a vulnerability CISA lists as actively exploited
sorts above an untouched HIGH, whatever the tool called it.

This module never reopens source files: snippets were captured at scan
time by the scanners (see scanners/base.py).
"""

from __future__ import annotations

import exploitability
from knowledge import UNKNOWN, lookup
from models import Finding


def merge(finding_lists: list[list[Finding]],
          catalogue: exploitability.Catalogue | None = None) -> list[Finding]:
    """Flatten -> dedupe by fingerprint -> enrich -> sort."""
    unique: dict[tuple, Finding] = {}
    for findings in finding_lists:
        for finding in findings:
            existing = unique.get(finding.fingerprint)
            if existing is None or finding.severity > existing.severity:
                unique[finding.fingerprint] = finding

    # No catalogue supplied means nobody looked it up — which is "unknown",
    # never "not exploited".
    catalogue = catalogue or exploitability.Catalogue()

    merged = list(unique.values())
    for finding in merged:
        knowledge = lookup(finding.cwe)
        # Prefer our reviewed mapping when one exists. For an unknown CWE,
        # preserve an OWASP category supplied by the external rule instead
        # of discarding useful tool evidence.
        if knowledge != UNKNOWN or not finding.owasp:
            finding.owasp = knowledge.owasp
        finding.remediation = knowledge.remediation
        finding.scenario = knowledge.scenario

        exploit = catalogue.of_advisory(
            finding.advisory_id, finding.advisory_aliases)
        finding.exploit_status = exploit.status
        finding.epss = exploit.epss
        finding.epss_percentile = exploit.percentile
        finding.kev = exploit.kev
        finding.exploit_note = exploit.note

    merged.sort(key=sort_key)
    return merged


def sort_key(finding: Finding) -> tuple:
    """Most urgent first: proven real-world attacks, then severity, then the
    exploit probability, then a stable file/line order."""
    priority = exploitability.PRIORITY.get(finding.exploit_status, 0)
    return (-priority, -finding.severity, -(finding.epss or 0.0),
            finding.file, finding.line)
