"""
extensions/correlation.py — cross-scanner risk correlation.

INTERFACE READY, NOT IMPLEMENTED — future work.

RECEIVES:  the consolidated list[Finding]
PRODUCES:  the same list, with correlation notes attached
CALLED BY: main.py, immediately after consolidation (call site is written
           out as a comment near the top of main.py)

The idea: two findings that are unremarkable alone can matter together —
a hardcoded credential (gitleaks) in the same file as an injection sink
(semgrep), or a vulnerable dependency (trivy) whose vulnerable function
is actually called in scanned code. dependency_usage.py already attaches
conservative direct-import evidence; true call-path correlation still
needs reachability analysis and stays out of scope until this seam is
implemented on purpose.
"""

from __future__ import annotations

from models import Finding


def correlate(findings: list[Finding]) -> list[Finding]:
    """No-op. Returns findings untouched. Future work: group related
    findings and note where combinations raise real risk."""
    return findings
