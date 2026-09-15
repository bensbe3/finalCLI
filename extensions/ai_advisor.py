"""
extensions/ai_advisor.py — AI recommendation engine.

INTERFACE READY, NOT IMPLEMENTED — future work.

RECEIVES:  the consolidated list[Finding] (after consolidator.merge)
PRODUCES:  the same list, with richer per-finding explanations
CALLED BY: main.py, immediately after consolidation (call site is written
           out as a comment near the top of main.py)

Why it is a seam and not a feature: the report today only states what a
tool found and what the CWE knowledge base says. Anything generated
would need to be clearly labelled as generated, and validated, before it
belongs in a security report.
"""

from __future__ import annotations

from models import Finding


def explain_findings(findings: list[Finding]) -> list[Finding]:
    """No-op. Returns findings untouched. Future work: attach generated,
    clearly-labelled explanations to each finding."""
    return findings
