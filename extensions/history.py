"""
extensions/history.py — scan history and delta tracking between runs.

INTERFACE READY, NOT IMPLEMENTED — future work.

RECEIVES:  the consolidated list[Finding] + the report folder
PRODUCES:  nothing today; eventually an appended history file and a
           new/fixed/unchanged verdict per finding
CALLED BY: main.py, immediately after consolidation (call site is written
           out as a comment near the top of main.py)

The groundwork is already done and is the reason this seam is cheap:
Finding.fingerprint (models.py) is a STABLE identity — dependency
findings key on (package, advisory) rather than a line number, so a
lockfile line shifting cannot fake a "new" or "fixed" vulnerability.
Comparing two runs is therefore a set difference over fingerprints.
"""

from __future__ import annotations

from pathlib import Path

from models import Finding


def record_scan(findings: list[Finding], report_dir: Path) -> None:
    """No-op. Future work: append this run's fingerprints to a history
    file and diff against the previous run."""
    return None
