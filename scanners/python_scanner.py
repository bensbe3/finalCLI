"""
scanners/python_scanner.py — Python static analysis via Semgrep.

RECEIVES:  the Python files the router selected for it
PRODUCES:  list[Finding] (complete, snippets attached)
CALLED BY: main.py, through the Scanner contract

This scanner exists partly to PROVE the extensibility claim: adding a
whole language to the project is exactly this many lines, and zero
changes anywhere else.
"""

from scanners.base import SemgrepScanner


class PythonScanner(SemgrepScanner):
    label = "Python code scan (Semgrep)"
    scan_type = "python"
    file_types = {".py"}
    rulesets = ["p/python"]
