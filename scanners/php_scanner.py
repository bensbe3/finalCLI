"""
scanners/php_scanner.py — PHP static analysis via Semgrep.

RECEIVES:  the PHP files the router selected for it
PRODUCES:  list[Finding] (complete, snippets attached)
CALLED BY: main.py, through the Scanner contract

Everything below is a DECLARATION — the actual work lives in
SemgrepScanner (scanners/base.py). Adding another language to this
project means writing another file exactly this small.
"""

from scanners.base import SemgrepScanner


class PhpScanner(SemgrepScanner):
    label = "PHP code scan (Semgrep)"
    scan_type = "php"
    file_types = {".php", ".phtml", ".php5"}
    rulesets = ["p/php"]
