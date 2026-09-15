"""
scanners/js_scanner.py — JavaScript/TypeScript static analysis via Semgrep.

RECEIVES:  the JS/TS files the router selected for it
PRODUCES:  list[Finding] (complete, snippets attached)
CALLED BY: main.py, through the Scanner contract

A declaration only — the work lives in SemgrepScanner (scanners/base.py).

WHY THREE RULESETS: Semgrep's registry splits JavaScript coverage across
packs, and `p/javascript` alone reported nothing on plain (non-framework)
JS during testing. `p/eslint-plugin-security` and `p/nodejsscan` are what
actually catch command injection and insecure randomness in plain Node
code, so all three are used together. Even combined they miss some
classic flaws (notably eval of user input) — sample_vuln_app/README.md
documents that measured gap as a worked example of a false negative.
"""

from scanners.base import SemgrepScanner


class JsScanner(SemgrepScanner):
    label = "JavaScript/TypeScript code scan (Semgrep)"
    scan_type = "js"
    file_types = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    rulesets = ["p/javascript", "p/eslint-plugin-security", "p/nodejsscan"]
