"""
scanners/__init__.py — the ONE list every part of the program reads.

RECEIVES:  nothing
PRODUCES:  ALL_SCANNERS — a plain, readable list of scanner instances
CALLED BY: main.py (menu + "run all" + --scan choices are all views of
           this list, so they can never fall out of sync)

Deliberately a literal list, not auto-discovery/reflection: three saved
lines are not worth losing the ability to read what the program does.
To add a scanner: write the new file in this folder, add one line here.
"""

from scanners.php_scanner import PhpScanner
from scanners.js_scanner import JsScanner
from scanners.python_scanner import PythonScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.secrets_scanner import SecretsScanner

ALL_SCANNERS = [
    PhpScanner(),
    JsScanner(),
    PythonScanner(),
    DependencyScanner(),
    SecretsScanner(),
]
