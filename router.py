"""
router.py — hands each scanner exactly the files it declared it wants.

RECEIVES:  a FileSet + one scanner (only its .file_types declaration is read)
PRODUCES:  the exact list of paths that scanner should receive
CALLED BY: main.py

The router is DELIBERATELY DUMB. It does not know what PHP is. It
computes an intersection between the FileSet's buckets and the
scanner's declaration, nothing more:

    "*"        -> every collected file (the secrets scanner declares this;
                  that is the contract working, not a hole)
    ".php"     -> the extension bucket
    "yarn.lock"-> the exact-filename bucket

All routing knowledge lives in each scanner's file_types declaration —
so adding a language is one new scanner file and zero changes here.
"""

from __future__ import annotations

from pathlib import Path

from models import FileSet


def route(fileset: FileSet, scanner) -> list[Path]:
    """Return the subset of `fileset` that `scanner` declared it wants."""
    if "*" in scanner.file_types:
        return fileset.all_files()

    selected: set[Path] = set()
    for file_type in scanner.file_types:
        selected.update(fileset.get(file_type.lower()))
    return sorted(selected)
