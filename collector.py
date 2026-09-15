"""
collector.py — walks the target folder ONCE and groups files by type.

RECEIVES:  a folder path + the prepared Excludes rules
PRODUCES:  one FileSet (dict: file_type -> list of paths)
CALLED BY: main.py

Grouping rule: special filenames first (lockfiles are bucketed under
their exact name, e.g. "package-lock.json", so the dependency scanner
can declare precisely which lockfiles it wants), everything else under
its lowercase extension (".php", ".js", ...). Files with no extension
land in the "" bucket — they still reach scanners that declare "*".

Low memory: this module stores paths only. No file content is ever read.
"""

from __future__ import annotations

import os
from pathlib import Path

from excludes import Excludes
from models import FileSet

# Filenames that identify a dependency lockfile / manifest. These are
# bucketed by exact name, not by extension. Keep in sync with
# DependencyScanner.file_types in scanners/dependency_scanner.py.
LOCKFILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "pipfile.lock",
    "poetry.lock",
    "requirements.txt",
    "gemfile.lock",
    "cargo.lock",
    "go.mod",
    "packages.lock.json",
    "packages.config",
    "pom.xml",
    "conan.lock",
    "mix.lock",
    "pubspec.lock",
    "podfile.lock",
    "package.resolved",
    "manifest.toml",
}


def classify(path: Path) -> str:
    """Decide which FileSet bucket a file belongs to."""
    name = path.name.lower()
    if name in LOCKFILE_NAMES:
        return name
    return path.suffix.lower()  # "" when the file has no extension


def collect(target: Path, excludes: Excludes) -> FileSet:
    """Walk `target` exactly once and return the grouped FileSet."""
    fileset = FileSet()

    for current_dir, dir_names, file_names in os.walk(target):
        current = Path(current_dir)

        # Prune excluded directories in place so os.walk never enters them.
        dir_names[:] = sorted(
            d for d in dir_names if not excludes.skip_dir(current / d)
        )

        for file_name in sorted(file_names):
            file_path = current / file_name
            if excludes.skip_file(file_path):
                continue
            fileset.add(classify(file_path), file_path)

    return fileset
