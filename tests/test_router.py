"""Phase 1 tests: the router is a dumb intersection — it only reads
scanner.file_types and never interprets anything else."""

from pathlib import Path

import router
from models import FileSet


class FakeScanner:
    """The router only touches .file_types — this is the whole contract."""

    def __init__(self, file_types):
        self.file_types = file_types


def build_fileset() -> FileSet:
    fs = FileSet()
    fs.add(".php", Path("a.php"))
    fs.add(".php", Path("b.php"))
    fs.add(".js", Path("app.js"))
    fs.add("package-lock.json", Path("package-lock.json"))
    fs.add("", Path("README"))
    return fs


def test_extension_declaration_gets_only_that_bucket():
    files = router.route(build_fileset(), FakeScanner({".php"}))
    assert [p.name for p in files] == ["a.php", "b.php"]


def test_multiple_declarations_are_unioned():
    files = router.route(build_fileset(), FakeScanner({".php", ".js"}))
    assert sorted(p.name for p in files) == ["a.php", "app.js", "b.php"]


def test_exact_filename_declaration_gets_the_lockfile_bucket():
    files = router.route(build_fileset(), FakeScanner({"package-lock.json"}))
    assert [p.name for p in files] == ["package-lock.json"]


def test_star_declaration_gets_every_collected_file():
    """The secrets scanner declares '*' — receiving everything is the
    routing contract working, not a hole."""
    files = router.route(build_fileset(), FakeScanner({"*"}))
    assert len(files) == 5


def test_unknown_declaration_gets_nothing():
    assert router.route(build_fileset(), FakeScanner({".rb"})) == []
