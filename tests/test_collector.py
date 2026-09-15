"""Phase 1 tests: single-walk collection, grouping, and exclusion."""

from pathlib import Path

import collector
import excludes as excludes_module


def build_sample_tree(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "src" / "index.php").write_text("<?php echo 1;", encoding="utf-8")
    (root / "src" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (root / "src" / "util.py").write_text("print(1)", encoding="utf-8")
    (root / "package-lock.json").write_text("{}", encoding="utf-8")
    (root / "README").write_text("no extension", encoding="utf-8")
    # Things that must NEVER be collected:
    (root / "node_modules" / "lib").mkdir(parents=True)
    (root / "node_modules" / "lib" / "evil.js").write_text("x", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("x", encoding="utf-8")
    (root / "reports").mkdir()
    (root / "reports" / "report.html").write_text("<html>", encoding="utf-8")
    (root / "reports" / "report.json").write_text("{}", encoding="utf-8")


def collect_tree(tmp_path):
    target = tmp_path / "project"
    build_sample_tree(target)
    ex = excludes_module.prepare(target, target / "reports")
    return collector.collect(target, ex)


def test_files_are_grouped_by_type(tmp_path):
    fileset = collect_tree(tmp_path)
    assert [p.name for p in fileset.get(".php")] == ["index.php"]
    assert [p.name for p in fileset.get(".js")] == ["app.js"]
    assert [p.name for p in fileset.get(".py")] == ["util.py"]


def test_lockfiles_are_bucketed_by_exact_name(tmp_path):
    fileset = collect_tree(tmp_path)
    assert [p.name for p in fileset.get("package-lock.json")] == ["package-lock.json"]
    assert fileset.get(".json") == []   # NOT under its extension


def test_supported_dependency_manifests_use_exact_name_buckets():
    assert collector.classify(Path("go.mod")) == "go.mod"
    assert collector.classify(Path("pom.xml")) == "pom.xml"
    assert collector.classify(Path("Packages.lock.json")) == "packages.lock.json"
    assert collector.classify(Path("Podfile.lock")) == "podfile.lock"


def test_extensionless_files_land_in_empty_bucket(tmp_path):
    fileset = collect_tree(tmp_path)
    assert [p.name for p in fileset.get("")] == ["README"]


def test_excluded_dirs_and_own_reports_never_collected(tmp_path):
    """The regression net: no tool-artifact or vendored file may ever
    enter the pipeline."""
    fileset = collect_tree(tmp_path)
    all_names = [p.name for p in fileset.all_files()]
    assert "evil.js" not in all_names        # node_modules pruned
    assert "config" not in all_names         # .git pruned
    assert "report.html" not in all_names    # own output pruned
    assert "report.json" not in all_names
    assert fileset.count() == 5
