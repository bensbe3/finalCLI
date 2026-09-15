"""Phase 1 tests: the one exclude list and its tool projections.
The core guarantee: the tool must never scan or flag its own output."""

import excludes as excludes_module


def make_excludes(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    report_dir = tmp_path / "reports"
    return target, report_dir, None


def test_default_directories_are_skipped(tmp_path):
    target = tmp_path / "project"
    (target / "node_modules").mkdir(parents=True)
    (target / ".git").mkdir()
    ex = excludes_module.prepare(target, tmp_path / "reports")
    assert ex.skip_dir(target / "node_modules")
    assert ex.skip_dir(target / ".git")
    assert not ex.skip_dir(target / "src")


def test_own_report_dir_is_always_skipped(tmp_path):
    """The report dir is our own output — flagging it is the known
    failure mode this module exists to prevent."""
    target = tmp_path / "project"
    target.mkdir()
    report_dir = target / "reports"          # even when INSIDE the target
    report_dir.mkdir()
    ex = excludes_module.prepare(target, report_dir)
    assert ex.skip_dir(report_dir)
    assert ex.skip_file(report_dir / "report.html")
    assert ex.skip_file(report_dir / "gitleaks_config.toml")


def test_secignore_patterns_are_honored(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    (target / ".secignore").write_text("*.min.js\nlegacy/\n", encoding="utf-8")
    ex = excludes_module.prepare(target, tmp_path / "reports")
    assert ex.skip_file(target / "app.min.js")
    assert ex.skip_file(target / "legacy" / "old.php")
    assert not ex.skip_file(target / "app.js")


def test_semgrep_projection_contains_the_shared_list(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    ex = excludes_module.prepare(target, tmp_path / "reports")
    args = ex.semgrep_args()
    assert "node_modules" in args and ".git" in args and "reports" in args
    # flags come in --exclude/value pairs
    assert args.count("--exclude") == (len(args) // 2)


def test_trivy_projection_contains_the_shared_list(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    ex = excludes_module.prepare(target, tmp_path / "reports")
    args = ex.trivy_args()
    assert args[0] == "--skip-dirs"
    assert "node_modules" in args[1] and "reports" in args[1]


def test_gitleaks_projection_writes_native_config(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    (target / ".secignore").write_text("legacy/\n", encoding="utf-8")
    ex = excludes_module.prepare(target, tmp_path / "reports")
    config = ex.gitleaks_config_path()
    assert config.exists()
    text = config.read_text(encoding="utf-8")
    assert "useDefault = true" in text
    assert "node_modules" in text
    assert "legacy" in text                     # .secignore reaches gitleaks too
    assert str(config).startswith(str(tmp_path / "reports"))  # lives in excluded dir
