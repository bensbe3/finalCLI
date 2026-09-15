"""Phase 5 tests: the orchestration in main.py. These run the real
collector, router, consolidator and reporter — only the external tools
are faked, so the traced run is genuinely exercised."""

import json
from pathlib import Path

import main as main_module
import scanners.base as base
from scanners import ALL_SCANNERS


def build_project(tmp_path: Path) -> Path:
    target = tmp_path / "project"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.php").write_text("<?php echo $_GET['x'];", encoding="utf-8")
    (target / "src" / "b.php").write_text("<?php echo 1;", encoding="utf-8")
    (target / "src" / "app.js").write_text("eval(input)", encoding="utf-8")
    (target / "package-lock.json").write_text("{}", encoding="utf-8")
    (target / "node_modules").mkdir()
    (target / "node_modules" / "ignored.php").write_text("<?php", encoding="utf-8")
    return target


def fake_all_scanners(monkeypatch) -> dict:
    """Replace every scanner's tool call with a recorder, so we can see
    exactly which files each one received."""
    received: dict[str, list] = {}
    for scanner in ALL_SCANNERS:
        monkeypatch.setattr(scanner, "is_available", lambda: True)

        def record(files, target, excludes, _scan_type=None):
            received[_scan_type] = list(files)
            return []

        monkeypatch.setattr(
            scanner, "run",
            lambda files, target, excludes, _s=scanner.scan_type: record(
                files, target, excludes, _s),
        )
    return received


# ---- routing is visible AND correct ---------------------------------------

def test_php_scan_routes_only_php_files_and_prints_the_count(tmp_path, monkeypatch, capsys):
    target = build_project(tmp_path)
    received = fake_all_scanners(monkeypatch)

    exit_code = main_module.main(
        [str(target), "--scan", "php", "--report", str(tmp_path / "reports")]
    )
    printed = capsys.readouterr().out

    assert exit_code == 0
    assert "PHP code scan (Semgrep) -> 2 file(s) selected" in printed
    assert sorted(p.name for p in received["php"]) == ["a.php", "b.php"]
    assert "app.js" not in printed                       # never offered to PHP
    assert received.keys() == {"php"}                     # only this scanner ran


def test_run_all_routes_each_scanner_its_own_subset(tmp_path, monkeypatch):
    target = build_project(tmp_path)
    received = fake_all_scanners(monkeypatch)

    main_module.main([str(target), "--all", "--report", str(tmp_path / "reports")])

    assert sorted(p.name for p in received["php"]) == ["a.php", "b.php"]
    assert [p.name for p in received["js"]] == ["app.js"]
    assert received["python"] == []                       # no .py files here
    assert [p.name for p in received["dependencies"]] == ["package-lock.json"]
    # the secrets scanner declared "*", so it gets everything collected
    assert len(received["secrets"]) == 4
    # ...and never a vendored file, because the collector excluded it
    assert all("node_modules" not in str(p) for p in received["secrets"])


def test_selection_is_printed_before_the_scanner_runs(tmp_path, monkeypatch, capsys):
    """The point of the printed line: you can verify routing BEFORE the
    tool touches anything."""
    target = build_project(tmp_path)
    order: list[str] = []
    for scanner in ALL_SCANNERS:
        monkeypatch.setattr(scanner, "is_available", lambda: True)
        monkeypatch.setattr(
            scanner, "run",
            lambda files, t, e: order.append(f"ran-with-{len(files)}") or [],
        )
    monkeypatch.setattr(
        main_module, "print",
        lambda *args, **kwargs: order.append(" ".join(str(a) for a in args)),
        raising=False,
    )

    main_module.main([str(target), "--scan", "php", "--report", str(tmp_path / "reports")])

    selected_index = next(i for i, line in enumerate(order) if "2 file(s) selected" in line)
    ran_index = order.index("ran-with-2")
    assert selected_index < ran_index


# ---- orchestration order --------------------------------------------------

def test_orchestration_order_matches_the_documented_trace(tmp_path, monkeypatch):
    target = build_project(tmp_path)
    fake_all_scanners(monkeypatch)
    order: list[str] = []

    def wrap(module, name):
        original = getattr(module, name)

        def wrapper(*args, **kwargs):
            order.append(name)
            return original(*args, **kwargs)

        monkeypatch.setattr(module, name, wrapper)

    wrap(main_module.excludes_module, "prepare")
    wrap(main_module.collector, "collect")
    wrap(main_module.router, "route")
    wrap(main_module.consolidator, "merge")
    wrap(main_module.reporter, "write")

    main_module.main([str(target), "--scan", "php", "--report", str(tmp_path / "reports")])

    assert order == ["prepare", "collect", "route", "merge", "write"]


# ---- the generated menu ---------------------------------------------------

def test_menu_is_generated_from_the_one_scanner_list(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *_: "0")
    chosen = main_module.choose_scanners_interactively()
    printed = capsys.readouterr().out
    for number, scanner in enumerate(ALL_SCANNERS, start=1):
        assert f"{number}. {scanner.label}" in printed
    assert f"{len(ALL_SCANNERS) + 1}. Run everything at once" in printed
    assert chosen == []                                   # 0 quits


def test_menu_choices_map_to_scanners_and_run_all(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "1")
    assert main_module.choose_scanners_interactively() == [ALL_SCANNERS[0]]

    monkeypatch.setattr("builtins.input", lambda *_: str(len(ALL_SCANNERS) + 1))
    assert main_module.choose_scanners_interactively() == list(ALL_SCANNERS)


def test_menu_exits_cleanly_when_there_is_no_terminal(monkeypatch, capsys):
    """Piped input, CI or docker without -it: input() hits EOF. That must
    be a helpful message, not a traceback."""
    def raise_eof(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    assert main_module.choose_scanners_interactively() == []
    assert "--scan" in capsys.readouterr().out


def test_menu_tolerates_a_byte_order_mark_from_a_windows_pipe(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "﻿1")
    assert main_module.choose_scanners_interactively() == [ALL_SCANNERS[0]]


def test_menu_reprompts_on_bad_input(monkeypatch, capsys):
    answers = iter(["banana", "99", "2"])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    assert main_module.choose_scanners_interactively() == [ALL_SCANNERS[1]]
    assert "Please enter a number" in capsys.readouterr().out


# ---- graceful degradation -------------------------------------------------

def test_full_run_with_no_tools_installed_still_reports(tmp_path, monkeypatch, capsys):
    """Every external tool missing: skip lines, exit 0, report still written."""
    target = build_project(tmp_path)
    monkeypatch.setattr(base.shutil, "which", lambda cmd: None)
    report_dir = tmp_path / "reports"

    exit_code = main_module.main([str(target), "--all", "--report", str(report_dir)])
    printed = capsys.readouterr().out

    assert exit_code == 0
    assert printed.count("skip:") == len(ALL_SCANNERS)
    data = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 0
    assert all("not installed" in scan["status"] for scan in data["meta"]["scans"])


def test_a_failing_tool_is_reported_as_failed_not_as_zero_findings(
        tmp_path, monkeypatch, capsys):
    """The honesty regression test. A tool that breaks mid-run must be
    marked FAILED everywhere - terminal, HTML and JSON - because zero
    findings from a scan that never ran is not a clean result."""
    target = build_project(tmp_path)
    report_dir = tmp_path / "reports"

    for scanner in ALL_SCANNERS:
        monkeypatch.setattr(scanner, "is_available", lambda: True)

        def explode(files, t, e):
            raise base.ScannerFailed("could not download vulnerability DB")

        monkeypatch.setattr(scanner, "run", explode)

    exit_code = main_module.main([str(target), "--all", "--report", str(report_dir)])
    printed = capsys.readouterr().out

    assert exit_code == 0                       # loud, but never fatal
    assert "FAILED" in printed
    assert "did NOT complete" in printed
    assert "This report is INCOMPLETE" in printed

    data = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
    assert len(data["incomplete_scans"]) == len(ALL_SCANNERS)
    assert all(scan["status"].startswith("FAILED") for scan in data["meta"]["scans"])

    html = (report_dir / "report.html").read_text(encoding="utf-8")
    assert "This report is incomplete" in html
    assert "means <em>unknown</em>, not clean" in html


def test_skipped_scans_are_also_flagged_as_not_covered(tmp_path, monkeypatch):
    """A missing tool is not a failure, but it still means that area was
    never checked - the report must say so."""
    target = build_project(tmp_path)
    report_dir = tmp_path / "reports"
    monkeypatch.setattr(base.shutil, "which", lambda cmd: None)

    main_module.main([str(target), "--all", "--report", str(report_dir)])

    data = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
    assert len(data["incomplete_scans"]) == len(ALL_SCANNERS)
    html = (report_dir / "report.html").read_text(encoding="utf-8")
    assert "This report is incomplete" in html


def test_missing_target_folder_is_a_clean_error(tmp_path, capsys):
    exit_code = main_module.main([str(tmp_path / "nope"), "--all"])
    assert exit_code == 2
    assert "is not a folder" in capsys.readouterr().out
