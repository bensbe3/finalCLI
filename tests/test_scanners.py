"""Phase 2 tests: scanner parsing (fed recorded tool output), snippet
capture at scan time, secret masking, and graceful skip when a tool is
missing. No external tool is executed here."""

import json
from pathlib import Path

import pytest

import scanners.base as base
from scanners import ALL_SCANNERS
from scanners.dependency_scanner import DependencyScanner
from scanners.php_scanner import PhpScanner
from scanners.secrets_scanner import SecretsScanner
from models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str, target: Path):
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return json.loads(text.replace("TARGET", target.as_posix()))


# ---- semgrep (php/js/python share this code path) --------------------------

def test_semgrep_parse_builds_complete_findings(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "login.php").write_text(
        "<?php\n"
        "$id = $_GET['id'];\n"
        '$q = "SELECT * FROM users WHERE id = $id";\n'
        "$r = mysqli_query($db, $q);\n",
        encoding="utf-8",
    )
    findings = PhpScanner().parse(load_fixture("semgrep_output.json", tmp_path), tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.file == "src/login.php"          # relative, / separators
    assert f.line == 3
    assert f.severity == Severity.HIGH        # semgrep ERROR -> HIGH
    assert f.confidence == "high"
    assert f.cwe == "CWE-89"
    assert f.owasp == "A03:2021 - Injection"
    assert f.tool == "semgrep"
    assert f.scan_type == "php"
    assert ">    3 |" in f.snippet            # vulnerable line marked...
    assert "SELECT * FROM users" in f.snippet # ...captured at scan time
    assert "$_GET" in f.snippet               # with context above it


# ---- trivy -----------------------------------------------------------------

def test_trivy_parse_keys_identity_on_package_and_advisory(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{\n  "packages": {\n    "node_modules/lodash": {\n'
        '      "version": "4.17.15"\n    }\n  }\n}\n',
        encoding="utf-8",
    )
    output = load_fixture("trivy_output.json", tmp_path)
    findings = DependencyScanner().parse(output, lockfile, tmp_path)

    assert len(findings) == 2
    lodash = next(f for f in findings if f.package == "lodash")
    assert lodash.fingerprint == ("dep", "lodash", "CVE-2020-8203")
    assert lodash.advisory_id == "CVE-2020-8203"
    assert lodash.confidence == "high"
    assert lodash.scan_type == "dependencies"
    assert "fixed in 4.17.19" in lodash.message

    # The display line points at the package in the lockfile, but a
    # different line MUST NOT change identity:
    moved = DependencyScanner().parse(output, lockfile, tmp_path)[0]
    moved.line = moved.line + 40
    assert moved.fingerprint == lodash.fingerprint


def test_trivy_keeps_vendor_advisory_aliases(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('{"dependencies":{"demo":"1.0.0"}}', encoding="utf-8")
    output = {
        "Results": [{"Vulnerabilities": [{
            "PkgName": "demo",
            "VulnerabilityID": "GHSA-abcd-efgh-ijkl",
            "VendorIDs": ["CVE-2026-12345", "GHSA-abcd-efgh-ijkl"],
            "InstalledVersion": "1.0.0",
            "Severity": "HIGH",
        }]}],
    }

    finding = DependencyScanner().parse(output, lockfile, tmp_path)[0]

    assert finding.advisory_id == "GHSA-abcd-efgh-ijkl"
    assert finding.advisory_aliases == ["CVE-2026-12345"]


# ---- gitleaks --------------------------------------------------------------

def test_gitleaks_parse_masks_the_secret_in_the_snippet(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    secret_value = "SUPERSECRET1234"  # columns 10-25 on line 2 (see fixture)
    (src / "config.js").write_text(
        "// app config\n"
        f'key    = "{secret_value}";\n'
        "module.exports = { key };\n",
        encoding="utf-8",
    )
    findings = SecretsScanner().parse(load_fixture("gitleaks_output.json", tmp_path), tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-798"
    assert f.confidence == "high"             # specific rule, not "generic"
    assert f.scan_type == "secrets"
    assert secret_value not in f.snippet      # the value never reaches the report
    assert "****" in f.snippet
    assert "config.js" in f.file


def test_neighbouring_secrets_are_masked_in_each_others_context(tmp_path):
    """A snippet shows two lines of context, and secrets cluster together.
    Every secret in the window must be masked - not just the reported one."""
    config = tmp_path / "credentials.js"
    config.write_text(
        'module.exports = {\n'
        '  aws: "AKIAFAKEFAKEFAKEFAKE",\n'
        '  git: "ghp_fakefakefakefakefakefakefakefake12",\n'
        '};\n',
        encoding="utf-8",
    )
    leaks = [
        {"RuleID": "aws-access-token", "Description": "AWS key", "File": str(config),
         "StartLine": 2, "StartColumn": 9, "EndColumn": 30},
        {"RuleID": "github-pat", "Description": "GitHub token", "File": str(config),
         "StartLine": 3, "StartColumn": 9, "EndColumn": 48},
    ]
    findings = SecretsScanner().parse(leaks, tmp_path)

    assert len(findings) == 2
    for finding in findings:
        assert "AKIAFAKEFAKEFAKEFAKE" not in finding.snippet
        assert "ghp_fakefakefakefakefakefakefakefake12" not in finding.snippet
        assert finding.snippet.count("****") == 2   # both masked, both times


# ---- graceful skip ---------------------------------------------------------

def test_every_scanner_skips_cleanly_when_tool_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(base.shutil, "which", lambda cmd: None)
    for scanner in ALL_SCANNERS:
        result = scanner.run([Path("x.php")], tmp_path, excludes=None)
        assert result == []                   # never crashes, returns empty
    printed = capsys.readouterr().out
    assert printed.count("skip:") == len(ALL_SCANNERS)


# ---- a broken tool must not look like a clean result -----------------------

class FakeExcludes:
    """Minimal stand-in: scanners only ask it for tool flags."""

    def __init__(self, report_dir):
        self.report_dir = report_dir

    def semgrep_args(self):
        return []

    def trivy_args(self):
        return []

    def gitleaks_config_path(self):
        return self.report_dir / "gitleaks_config.toml"


def fake_run(returncode: int, stdout: str = "", stderr: str = ""):
    import subprocess
    return lambda argv, timeout=600: subprocess.CompletedProcess(
        argv, returncode, stdout, stderr)


def test_trivy_failing_to_reach_its_database_raises_instead_of_reporting_zero(
        tmp_path, monkeypatch):
    """The real-world case: trivy cannot download its vulnerability DB, so
    it exits non-zero with no output. Returning [] would tell the reader
    'no vulnerable dependencies' about a scan that never happened."""
    import scanners.dependency_scanner as dependency_module

    monkeypatch.setattr(dependency_module, "run_tool", fake_run(
        1, "", "FATAL failed to download vulnerability DB"))
    scanner = DependencyScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}", encoding="utf-8")

    with pytest.raises(base.ScannerFailed) as raised:
        scanner.run([lockfile], tmp_path, FakeExcludes(tmp_path))
    assert "vulnerability DB" in str(raised.value)
    assert raised.value.partial_findings == []


def test_semgrep_producing_no_output_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "run_tool", fake_run(2, "", "config error"))
    scanner = PhpScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    with pytest.raises(base.ScannerFailed) as raised:
        scanner.run([tmp_path / "a.php"], tmp_path, FakeExcludes(tmp_path))
    assert "config error" in str(raised.value)


def test_a_bad_ruleset_name_raises_instead_of_reporting_a_clean_scan(
        tmp_path, monkeypatch):
    """Semgrep answers a 404 ruleset with valid JSON: zero results, zero
    files scanned, and the reason buried in `errors`. Reporting that as
    "no problems found" would be a lie about a scan that read nothing."""
    aborted = json.dumps({
        "results": [],
        "errors": [{"type": "SemgrepError",
                    "message": "Failed to download configuration from "
                               "https://semgrep.dev/c/p/laravel HTTP 404."}],
        "paths": {"scanned": []},
    })
    monkeypatch.setattr(base, "run_tool", fake_run(0, aborted, ""))
    scanner = PhpScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    with pytest.raises(base.ScannerFailed) as raised:
        scanner.run([tmp_path / "a.php"], tmp_path, FakeExcludes(tmp_path))
    assert "404" in str(raised.value)


def test_semgrep_reporting_zero_scanned_files_is_never_clean(
        tmp_path, monkeypatch):
    """Coverage is still zero when Semgrep omits an error message. The
    paths it says it scanned are the evidence that the scan actually ran."""
    empty_coverage = json.dumps({
        "results": [],
        "errors": [],
        "paths": {"scanned": []},
    })
    monkeypatch.setattr(base, "run_tool", fake_run(0, empty_coverage, ""))
    scanner = PhpScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    with pytest.raises(base.ScannerFailed) as raised:
        scanner.run([tmp_path / "a.php"], tmp_path, FakeExcludes(tmp_path))
    assert "zero files were scanned" in str(raised.value)


def test_semgrep_invalid_json_is_reported_as_a_failed_scan(
        tmp_path, monkeypatch):
    monkeypatch.setattr(base, "run_tool", fake_run(2, "{broken", "fatal"))
    scanner = PhpScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    with pytest.raises(base.ScannerFailed) as raised:
        scanner.run([tmp_path / "a.php"], tmp_path, FakeExcludes(tmp_path))
    assert "invalid JSON" in str(raised.value)


def test_partial_semgrep_errors_still_report_the_files_that_worked(
        tmp_path, monkeypatch, capsys):
    """One unparseable file must not discard the findings from the rest -
    it warns instead of failing the whole scan."""
    partial = json.dumps({
        "results": [{
            "check_id": "php.sqli", "path": str(tmp_path / "ok.php"),
            "start": {"line": 1},
            "extra": {"message": "SQL injection", "severity": "ERROR", "metadata": {}},
        }],
        "errors": [{"type": "ParseError", "message": "broken.php: syntax error"}],
        "paths": {"scanned": [str(tmp_path / "ok.php")]},
    })
    monkeypatch.setattr(base, "run_tool", fake_run(1, partial, ""))
    scanner = PhpScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    findings = scanner.run([tmp_path / "ok.php"], tmp_path, FakeExcludes(tmp_path))
    assert len(findings) == 1
    assert scanner.last_warnings == ["broken.php: syntax error"]
    assert "warning: semgrep reported 1 error" in capsys.readouterr().out


def test_gitleaks_writing_no_report_raises(tmp_path, monkeypatch):
    import scanners.secrets_scanner as secrets_module

    monkeypatch.setattr(secrets_module, "run_tool", fake_run(1, "", "boom"))
    scanner = SecretsScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    with pytest.raises(base.ScannerFailed):
        scanner.run([tmp_path / "a.js"], tmp_path, FakeExcludes(tmp_path))


def test_gitleaks_never_reuses_a_stale_report(tmp_path, monkeypatch):
    import scanners.secrets_scanner as secrets_module

    stale_report = tmp_path / "gitleaks_findings.json"
    stale_report.write_text(json.dumps([{
        "RuleID": "stale-secret",
        "File": str(tmp_path / "old.env"),
        "StartLine": 1,
    }]), encoding="utf-8")
    monkeypatch.setattr(
        secrets_module, "run_tool", fake_run(1, "", "current run failed"))
    scanner = SecretsScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    with pytest.raises(base.ScannerFailed) as raised:
        scanner.run([tmp_path / "a.js"], tmp_path, FakeExcludes(tmp_path))
    assert raised.value.partial_findings == []
    assert not stale_report.exists()


def test_partial_failure_keeps_what_did_succeed(tmp_path, monkeypatch):
    """One lockfile parses, the next fails: the good findings survive and
    the failure is still reported."""
    import scanners.dependency_scanner as dependency_module

    good = (FIXTURES / "trivy_output.json").read_text(encoding="utf-8")
    calls = {"n": 0}

    def sometimes_broken(argv, timeout=600):
        import subprocess
        calls["n"] += 1
        if calls["n"] == 1:
            return subprocess.CompletedProcess(argv, 0, good, "")
        return subprocess.CompletedProcess(argv, 1, "", "network unreachable")

    monkeypatch.setattr(dependency_module, "run_tool", sometimes_broken)
    scanner = DependencyScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    first = tmp_path / "package-lock.json"
    first.write_text("{}", encoding="utf-8")
    second = tmp_path / "composer.lock"
    second.write_text("{}", encoding="utf-8")

    with pytest.raises(base.ScannerFailed) as raised:
        scanner.run([first, second], tmp_path, FakeExcludes(tmp_path))
    assert len(raised.value.partial_findings) == 2      # the good lockfile
    assert "composer.lock" in str(raised.value)


# ---- the one list ----------------------------------------------------------

def test_all_scanners_declare_the_full_contract():
    scan_types = [s.scan_type for s in ALL_SCANNERS]
    assert len(scan_types) == len(set(scan_types)) == 5
    for scanner in ALL_SCANNERS:
        assert scanner.label and scanner.file_types and scanner.tool_cmd
