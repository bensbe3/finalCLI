"""Phase 1 tests: Finding fingerprints — the identity rules that keep
future history/delta tracking honest."""

from models import Finding, Severity


def make_dep_finding(line: int) -> Finding:
    return Finding(
        file="package-lock.json",
        line=line,
        rule_id="trivy-vuln",
        message="lodash prototype pollution",
        severity=Severity.HIGH,
        tool="trivy",
        package="lodash",
        advisory_id="CVE-2020-8203",
    )


def test_dependency_fingerprint_ignores_line_number():
    """A lockfile line can shift for unrelated reasons — identity must
    be (package, advisory), never the line."""
    at_line_10 = make_dep_finding(line=10)
    at_line_99 = make_dep_finding(line=99)
    assert at_line_10.fingerprint == at_line_99.fingerprint
    assert at_line_10.fingerprint == ("dep", "lodash", "CVE-2020-8203")


def test_code_fingerprint_uses_file_line_and_rule():
    base = dict(
        rule_id="php.sqli",
        message="SQL injection",
        severity=Severity.CRITICAL,
        tool="semgrep",
    )
    a = Finding(file="a.php", line=5, **base)
    same = Finding(file="a.php", line=5, **base)
    other_line = Finding(file="a.php", line=6, **base)
    assert a.fingerprint == same.fingerprint
    assert a.fingerprint != other_line.fingerprint


def test_severity_maps_tool_words_and_orders_correctly():
    assert Severity.from_text("ERROR") == Severity.HIGH      # semgrep
    assert Severity.from_text("WARNING") == Severity.MEDIUM  # semgrep
    assert Severity.from_text("CRITICAL") == Severity.CRITICAL
    assert Severity.from_text("weird-unknown-word") == Severity.LOW
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
