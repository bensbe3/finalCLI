"""Phase 3 tests: fingerprint dedupe, enrichment, and ordering."""

import consolidator
import exploitability
from models import Finding, Severity


def code_finding(**overrides) -> Finding:
    values = dict(
        file="src/login.php",
        line=3,
        rule_id="php.sqli",
        message="SQL injection",
        severity=Severity.HIGH,
        tool="semgrep",
        cwe="CWE-89",
    )
    values.update(overrides)
    return Finding(**values)


def dep_finding(line: int, severity=Severity.HIGH) -> Finding:
    return Finding(
        file="package-lock.json",
        line=line,
        rule_id="CVE-2020-8203",
        message="lodash prototype pollution",
        severity=severity,
        tool="trivy",
        cwe="CWE-1321",
        package="lodash",
        advisory_id="CVE-2020-8203",
    )


def test_same_fingerprint_collapses_to_one():
    merged = consolidator.merge([[code_finding()], [code_finding()]])
    assert len(merged) == 1


def test_dependency_duplicates_collapse_even_with_different_lines():
    """The spec's key rule: (package, advisory) is the identity — a
    shifted lockfile line must NOT create a second finding."""
    merged = consolidator.merge([[dep_finding(line=10)], [dep_finding(line=99)]])
    assert len(merged) == 1


def test_duplicate_keeps_the_higher_severity():
    low = dep_finding(line=10, severity=Severity.MEDIUM)
    high = dep_finding(line=10, severity=Severity.CRITICAL)
    merged = consolidator.merge([[low], [high]])
    assert merged[0].severity == Severity.CRITICAL


def test_enrichment_fills_owasp_remediation_scenario():
    merged = consolidator.merge([[code_finding()]])
    f = merged[0]
    assert f.owasp.startswith("A03")
    assert "prepared statements" in f.remediation
    assert f.scenario  # illustrative text present


def test_unknown_cwe_gets_safe_fallback_not_a_crash():
    merged = consolidator.merge([[code_finding(cwe="CWE-99999")]])
    assert merged[0].owasp == "Not mapped by this report"
    assert "tool's explanation" in merged[0].remediation


def test_unknown_cwe_keeps_owasp_category_supplied_by_the_tool():
    merged = consolidator.merge([[
        code_finding(cwe="CWE-99999", owasp="A04:2021 - Insecure Design")
    ]])
    assert merged[0].owasp == "A04:2021 - Insecure Design"


def test_actively_exploited_sorts_above_a_more_severe_finding():
    """The whole point of the exploitation data: a MEDIUM that attackers are
    using today outranks a CRITICAL nobody has touched."""
    critical_code = code_finding(rule_id="sqli", severity=Severity.CRITICAL)
    exploited_dep = dep_finding(line=5, severity=Severity.MEDIUM)

    catalogue = exploitability.Catalogue(
        available=True,
        entries={"CVE-2020-8203": exploitability.Exploitability(
            status=exploitability.ACTIVELY_EXPLOITED, kev=True, epss=0.9)},
    )
    merged = consolidator.merge([[critical_code, exploited_dep]], catalogue)

    assert merged[0].advisory_id == "CVE-2020-8203"
    assert merged[0].kev is True
    assert merged[1].rule_id == "sqli"


def test_missing_exploitation_data_never_demotes_a_finding():
    """No catalogue means we know nothing - severity order must be unchanged,
    so a CRITICAL code finding cannot fall below an unknown dependency."""
    merged = consolidator.merge([[
        code_finding(rule_id="sqli", severity=Severity.CRITICAL),
        dep_finding(line=5, severity=Severity.LOW),
    ]])
    assert merged[0].rule_id == "sqli"
    assert merged[0].exploit_status == exploitability.NOT_APPLICABLE
    assert merged[1].exploit_status == exploitability.LOOKUP_UNAVAILABLE
    assert merged[1].kev is False


def test_sorted_most_severe_first():
    merged = consolidator.merge([[
        code_finding(rule_id="a", severity=Severity.LOW),
        code_finding(rule_id="b", severity=Severity.CRITICAL),
        code_finding(rule_id="c", severity=Severity.MEDIUM),
    ]])
    assert [f.severity for f in merged] == [
        Severity.CRITICAL, Severity.MEDIUM, Severity.LOW,
    ]
