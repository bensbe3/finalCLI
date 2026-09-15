"""Phase 4 tests: the two output files. The report must be honest
(tool + confidence + limitations shown) and self-contained (no scripts,
no external URLs — it has to open offline, anywhere)."""

import json

import consolidator
import exploitability
import reporter
from models import Finding, Severity


def make_meta() -> dict:
    return {
        "target": "sample_vuln_app",
        "generated_at": "2026-07-30 12:00:00",
        "duration_seconds": 1.5,
        "files_collected": 7,
        "files_by_type": {".php": 2, ".rb": 3, "package-lock.json": 1, ".txt": 1},
        "scans": [
            {"label": "PHP code scan (Semgrep)", "scan_type": "php", "tool": "semgrep",
             "files_selected": 2, "status": "ran", "findings": 1},
            {"label": "Secrets scan (Gitleaks)", "scan_type": "secrets", "tool": "gitleaks",
             "files_selected": 7, "status": "skipped: gitleaks not installed", "findings": 0},
        ],
        "scanner_declarations": [
            {"scan_type": "php", "label": "PHP code scan (Semgrep)",
             "file_types": [".php", ".php5", ".phtml"]},
            {"scan_type": "secrets", "label": "Secrets scan (Gitleaks)",
             "file_types": ["*"]},
        ],
        "scan_status_by_type": {
            "php": "ran",
            "secrets": "skipped: gitleaks not installed",
        },
    }


def make_findings() -> list[Finding]:
    return consolidator.merge([make_findings_raw()])   # enriches + sorts


def make_findings_raw() -> list[Finding]:
    code = Finding(
        file="src/login.php",
        line=3,
        rule_id="php.lang.security.tainted-sql-string",
        message="User input flows into a SQL query string.",
        severity=Severity.HIGH,
        tool="semgrep",
        scan_type="php",
        confidence="high",
        cwe="CWE-89",
        snippet="     2 | $id = $_GET['id'];\n>    3 | $q = \"SELECT * FROM users WHERE id = $id\";",
    )
    dependency = Finding(
        file="package-lock.json",
        line=12,
        rule_id="CVE-2020-8203",
        message="lodash 4.17.15: prototype pollution (fixed in 4.17.19)",
        severity=Severity.MEDIUM,
        tool="trivy",
        scan_type="dependencies",
        confidence="high",
        cwe="CWE-1321",
        package="lodash",
        advisory_id="CVE-2020-8203",
        usage_status="no direct reference found",
        usage_note="This is not proof that it is unreachable.",
    )
    return [code, dependency]


def write_report(tmp_path):
    html_path, json_path = reporter.write(make_findings(), tmp_path / "reports", make_meta())
    return (
        html_path.read_text(encoding="utf-8"),
        json.loads(json_path.read_text(encoding="utf-8")),
    )


# ---- self-contained ---------------------------------------------------------

def test_html_has_no_javascript_and_no_external_urls(tmp_path):
    html, _ = write_report(tmp_path)
    assert "<script" not in html.lower()
    assert "http://" not in html and "https://" not in html
    assert "src=" not in html                      # nothing to fetch
    assert "<svg" not in html                      # compact text summary only


# ---- honesty ---------------------------------------------------------------

def test_html_labels_tool_confidence_cwe_and_owasp(tmp_path):
    html, _ = write_report(tmp_path)
    assert "found by: semgrep" in html
    assert "found by: trivy" in html
    assert "confidence: high" in html
    assert "CWE-89" in html and "A03:2021" in html
    assert "File path:" in html and "src/login.php" in html
    assert "Tool explanation:" in html


def test_html_includes_limitations_and_standards(tmp_path):
    html, _ = write_report(tmp_path)
    assert "Limitations" in html
    assert "STATIC analysis only" in html
    assert "FALSE POSITIVES" in html
    assert "OWASP Top 10:2021" in html and "NIST NVD" in html


def test_routing_table_shows_files_selected_and_skips(tmp_path):
    """The report must record what each scan actually received, so the
    routing is verifiable after the fact."""
    html, _ = write_report(tmp_path)
    assert "Files routed" in html
    assert "skipped: gitleaks not installed" in html
    assert "Not routed to a selected code/dependency scanner" in html


# ---- snippets -------------------------------------------------------------

def test_snippet_is_highlighted_and_keeps_the_vulnerable_line_marker(tmp_path):
    html, _ = write_report(tmp_path)
    assert "SELECT" in html
    assert 'class="gutter"' in html
    assert "style=" in html                        # Pygments inline styles
    assert "&gt;    3" in html                     # the marked vulnerable line


def test_dependency_identity_is_package_and_advisory_not_a_line(tmp_path):
    html, _ = write_report(tmp_path)
    assert "lodash - CVE-2020-8203" in html
    assert "identified by package and advisory" in html
    assert "Direct usage evidence:" in html
    assert "not proof that it is unreachable" in html


def test_findings_index_is_location_first_and_lists_tool_explanation(tmp_path):
    html, data = write_report(tmp_path)
    assert "Quick findings list" in html
    assert html.index("src/login.php:3") < html.index(
        "php.lang.security.tainted-sql-string")
    row = next(item for item in data["findings_index"]
               if item["tool"] == "semgrep")
    assert row["location"] == "src/login.php:3"
    assert row["scan_type"] == "php"
    assert "User input flows" in row["explanation"]


def test_json_records_visible_coverage_boundaries(tmp_path):
    _, data = write_report(tmp_path)
    assert data["coverage"]["selected_scans_completed"] is False
    gaps = {item["file_type"]: item["files"]
            for item in data["coverage"]["unrouted_file_types"]}
    assert gaps[".rb"] == 3


def test_partial_scan_warnings_are_visible_in_html_and_json(tmp_path):
    meta = make_meta()
    meta["scans"][0]["status"] = "PARTIAL - 1 tool warning(s)"
    meta["scans"][0]["warnings"] = ["src/Broken.tsx: syntax error"]
    meta["scans"][1]["status"] = "no matching files"
    meta["scan_status_by_type"]["php"] = meta["scans"][0]["status"]
    meta["scan_status_by_type"]["secrets"] = meta["scans"][1]["status"]

    html_path, json_path = reporter.write(
        make_findings(), tmp_path / "reports", meta)
    html = html_path.read_text(encoding="utf-8")
    data = json.loads(json_path.read_text(encoding="utf-8"))

    assert "Some scans were only partial" in html
    assert "src/Broken.tsx: syntax error" in html
    assert data["partial_scans"][0]["scan_type"] == "php"
    assert data["coverage"]["status"] == "selected scans completed with warnings"


# ---- JSON twin ------------------------------------------------------------

def test_json_twin_mirrors_everything(tmp_path):
    _, data = write_report(tmp_path)
    assert data["summary"]["total"] == 2
    assert data["summary"]["by_tool"] == {"semgrep": 1, "trivy": 1}
    assert data["summary"]["by_severity"]["HIGH"] == 1
    assert data["limitations"] == reporter.LIMITATIONS
    assert data["standards_referenced"] == reporter.STANDARDS

    dependency = next(f for f in data["findings"] if f["tool"] == "trivy")
    assert dependency["fingerprint"] == ["dep", "lodash", "CVE-2020-8203"]
    assert dependency["severity"] == "MEDIUM"
    code = next(f for f in data["findings"] if f["tool"] == "semgrep")
    assert code["fingerprint"] == ["code", "src/login.php", 3,
                                   "php.lang.security.tainted-sql-string"]


# ---- degenerate case ------------------------------------------------------

def test_actively_exploited_findings_get_a_fix_these_first_banner(tmp_path):
    catalogue = exploitability.Catalogue(
        available=True,
        source_note="CISA KEV + FIRST EPSS, fetched just now",
        entries={"CVE-2020-8203": exploitability.Exploitability(
            status=exploitability.ACTIVELY_EXPLOITED, kev=True, epss=0.93,
            percentile=0.99,
            note="CISA lists this as exploited in the wild.")},
    )
    findings = consolidator.merge([make_findings_raw()], catalogue)
    meta = make_meta()
    meta["exploitation_available"] = True
    meta["exploitation_source"] = catalogue.source_note
    html_path, json_path = reporter.write(findings, tmp_path / "reports", meta)
    html = html_path.read_text(encoding="utf-8")

    assert "Fix these first" in html
    assert "exploited in the wild" in html
    assert "EPSS 93.0%" in html
    assert "99.0th percentile" in html
    # and it is the first finding shown, above the more severe code finding
    assert html.index("lodash - CVE-2020-8203") < html.index("tainted-sql-string")

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["actively_exploited"] == 1
    dependency = next(f for f in data["findings"] if f["tool"] == "trivy")
    assert dependency["kev"] is True
    assert dependency["epss"] == 0.93
    assert dependency["exploit_status"] == "actively exploited"


def test_report_says_unknown_not_safe_when_the_lookup_failed(tmp_path):
    """A lookup that never happened must not read as 'nothing is exploited'."""
    findings = consolidator.merge([make_findings_raw()])   # no catalogue
    meta = make_meta()
    meta["exploitation_available"] = False
    meta["exploitation_source"] = "Lookup failed (CISA KEV unreachable)"
    html_path, _ = reporter.write(findings, tmp_path / "reports", meta)
    html = html_path.read_text(encoding="utf-8")

    assert "Fix these first" not in html          # no false calm, no false alarm
    assert "Lookup failed" in html
    assert "the honest word is" in html
    assert "unknown - lookup unavailable" in html


def test_empty_findings_still_renders_both_files(tmp_path):
    html_path, json_path = reporter.write([], tmp_path / "reports", make_meta())
    html = html_path.read_text(encoding="utf-8")
    assert "No findings were reported" in html
    assert "proof the code is safe" in html         # honest about false negatives
    assert "At a glance" in html
    assert json.loads(json_path.read_text(encoding="utf-8"))["summary"]["total"] == 0
