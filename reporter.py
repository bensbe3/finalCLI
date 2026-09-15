"""
reporter.py — writes the two output files, and nothing else.

RECEIVES:  the final consolidated list[Finding] + an output folder + a
           `meta` dict describing the run (target, timestamp, which
           scans ran / were skipped / were PARTIAL, warnings, routed vs
           confirmed-scanned counts, coverage declarations)
PRODUCES:  report.html (self-contained: plain HTML, inline styles,
           NO JavaScript) and report.json (its twin)
CALLED BY: main.py — the last step of the pipeline

Honesty rules encoded here:
  * every finding is labelled with the tool that found it, plus its
    confidence, so a reader can weigh it;
  * the snippet shown is the one captured at scan time by the scanner,
    not re-read now, so the report reflects the code as scanned;
  * incomplete (FAILED/skipped) and PARTIAL scans are called out before
    a reader can treat a low finding count as a clean bill of health;
  * dependency cards show usage evidence when present, without claiming
    full reachability;
  * a Limitations section states plainly what static analysis cannot do;
  * the same LIMITATIONS / STANDARDS text feeds both HTML and JSON, so
    the two files can never disagree.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import TextLexer, get_lexer_for_filename
from pygments.util import ClassNotFound

from models import Finding, Severity

TEMPLATE_NAME = "reporter_template.html"

# Colour per severity, used by the finding cards.
SEVERITY_COLOURS = {
    "CRITICAL": "#b3123a",
    "HIGH": "#d9480f",
    "MEDIUM": "#b98700",
    "LOW": "#1c7ed6",
    "INFO": "#6c757d",
}

LIMITATIONS = [
    "This is STATIC analysis only. Nothing was executed, no requests were sent, "
    "and no running system was tested. A finding describes code as written, not "
    "proven exploitability.",
    "Detection is tool- and pattern-based, so FALSE POSITIVES are expected. Every "
    "finding needs manual triage before it is treated as a real vulnerability.",
    "Absence of findings is not proof of safety (false negatives). Coverage is "
    "limited to the file types routed to the tools that were installed at scan time.",
    "Direct dependency references are evidence of package use, not full call-path "
    "reachability. No direct reference found is NOT proof that a framework or "
    "transitive dependency cannot load the vulnerable code.",
    "Severity is reported as the tool assigned it. It reflects the general class of "
    "issue, not the business impact in this specific application.",
    "Attack scenarios in this report are ILLUSTRATIVE textbook descriptions included "
    "for explanation only. They were not attempted against this code.",
    "This report quotes excerpts of the scanned source code. Secret values found by "
    "the secrets scan are masked, but the report should still be treated as SENSITIVE "
    "and shared with the same care as the code itself.",
    "EPSS is a PREDICTION about the world, not a measurement of this application. It "
    "estimates the chance a vulnerability is exploited somewhere in the next 30 days. "
    "This report labels scores of 10% or more as 'likely exploited' for prioritisation. "
    "A low score is a reason to deprioritise, never a guarantee of safety.",
    "The CISA KEV catalogue lists vulnerabilities CONFIRMED to be exploited in the "
    "wild, so being listed is strong evidence. It is not exhaustive, however - absence "
    "from KEV does not mean nobody is exploiting the issue.",
    "Exploitation data exists only for findings with a CVE id or an explicit CVE alias "
    "supplied by Trivy. Other findings are marked 'not applicable', which is NOT a "
    "judgement that they are low risk.",
]

STANDARDS = [
    "OWASP Top 10:2021 - category mapping for each finding",
    "CWE Top 25 - the weakness identifiers used throughout",
    "MITRE CAPEC - attack-pattern context behind the illustrative scenarios",
    "OWASP ASVS - verification requirements to triage findings against",
    "ISO/IEC 27034 - application security management framework",
    "NIST SSDF (SP 800-218) - secure software development practices",
    "NIST NVD - the CVE data source behind dependency findings",
    "FIRST EPSS - exploit prediction scores used to prioritise CVE findings",
    "CISA KEV - catalogue of vulnerabilities known to be exploited in the wild",
]

# Colour per exploitation status, so the urgent ones are visible at a glance.
EXPLOIT_COLOURS = {
    "actively exploited": "#b3123a",
    "likely exploited": "#d9480f",
    "unlikely": "#2b8a3e",
}


def write(findings: list[Finding], out_dir: Path, meta: dict) -> tuple[Path, Path]:
    """Write report.html + report.json. Returns both paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = build_summary(findings)
    coverage = build_coverage(meta)
    findings_index = build_findings_index(findings, meta)
    scan_statuses = meta.get("scan_status_by_type", {})

    json_path = out_dir / "report.json"
    json_path.write_text(
        json.dumps(
            {
                "meta": meta,
                "summary": summary,
                "incomplete_scans": incomplete_scans(meta),
                "partial_scans": partial_scans(meta),
                "coverage": coverage,
                "findings_index": findings_index,
                "findings": [finding_to_dict(f) for f in findings],
                "limitations": LIMITATIONS,
                "standards_referenced": STANDARDS,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    environment = Environment(
        loader=FileSystemLoader(Path(__file__).parent),
        autoescape=select_autoescape(["html"]),
    )
    html = environment.get_template(TEMPLATE_NAME).render(
        meta=meta,
        summary=summary,
        findings=[
            view_of(f, scan_statuses.get(f.scan_type, "unknown"))
            for f in findings
        ],
        findings_index=findings_index,
        coverage=coverage,
        limitations=LIMITATIONS,
        standards=STANDARDS,
        incomplete=incomplete_scans(meta),
        partial=partial_scans(meta),
    )
    html_path = out_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")
    return html_path, json_path


# ---- summary ---------------------------------------------------------------

def incomplete_scans(meta: dict) -> list[dict]:
    """Scans that were skipped or that failed outright.

    Both mean the same thing to a reader: that area was NOT checked, so
    zero findings there proves nothing. The report has to say so, or it
    quietly overstates how much ground it covered.
    """
    return [
        scan for scan in meta.get("scans", [])
        if scan["status"].startswith("FAILED") or scan["status"].startswith("skipped")
    ]


def partial_scans(meta: dict) -> list[dict]:
    """Scans that returned results but reported incomplete analysis."""
    return [
        scan for scan in meta.get("scans", [])
        if scan["status"].startswith("PARTIAL")
    ]


def build_coverage(meta: dict) -> dict:
    """Describe what the selected scanners did and did not receive.

    An unrouted file type is information, not proof of a vulnerability gap:
    it may be documentation or an asset. We therefore do not call a run
    "complete" merely because every selected tool exited successfully.
    """
    declared_types: set[str] = set()
    for scanner in meta.get("scanner_declarations", []):
        if scanner.get("scan_type") == "secrets":
            continue
        declared_types.update(scanner.get("file_types", []))

    unrouted = [
        {"file_type": file_type, "files": count}
        for file_type, count in meta.get("files_by_type", {}).items()
        if count and file_type not in declared_types
    ]
    unrouted.sort(key=lambda item: (-item["files"], item["file_type"]))

    incomplete = incomplete_scans(meta)
    partial = partial_scans(meta)
    return {
        "selected_scans_completed": not incomplete and not partial,
        "status": (
            "selected scans incomplete" if incomplete
            else "selected scans completed with warnings" if partial
            else "all selected scans completed"
        ),
        "unrouted_file_types": unrouted,
        "no_matching_scans": [
            scan for scan in meta.get("scans", [])
            if scan.get("status") == "no matching files"
        ],
    }


def build_findings_index(findings: list[Finding], meta: dict) -> list[dict]:
    """Compact, location-first rows for fast triage in HTML and JSON."""
    statuses = meta.get("scan_status_by_type", {})
    rows: list[dict] = []
    for number, finding in enumerate(findings, start=1):
        message = " ".join(finding.message.split())
        if len(message) > 120:
            message = message[:119].rstrip() + "…"
        rows.append({
            "number": number,
            "severity": finding.severity.name,
            "location": location_of(finding),
            "file": finding.file,
            "line": finding.line,
            "tool": finding.tool,
            "scan_type": finding.scan_type,
            "scan_status": statuses.get(finding.scan_type, "unknown"),
            "identity": identity_of(finding),
            "explanation": message,
            "exploit_status": finding.exploit_status,
        })
    return rows


def build_summary(findings: list[Finding]) -> dict:
    """Counts the report leads with; all five severity keys stay visible."""
    by_severity = Counter(f.severity.name for f in findings)
    return {
        "total": len(findings),
        "by_severity": {
            name: by_severity.get(name, 0)
            for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
        "by_tool": dict(sorted(Counter(f.tool for f in findings).items())),
        "by_confidence": {
            level: sum(1 for f in findings if f.confidence == level)
            for level in ("high", "medium", "low")
        },
        # What is actually being attacked in the real world. This is the
        # number that tells a reader where to start.
        "actively_exploited": sum(1 for f in findings if f.kev),
        "by_exploitation": dict(sorted(
            Counter(f.exploit_status for f in findings).items())),
    }


def finding_to_dict(finding: Finding) -> dict:
    """JSON shape: the dataclass plus its fingerprint, with the enum
    rendered as both a name and a number."""
    data = asdict(finding)
    data["severity"] = finding.severity.name
    data["severity_rank"] = int(finding.severity)
    data["fingerprint"] = list(finding.fingerprint)
    return data


# ---- per-finding view ------------------------------------------------------

def view_of(finding: Finding, scan_status: str = "unknown") -> dict:
    """Everything the template needs for one finding, pre-computed here
    so the template stays plain markup."""
    return {
        "location": location_of(finding),
        "file": finding.file,
        "line": finding.line,
        "identity": identity_of(finding),
        "severity": finding.severity.name,
        "severity_colour": SEVERITY_COLOURS[finding.severity.name],
        "confidence": finding.confidence,
        "tool": finding.tool,
        "scan_type": finding.scan_type,
        "scan_status": scan_status,
        "rule_id": finding.rule_id,
        "message": finding.message,
        "cwe": finding.cwe or "unmapped",
        "owasp": finding.owasp,
        "remediation": finding.remediation,
        "scenario": finding.scenario,
        "snippet": highlight_snippet(finding.snippet, finding.file),
        "is_dependency": bool(finding.advisory_id),
        "advisory_aliases": finding.advisory_aliases,
        "usage_status": finding.usage_status,
        "usage_note": finding.usage_note,
        "usage_evidence": finding.usage_evidence,
        # Real-world exploitation (CISA KEV + FIRST EPSS)
        "exploit_status": finding.exploit_status,
        "exploit_colour": EXPLOIT_COLOURS.get(finding.exploit_status, "#6c757d"),
        "exploit_note": finding.exploit_note,
        "kev": finding.kev,
        "epss_percent": (f"{finding.epss * 100:.1f}%"
                         if finding.epss is not None else ""),
        "epss_percentile": (
            f"{finding.epss_percentile * 100:.1f}th percentile"
            if finding.epss_percentile is not None else ""
        ),
    }


def location_of(finding: Finding) -> str:
    """file:line for code findings; a line of 0 means the line number is
    not meaningful, so it is left off."""
    return f"{finding.file}:{finding.line}" if finding.line else finding.file


def identity_of(finding: Finding) -> str:
    """What this finding IS, by its own identity rule: a dependency
    finding is a package + advisory, a code finding is its rule."""
    if finding.advisory_id:
        return f"{finding.package} - {finding.advisory_id}"
    return finding.rule_id


def highlight_snippet(snippet: str, filename: str) -> Markup:
    """Re-render the snippet captured at scan time as highlighted HTML.

    capture_snippet() (scanners/base.py) produced lines shaped
    ">    3 | code" - a marker, a line number, then the code. We split
    that back apart so the gutter stays plain text and only the CODE is
    highlighted. Each line is highlighted on its own, which keeps the
    HTML well-formed (a token can never span two lines).
    """
    if not snippet:
        return Markup("")

    try:
        lexer = get_lexer_for_filename(filename, stripnl=False)
    except ClassNotFound:
        lexer = TextLexer(stripnl=False)
    # noclasses=True writes inline styles, so the HTML needs no stylesheet.
    formatter = HtmlFormatter(nowrap=True, noclasses=True)

    rows = []
    for raw_line in snippet.splitlines():
        marker, number, code = split_snippet_line(raw_line)
        if code.strip():
            coloured = highlight(code, lexer, formatter).rstrip("\n")
        else:
            coloured = escape(code)
        # The vulnerable line is tinted, so it reads even in print/greyscale.
        row_style = "background:#fff4f4;" if marker == ">" else ""
        rows.append(
            f'<div class="code-line" style="{row_style}">'
            f'<span class="gutter">{escape(marker)}{escape(number)}</span>'
            f'<span class="code">{coloured}</span></div>'
        )
    return Markup("".join(rows))


def split_snippet_line(raw_line: str) -> tuple[str, str, str]:
    """Split ">    3 | code" into ('>', '    3', 'code'). Anything that
    does not match that shape is treated as plain code."""
    if raw_line[:1] in (">", " "):
        marker, rest = raw_line[:1], raw_line[1:]
    else:
        marker, rest = "", raw_line
    number, separator, code = rest.partition(" | ")
    if not separator:
        return "", "", raw_line
    return marker, number, code
