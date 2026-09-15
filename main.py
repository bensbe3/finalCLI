"""
main.py — the CLI entry point and the ONLY module that calls the others.

RECEIVES:  command-line arguments, or the user's menu choice
PRODUCES:  orchestration only — this file owns no analysis logic
CALLED BY: the user

Read run_scans() top-to-bottom and you have the whole program:

    excludes.prepare(...)          write the one exclude list outward
    collector.collect(...)         one walk  -> FileSet
    router.route(fileset, scanner)  intersection -> this scanner's files
    print("PHP scan -> 42 files selected")      routing made visible
    scanner.run(files, ...)        -> list[Finding] (snippets attached)
    consolidator.merge(...)        -> deduped + enriched
    dependency_usage.enrich(...)   -> conservative direct-use evidence
    reporter.write(...)            -> report.html + report.json

Every arrow above goes through this file. No module calls another
behind its back, which is why the data flow is readable in one place.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

import collector
import consolidator
import dependency_usage
import excludes as excludes_module
import exploitability
import reporter
import router
from scanners import ALL_SCANNERS
from scanners.base import ScannerFailed

# ---- extension seams (future work — see extensions/) ----------------------
# These are deliberately empty no-ops. Their call sites are shown here so
# adding them later restructures nothing:
#
#   from extensions.ai_advisor import explain_findings
#   from extensions.history import record_scan
#   from extensions.correlation import correlate
#
# ...and inside run_scans(), immediately after consolidation:
#
#   findings = explain_findings(findings)   # AI recommendation engine
#   record_scan(findings, report_dir)       # scan history / delta tracking
#   findings = correlate(findings)          # cross-scanner risk correlation


def build_parser() -> argparse.ArgumentParser:
    """CLI flags for non-interactive/CI use. The scan choices come from
    ALL_SCANNERS, so they can never drift from the menu."""
    scan_types = [scanner.scan_type for scanner in ALL_SCANNERS]
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="Static security analysis: routes files to Semgrep, Trivy and Gitleaks, "
                    "then consolidates their findings into one report.",
    )
    parser.add_argument("target", nargs="?", default=".",
                        help="folder to scan (default: current folder)")
    parser.add_argument("--scan", choices=scan_types,
                        help="run one scan without the menu")
    parser.add_argument("--all", action="store_true",
                        help="run every scan without the menu")
    parser.add_argument("--report", default="reports",
                        help="folder for report.html + report.json (default: reports)")
    parser.add_argument("--offline", action="store_true",
                        help="do not look up real-world exploitation data "
                             "(CISA KEV + FIRST EPSS); findings are then "
                             "reported as 'unknown', never as 'not exploited'")
    return parser


def choose_scanners_interactively() -> list:
    """The menu is GENERATED from ALL_SCANNERS — menu, --scan choices and
    'run all' are three views of one list, so they cannot fall out of sync."""
    print("\nWhich scan would you like to run?\n")
    for number, scanner in enumerate(ALL_SCANNERS, start=1):
        availability = "" if scanner.is_available() else f"  (needs {scanner.tool_cmd}, not installed)"
        print(f"  {number}. {scanner.label}{availability}")
    run_all_choice = len(ALL_SCANNERS) + 1
    print(f"  {run_all_choice}. Run everything at once")
    print("  0. Quit")

    while True:
        try:
            raw = input("\nChoice: ")
        except (EOFError, KeyboardInterrupt):
            # No terminal attached (piped input, CI, docker without -it).
            print("\nNo choice received. Use --scan <type> or --all to run "
                  "without the menu.")
            return []
        answer = raw.strip().lstrip("﻿")  # Windows pipes can prefix a BOM
        if answer == "0":
            return []
        if answer.isdigit():
            number = int(answer)
            if number == run_all_choice:
                return list(ALL_SCANNERS)
            if 1 <= number <= len(ALL_SCANNERS):
                return [ALL_SCANNERS[number - 1]]
        print(f"  Please enter a number between 0 and {run_all_choice}.")


def run_scans(target: Path, report_dir: Path, chosen: list,
              offline: bool = False) -> int:
    """The traced run. Read this function to understand the program."""
    started = time.time()
    print(f"\nTarget folder : {target}")
    print(f"Report folder : {report_dir}")

    # 1. The one exclude list, written outward into each tool's own format,
    #    ONCE, before anything is collected or scanned.
    excludes = excludes_module.prepare(target, report_dir)

    # 2. One walk of the folder, grouping files by type.
    fileset = collector.collect(target, excludes)
    print(f"\nCollected {fileset.count()} file(s) in "
          f"{len(fileset.buckets)} type group(s).")

    findings_per_scanner: list[list] = []
    scan_records: list[dict] = []

    for scanner in chosen:
        # 3. Ask the router which files this scanner declared it wants.
        files = router.route(fileset, scanner)

        # 4. Make the routing VISIBLE before anything runs.
        print(f"\n{scanner.label} -> {len(files)} file(s) selected")

        # 5. Run the tool on exactly those files (or skip cleanly).
        scanner.last_files_scanned = None
        scanner.last_warnings = []
        if not scanner.is_available():
            status = f"skipped: {scanner.tool_cmd} not installed"
        elif not files:
            status = "no matching files"
        else:
            status = "ran"

        try:
            found = scanner.run(files, target, excludes)
        except ScannerFailed as failure:
            # The tool was installed but broke (e.g. trivy could not reach
            # its vulnerability database). Say so loudly: zero findings from
            # a scan that never ran must never look like a clean result.
            found = failure.partial_findings
            status = f"FAILED - {failure}"
            print(f"  FAILED: {failure}")
            print(f"  ^ this scan did NOT complete - treat its result as unknown, "
                  f"not as 'nothing found'")

        if status == "ran" and scanner.last_warnings:
            status = f"PARTIAL - {len(scanner.last_warnings)} tool warning(s)"
            print("  ^ this scan completed with coverage warnings; some code "
                  "may not have been analysed")

        print(f"  {len(found)} finding(s) from {scanner.tool_cmd}")

        findings_per_scanner.append(found)
        scan_records.append({
            "label": scanner.label,
            "scan_type": scanner.scan_type,
            "tool": scanner.tool_cmd,
            "rulesets": list(getattr(scanner, "rulesets", [])),
            "scope": (
                "whole target directory (shared excludes applied)"
                if scanner.scan_type == "secrets" else "routed files"
            ),
            "files_selected": len(files),
            "files_scanned": scanner.last_files_scanned,
            "warnings": list(scanner.last_warnings),
            "status": status,
            "findings": len(found),
        })

    # 6. Ask the two public sources which of these CVEs are actually being
    #    attacked. This is what lets the report say "fix THIS one first"
    #    instead of showing twenty identical HIGH labels.
    advisory_ids = {
        advisory_id
        for group in findings_per_scanner
        for finding in group
        for advisory_id in [finding.advisory_id, *finding.advisory_aliases]
        if advisory_id
    }
    catalogue = exploitability.fetch(
        advisory_ids,
        cache_path=report_dir / "exploitability_cache.json",
        offline=offline,
    )
    if advisory_ids:
        print(f"\nExploitation data: {catalogue.source_note}")

    # 7. Merge everything: dedupe by fingerprint, enrich each CWE, attach
    #    the exploitation data, and sort real attacks to the top.
    findings = consolidator.merge(findings_per_scanner, catalogue)
    dependency_usage.enrich(findings, fileset, target)
    print(f"Consolidated to {len(findings)} unique finding(s).")

    exploited = [f for f in findings if f.kev]
    if exploited:
        print(f"\n{len(exploited)} finding(s) are on CISA's actively-exploited "
              f"list - fix these first:")
        for finding in exploited:
            print(f"  - {finding.package} {finding.advisory_id}")

    # 8. Write the two output files.
    meta = {
        "target": str(target),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round(time.time() - started, 2),
        "files_collected": fileset.count(),
        "files_by_type": {
            file_type or "(no extension)": len(paths)
            for file_type, paths in sorted(fileset.buckets.items())
        },
        "scans": scan_records,
        "scanner_declarations": [
            {
                "scan_type": scanner.scan_type,
                "label": scanner.label,
                "file_types": sorted(scanner.file_types),
            }
            for scanner in chosen
        ],
        "scan_status_by_type": {
            scan["scan_type"]: scan["status"] for scan in scan_records
        },
        "exploitation_source": catalogue.source_note,
        "exploitation_available": catalogue.available,
        "kev_available": catalogue.kev_available,
        "epss_available": catalogue.epss_available,
    }
    html_path, json_path = reporter.write(findings, report_dir, meta)
    print(f"\nHTML report : {html_path}")
    print(f"JSON report : {json_path}")

    incomplete = [scan for scan in scan_records
                  if scan["status"].startswith(("FAILED", "PARTIAL"))]
    if incomplete:
        print(f"\nWARNING: {len(incomplete)} scan(s) were incomplete or partial:")
        for scan in incomplete:
            print(f"  - {scan['label']}: {scan['status']}")
        if any(scan["status"].startswith("FAILED") for scan in incomplete):
            print("  This report is INCOMPLETE because one or more scans failed.")
        print("  Review the report coverage section before interpreting zero findings.")

    print("\nReminder: static analysis only. Findings need manual triage - "
          "see the Limitations section of the report.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"error: {target} is not a folder")
        return 2
    report_dir = Path(args.report)
    if not report_dir.is_absolute():
        report_dir = (Path.cwd() / report_dir).resolve()

    if args.all:
        chosen = list(ALL_SCANNERS)
    elif args.scan:
        chosen = [s for s in ALL_SCANNERS if s.scan_type == args.scan]
    else:
        chosen = choose_scanners_interactively()

    if not chosen:
        print("Nothing to do.")
        return 0
    return run_scans(target, report_dir, chosen, offline=args.offline)


if __name__ == "__main__":
    sys.exit(main())
