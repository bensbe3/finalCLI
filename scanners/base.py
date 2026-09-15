"""
scanners/base.py — the contract every scanner obeys, plus shared helpers.

RECEIVES:  nothing directly (this is a contract, not a pipeline step)
PRODUCES:  the Scanner base class (label, scan_type, file_types,
           is_available(), run(files, target, excludes) -> list[Finding],
           last_files_scanned, last_warnings)
           and shared helpers: snippet capture, subprocess runner,
           command-line batching, CWE/OWASP extractors
CALLED BY: inherited by every file in scanners/; helpers used only there

Three guarantees live here so no scanner can forget them:
  * a Finding leaves its scanner COMPLETE — the snippet (vulnerable line
    +/- 2 lines) is captured at scan time by capture_snippet(), before
    the Finding is returned;
  * a missing external tool is a clean `skip`, never a crash;
  * soft tool errors that still scanned some files (e.g. Semgrep parser
    errors) are stored on last_warnings so main.py can mark the scan
    PARTIAL instead of pretending coverage was complete.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from models import Finding, Severity

SNIPPET_CONTEXT = 2          # lines shown above and below the finding
CMDLINE_BUDGET = 20_000      # stay far below Windows' ~32k argv limit
STDERR_TAIL = 400            # how much tool stderr to quote when it fails


class ScannerFailed(Exception):
    """The tool WAS installed but did not run successfully.

    This exists to keep the report honest. "The tool ran and found
    nothing" and "the tool never ran" both produce zero findings, and a
    reader would read either as "your code is clean". Trivy failing to
    download its vulnerability database is the real case that prompted
    this: it exits non-zero, prints nothing, and finds nothing.

    main.py catches this, records the scan as FAILED in the report, and
    carries on with the other scans - so a broken tool is loud but never
    fatal. `partial_findings` carries whatever DID succeed (e.g. one
    lockfile parsed while another failed).
    """

    def __init__(self, message: str, partial_findings: list | None = None):
        super().__init__(message)
        self.partial_findings = partial_findings or []


class Scanner:
    """Base class: every scanner declares WHAT it wants and HOW to run.

    Subclasses must set:
      label      -> human name shown in the menu ("PHP code scan (Semgrep)")
      scan_type  -> menu/CLI id ("php", "js", "python", "dependencies", "secrets")
      file_types -> what to receive from the router: extensions (".php"),
                    exact filenames ("composer.lock"), or "*" for everything
      tool_cmd   -> the external executable this scanner wraps
    and implement run().

    After a run, main.py also reads:
      last_files_scanned -> how many paths the tool confirmed it analysed
                           (None when the tool does not report that)
      last_warnings      -> soft coverage problems that still returned findings
    """

    label: str = ""
    scan_type: str = ""
    file_types: set[str] = set()
    tool_cmd: str = ""
    last_files_scanned: int | None = None
    last_warnings: list[str] = []

    def is_available(self) -> bool:
        """A tool is available when its executable is on PATH."""
        return shutil.which(self.tool_cmd) is not None

    def run(self, files: list[Path], target: Path, excludes) -> list[Finding]:
        raise NotImplementedError

    # ---- shared behaviour --------------------------------------------------

    def skip_if_unavailable(self) -> bool:
        """Print the skip line and tell the caller to stop. Never crashes."""
        if not self.is_available():
            print(f"  skip: {self.tool_cmd} not installed - {self.label} skipped")
            return True
        return False


def run_tool(argv: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    """Run an external tool safely: list argv (no shell), captured output,
    UTF-8 with replacement.

    Non-zero exit codes are RETURNED, not raised - semgrep exits 1 when it
    finds something, which is a result, not an error. A tool that hangs or
    cannot be started IS an error, and becomes ScannerFailed so the report
    records the scan as incomplete instead of crashing the run. (Trivy
    stalling while it downloads its vulnerability database is the case that
    prompted this.)
    """
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ScannerFailed(
            f"{argv[0]} did not finish within {timeout}s and was stopped")
    except OSError as error:
        raise ScannerFailed(f"{argv[0]} could not be started: {error}")


def capture_snippet(
    path: Path,
    line: int,
    context: int = SNIPPET_CONTEXT,
    masks: dict[int, tuple[int, int]] | None = None,
) -> str:
    """Read the vulnerable line +/- `context` lines, AT SCAN TIME, streaming
    the file (never loading it whole) and stopping early.

    `masks` maps line number -> (start_col, end_col), 1-based, and those
    columns are replaced with ****. The secrets scanner passes EVERY secret
    it found in this file, not just the one being reported: a snippet shows
    two lines of context, so a neighbouring secret would otherwise be
    printed in full next to the one that was masked.
    """
    if line <= 0:
        return ""
    first, last = max(1, line - context), line + context
    masks = masks or {}
    captured: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for number, text in enumerate(handle, start=1):
                if number > last:
                    break
                if number < first:
                    continue
                text = text.rstrip("\n").rstrip("\r")
                if number in masks:
                    start, end = masks[number]
                    text = text[: start - 1] + "****" + text[end:]
                marker = ">" if number == line else " "
                captured.append(f"{marker}{number:>5} | {text}")
    except OSError:
        return ""
    return "\n".join(captured)


def batch_by_cmdline_limit(paths: list[Path], budget: int = CMDLINE_BUDGET):
    """Yield path batches that keep each command line under `budget` chars
    (Windows caps a command line at ~32k)."""
    batch: list[str] = []
    length = 0
    for path in paths:
        text = str(path)
        if batch and length + len(text) + 1 > budget:
            yield batch
            batch, length = [], 0
        batch.append(text)
        length += len(text) + 1
    if batch:
        yield batch


def relative_posix(path: Path, target: Path) -> str:
    """Report paths relative to the scanned folder, with / separators."""
    try:
        return path.resolve().relative_to(target.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def first_error_message(errors: list) -> str:
    """The most useful line out of a tool's JSON `errors` array."""
    if not errors:
        return "unknown error"
    first = errors[0]
    if isinstance(first, dict):
        return " ".join(str(first.get("message", first)).split())[:STDERR_TAIL]
    return str(first)[:STDERR_TAIL]


def error_messages(errors: list) -> list[str]:
    """All distinct tool error messages, shortened for safe reporting."""
    messages: list[str] = []
    for error in errors:
        if isinstance(error, dict):
            message = " ".join(
                str(error.get("message", error)).split())[:STDERR_TAIL]
        else:
            message = " ".join(str(error).split())[:STDERR_TAIL]
        if message and message not in messages:
            messages.append(message)
    return messages


def describe_failure(result: subprocess.CompletedProcess) -> str:
    """A short, quotable reason a tool run failed, for the report.

    Some tools print a long progress log first and the real error last,
    so we keep the TAIL of stderr, not the start.
    """
    text = " ".join(result.stderr.split())
    stderr = text[-STDERR_TAIL:] if len(text) > STDERR_TAIL else text
    return f"exit {result.returncode}: {stderr}" if stderr else f"exit {result.returncode}"


def extract_cwe(raw) -> str:
    """Normalize the many CWE shapes tools emit to plain 'CWE-89'.

    Tags like 'cwe-078' drop leading zeros so they match knowledge.py
    keys such as CWE-78.
    """
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    match = re.search(r"CWE-0*(\d+)", str(raw), re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else ""


def extract_owasp(raw) -> str:
    """Keep the first OWASP category supplied by a tool rule."""
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    return " ".join(str(raw).split())


class SemgrepScanner(Scanner):
    """Shared implementation for every Semgrep-backed language scanner.

    A concrete language scanner (php/js/python) is just a declaration:
    label + scan_type + file_types + rulesets. That is what makes
    "adding a language = one new small file" literally true.

    `rulesets` is a LIST because Semgrep's registry splits coverage for a
    language across several packs — see each language scanner for which
    packs it uses and why.
    """

    tool_cmd = "semgrep"
    rulesets: list[str] = []  # e.g. ["p/php"] — set by each language scanner

    def run(self, files: list[Path], target: Path, excludes) -> list[Finding]:
        self.last_files_scanned = 0
        self.last_warnings = []
        if self.skip_if_unavailable():
            return []
        if not files:
            print(f"  {self.label}: no matching files - nothing to do")
            return []

        ruleset_args: list[str] = []
        for ruleset in self.rulesets:
            ruleset_args += ["--config", ruleset]

        findings: list[Finding] = []
        failures: list[str] = []
        for batch in batch_by_cmdline_limit(files):
            argv = (
                [self.tool_cmd, "scan", "--json", "--quiet"]
                + ruleset_args
                + excludes.semgrep_args()
                + batch
            )
            result = run_tool(argv)
            # Semgrep exits 1 when it FINDS something, so a non-zero exit
            # is not itself a failure - no output at all is.
            if not result.stdout.strip():
                failures.append(describe_failure(result))
                continue

            try:
                output = json.loads(result.stdout)
            except (json.JSONDecodeError, TypeError):
                failures.append(
                    f"invalid JSON from semgrep ({describe_failure(result)})")
                continue
            errors = output.get("errors", [])
            scanned = output.get("paths", {}).get("scanned", [])

            # The subtle one: a ruleset that fails to load (a wrong pack
            # name returns HTTP 404) makes semgrep give up, yet it still
            # prints valid JSON with zero results and zero files scanned.
            # Parsing that happily would report "no problems found" about
            # a scan that examined nothing.
            if not scanned:
                reason = first_error_message(errors) if errors else (
                    "semgrep reported that zero files were scanned")
                failures.append(reason)
                continue
            self.last_files_scanned += len(scanned)
            if result.returncode not in (0, 1):
                failures.append(describe_failure(result))
                findings += self.parse(output, target)
                continue
            if errors:
                self.last_warnings.extend(
                    message for message in error_messages(errors)
                    if message not in self.last_warnings)
                print(f"  warning: semgrep reported {len(errors)} error(s) - "
                      f"some files may not have been analysed: "
                      f"{first_error_message(errors)}")

            findings += self.parse(output, target)

        if failures:
            raise ScannerFailed(
                f"semgrep did not complete ({failures[0]})", findings)
        return findings

    def parse(self, output: dict, target: Path) -> list[Finding]:
        """Turn semgrep's JSON into complete Findings (snippet attached)."""
        findings: list[Finding] = []
        for result in output.get("results", []):
            path = Path(result.get("path", ""))
            line = int(result.get("start", {}).get("line", 0))
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            findings.append(
                Finding(
                    file=relative_posix(path, target),
                    line=line,
                    rule_id=result.get("check_id", ""),
                    message=extra.get("message", "").strip(),
                    severity=Severity.from_text(extra.get("severity", "")),
                    confidence=str(metadata.get("confidence", "medium")).lower(),
                    tool="semgrep",
                    scan_type=self.scan_type,
                    cwe=extract_cwe(metadata.get("cwe", "")),
                    owasp=extract_owasp(metadata.get("owasp", "")),
                    snippet=capture_snippet(path, line),
                )
            )
        return findings
