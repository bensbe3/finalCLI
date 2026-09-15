# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Python CLI for **static application security analysis** (SAST + SCA + secrets). It scans a target folder by **routing files to scanners**: one walk of the folder, files grouped by type, then each external tool receives only the files it declared it wants (PHP → Semgrep PHP rules, JS/TS → Semgrep JS rules, lockfiles → Trivy, all files → Gitleaks). It never passes every file to every tool. All three tools are optional — a missing one prints `skip:` and the run continues.

Built and working end-to-end: unit tests pass; end-to-end tests run the real Semgrep/Trivy/Gitleaks against `sample_vuln_app/`. This is an internship/PFE deliverable, so **beginner-readable code with obvious names and explicit data flow beats cleverness** — that priority is the point of the project, not a nicety.

Environment note: semgrep, trivy and gitleaks are all installed on this machine, so the end-to-end tests actually execute. Docker is not installed — the Dockerfile is written but has never been built.

## Commands

```bash
python main.py sample_vuln_app --all --report reports   # full run on the sample
python main.py <folder>                                 # interactive menu
python main.py <folder> --scan php                      # one scan (php|js|python|dependencies|secrets)
python -m pytest tests/ -q                              # all tests (~70s; e2e runs real tools)
python -m pytest tests/ -q --ignore=tests/test_e2e.py   # unit tests only (~1s)
python -m pytest tests/test_main.py -q -k routing       # a single test
```

Real deps: `jinja2`, `pygments`, `rich`, `pytest`. Everything else is stdlib on purpose. Must keep working on native Windows and Linux/WSL — use `pathlib`/`os.path` and `shutil.which`, no bash-isms.

## Architecture

Control is hub-and-spoke (`main.py` is the only module that calls the others); data flows one way. Reading `main.py:run_scans()` top-to-bottom gives you the whole program.

```
folder ──▶ FileSet ──▶ file subsets ──▶ Finding lists ──▶ merged ──▶ usage evidence ──▶ reports
         collector     router          scanners        consolidator  dependency_usage  reporter
```

| Module | RECEIVES | PRODUCES | CALLED BY |
|---|---|---|---|
| `main.py` | CLI args / menu choice | orchestration only — no analysis logic | user |
| `excludes.py` | target folder (+ its `.secignore`) | skip rules for collector **and** each tool's native ignore format | `main.py`, `collector.py` |
| `collector.py` | folder path | one `FileSet` (buckets: extension or exact filename), single walk | `main.py` |
| `router.py` | `FileSet` + a scanner | the subset that scanner declared via `file_types` | `main.py` |
| `scanners/base.py` | (contract) `label`, `scan_type`, `file_types`, `is_available()`, `run(files, target, excludes)` | `Scanner`, `SemgrepScanner`, `capture_snippet`, `run_tool` | all scanners inherit |
| `scanners/*_scanner.py` | its routed subset | complete `list[Finding]`, snippets attached | `main.py` via contract |
| `consolidator.py` | all Finding lists | deduplicated, CWE-enriched, severity-sorted list | `main.py` |
| `knowledge.py` | CWE id | OWASP category + remediation + illustrative scenario | `consolidator.py` |
| `exploitability.py` | CVE ids | CISA KEV + FIRST EPSS catalogue (24-hour cache) | `main.py`, then `consolidator.py` |
| `dependency_usage.py` | findings + `FileSet` + target | conservative direct-import evidence; never a reachability verdict | `main.py` |
| `reporter.py` | final Finding list + `meta` | `report.html` + `report.json` (template: `reporter_template.html`) | `main.py` |
| `models.py` | — | `Finding`, `Severity`, `FileSet` | everyone |

Import rules — **verified acyclic and two levels deep; keep it that way**: everyone may import `models.py`; `main.py` imports everything; a scanner imports only `base.py` + `models.py`; `consolidator.py` imports `knowledge.py` + `exploitability.py`; `collector.py` imports `excludes.py`; `dependency_usage.py` imports only `models.py`. Nothing else imports anything else. If a third level appears, the design is drifting — stop and flag it.

Every module opens with a header comment stating what it RECEIVES, PRODUCES, and which module CALLS it. Keep that up to date when changing a signature.

## Load-bearing decisions (do not regress)

1. **The router is dumb.** It computes `FileSet ∩ scanner.file_types` and nothing else — it does not know what PHP is. Adding a language = one new scanner file + one line in `scanners/__init__.py`, zero changes elsewhere.
2. **The menu is generated.** `scanners/__init__.py` holds the literal `ALL_SCANNERS` list; the interactive menu, `--scan` choices, and "run all" are three views of it. No auto-discovery or reflection.
3. **Findings leave scanners complete.** `capture_snippet()` in `scanners/base.py` captures the flagged line ±2 lines *at scan time*, streaming the file. The consolidator never reopens a source file.
4. **Identity lives on the Finding.** `Finding.fingerprint` is `(file, line, rule_id)` for code, `(package, advisory_id)` for dependencies — **never a line number for dependencies**, so lockfile churn can't fake a new/fixed vuln. Deduping happens on `fingerprint` without type-checking. Two *different* rules on the same line are two findings, deliberately (they can carry different CWEs — see `sample_vuln_app/README.md`).
5. **The exclude list is projected outward, once.** External tools do their own filesystem walk, so `excludes.py` holds ONE list and emits it as Semgrep `--exclude` args, Trivy `--skip-dirs`, and a generated Gitleaks TOML config. No scanner keeps a private exclude list. The tool must never flag its own report/cache files — `tests/test_e2e.py` proves this with the report folder placed *inside* the scanned project, scanned twice.
6. **Routing is visible.** Print the resolved selection ("PHP code scan (Semgrep) -> 3 file(s) selected") before the scanner runs, and record `files_selected` per scan in the report.
7. **Secrets are masked, including neighbours.** `SecretsScanner.parse()` collects every secret location per file first, then passes all of them to `capture_snippet(masks=...)`. Masking only the reported line leaks adjacent secrets through the ±2 lines of context — this was a real bug caught by a test; don't reintroduce it.
8. **Honest reporting.** Per-tool attribution, `confidence` on every finding, CWE + OWASP mapping, a Limitations section, and standards citations. Self-contained HTML: inline styles, **no JavaScript and no external URLs** (a test asserts this).
9. **Extension stubs stay empty.** `extensions/ai_advisor.py`, `history.py`, `correlation.py` are no-op seams with call sites written as comments in `main.py`. Do not implement unless asked.
10. **Unknown web data stays unknown.** CISA KEV and FIRST EPSS only enrich CVEs. A failed/skipped source never becomes evidence of absence, partial-source state is preserved in the cache, and non-CVE advisories are `not applicable` unless Trivy explicitly supplies a CVE alias.
11. **Tool coverage is evidence.** Semgrep must report at least one scanned path for a non-empty batch; malformed output fails loudly. Reports show routed files separately from tool-confirmed scanned files.
12. **Usage evidence is not reachability.** Direct imports/references may be reported for npm, Composer, Python, Ruby, Rust and Go projects. No reference found is never labelled unreachable; frameworks and transitive dependencies may load it indirectly.
13. **Partial scanner warnings survive.** Semgrep parser errors and timeouts are stored in JSON and HTML, and the scan status becomes `PARTIAL` rather than `ran`.

## Two things that look like bugs but aren't

**The secrets scanner declares `file_types = {"*"}`** and receives every collected file. That is the routing contract working — every scanner gets exactly what it declared, and Gitleaks declared everything. Documented in the README; don't "fix" it.

**`sample_vuln_app/README.md` documents planted flaws the tools do NOT find** — `eval()` in JS, a low-entropy hardcoded password, path traversal, MD5 in PHP (though it *is* caught in Python). These are measured false negatives, verified against real runs, kept on purpose as a demonstration of the Limitations section. Do not delete the undetected flaws to make the sample look cleaner, and do not claim they are detected.

`js_scanner.py` needs **three** Semgrep rulesets (`p/javascript`, `p/eslint-plugin-security`, `p/nodejsscan`) because `p/javascript` alone reported nothing on plain non-framework JS. That's why `SemgrepScanner.rulesets` is a list, not a string.

## Testing

`tests/test_e2e.py` runs the real tools and skips per-tool via `shutil.which`. Its assertions avoid exact finding counts (Trivy's advisory DB updates constantly) — they assert specific stable fingerprints like `("dep", "lodash", "CVE-2020-8203")`. When changing collector/excludes/router logic, the regression net is: planted vulns still found, no tool-artifact file ever flagged, dependency fingerprints stable across re-runs, fake secret values absent from both output files.
