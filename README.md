# Static security analysis CLI

A command-line tool that scans a project folder for security problems by
**routing each file to the right analyser**, then merging everything the
analysers say into one report.

It does not invent its own detection. It orchestrates well-known tools —
**Semgrep** (code), **Trivy** (dependency CVEs) and **Gitleaks** (secrets) —
and its own contribution is *collection, consolidation and reporting*: working
out which files each tool should see, removing duplicates,
mapping findings to CWE and OWASP categories, checking CVEs against CISA KEV
and FIRST EPSS, and presenting the result honestly.

**Scope: static analysis only.** Nothing is executed, no requests are sent, no
running system is touched. See [Limitations](#limitations).

---

## Quick start

```bash
pip install -r requirements.txt
```

Then install whichever external tools you want to use. Each is optional — the
CLI prints a `skip` line for anything missing and carries on:

| Tool | Used for | Install |
|---|---|---|
| Semgrep | PHP / JS / Python code analysis | `pip install semgrep` |
| Trivy | Known CVEs in dependencies | see trivy.dev |
| Gitleaks | Hardcoded secrets | see gitleaks.io |

Run it interactively and pick a scan from the menu:

```bash
python main.py sample_vuln_app
```

Or skip the menu (this is what you would use in CI):

```bash
python main.py sample_vuln_app --all --report reports
```

```bash
python main.py /path/to/project --scan php
```

Use `--offline` to skip CISA/EPSS network lookups. CVE exploitation then reads
as **unknown**, never as "not exploited":

```bash
python main.py /path/to/project --all --offline
```

The report lands in `reports/report.html` and `reports/report.json`.

---

## How it works: the flow

Data moves forward through five stages. Each stage has one job and hands its
result to the next:

```
   your project folder
            |
            v
   +--------------------+
   |    excludes.py     |   ONE exclude list, written out into each
   |                    |   external tool's own ignore format
   +--------------------+
            |
            v
   +--------------------+
   |    collector.py    |   walks the folder ONCE
   +--------------------+   groups files by type
            |
            |  FileSet     { ".php": [...], ".js": [...],
            |                "package-lock.json": [...] }
            v
   +--------------------+
   |     router.py      |   for one scanner: which of those files
   +--------------------+   did it declare it wants?
            |
            |  a list of file paths - just this scanner's subset
            v
   +--------------------+
   |     scanners/      |   php / js / python -> Semgrep
   |                    |   dependencies      -> Trivy
   |                    |   secrets           -> Gitleaks
   +--------------------+
            |
            |  list[Finding]  (snippet already attached)
            v
   +--------------------+
   |  consolidator.py   |   removes duplicates, adds CWE + exploitation context
   +--------------------+
            |
            |  one clean list[Finding]
            v
   +--------------------+
   |    reporter.py     |   report.html + report.json
   +--------------------+
```

**`main.py` is the only module that calls the others.** Every arrow above is a
line in `main.py`'s `run_scans()` function, in that order. No module reaches
sideways into another, so you can read that one function and know the whole
program.

---

## What each file does

Every module repeats this in a comment at the top of the file, so you never
have to come back here.

| File | Receives | Produces | Called by |
|---|---|---|---|
| `main.py` | CLI arguments, or your menu choice | orchestration only — no analysis logic of its own | you |
| `excludes.py` | the target folder (reads `.secignore`) | skip rules for the collector, plus each tool's native ignore format | `main.py`, `collector.py` |
| `collector.py` | a folder path | one `FileSet` — files grouped by type, from a single walk | `main.py` |
| `router.py` | a `FileSet` and one scanner | exactly the files that scanner declared it wants | `main.py` |
| `scanners/base.py` | — (a contract, not a step) | the `Scanner` class, snippet capture, subprocess runner | inherited by every scanner |
| `scanners/*_scanner.py` | its own routed subset of files | `list[Finding]`, complete with code snippets | `main.py`, via the contract |
| `consolidator.py` | every scanner's findings | one deduplicated, enriched, sorted list | `main.py` |
| `knowledge.py` | a CWE id | its OWASP category, a fix, an illustrative scenario | `consolidator.py` |
| `exploitability.py` | CVE ids | CISA KEV status + FIRST EPSS probability, cached for 24 hours | `main.py`, then `consolidator.py` |
| `dependency_usage.py` | dependency findings + the collected `FileSet` | conservative direct-import evidence | `main.py` |
| `reporter.py` | the final list of findings | `report.html` and `report.json` | `main.py` |
| `models.py` | — | `Finding`, `Severity`, `FileSet` | everyone |

Imports go one way only: everyone may import `models.py`; `main.py` imports
everything; a scanner imports only `base.py` and `models.py`; `consolidator.py`
imports `knowledge.py` and `exploitability.py`; `dependency_usage.py` imports
only `models.py`. Nothing else imports anything else.

---

## The central idea: file routing

Most scanners are pointed at a folder and left to figure it out. This tool
decides deliberately, and shows you its decision before it runs anything:

```
PHP code scan (Semgrep) -> 3 file(s) selected
```

Each scanner **declares** what it wants, as data:

```python
class PhpScanner(SemgrepScanner):
    file_types = {".php", ".phtml", ".php5"}     # extensions
    rulesets   = ["p/php"]

class DependencyScanner(Scanner):
    file_types = {"package-lock.json", "composer.lock", ...}   # exact names
```

`router.py` then does one thing: intersect that declaration with what the
collector found. **It has no idea what PHP is.** It never grows when you add a
language, because all the knowledge lives in the declaration.

### Adding a language is one file

Create `scanners/ruby_scanner.py`:

```python
from scanners.base import SemgrepScanner

class RubyScanner(SemgrepScanner):
    label = "Ruby code scan (Semgrep)"
    scan_type = "ruby"
    file_types = {".rb", ".erb"}
    rulesets = ["p/ruby"]
```

...and add `RubyScanner()` to the list in `scanners/__init__.py`. That is all.
The menu, the `--scan ruby` flag, the routing and the report all pick it up,
because they are all views of that one list.

### Why the secrets scanner "gets everything"

`SecretsScanner` declares `file_types = {"*"}`, so the router hands it every
collected file. That is the contract **working**, not a hole in it: every
scanner receives exactly what it declared, and Gitleaks declared everything —
a secret can be hiding in any file type.

---

## Five decisions worth knowing

**1. The router is deliberately dumb.** An intersection, nothing more. All
language knowledge sits in the scanner declarations, which is what makes the
one-file extension above possible.

**2. The menu is generated, not written.** `scanners/__init__.py` holds a plain
list. The interactive menu, the `--scan` choices and "run everything" are three
views of it, so they cannot drift apart. There is no plugin auto-discovery —
a list you can read beats magic you have to trace.

**3. Findings are complete when they leave a scanner.** The code snippet
(the flagged line plus two lines either side) is captured *at scan time*,
inside `scanners/base.py`. The consolidator never reopens a source file, so the
report always shows the code as it was when scanned.

**4. A finding's identity belongs to the finding.** `Finding.fingerprint` is
`(file, line, rule_id)` for code — but for a dependency it is
`(package, advisory_id)`, with **no line number**. A lockfile line moves when
unrelated packages are added; keying on it would report the same old CVE as
"new" on the next scan. The consolidator deduplicates on the fingerprint
without needing to know which kind it is holding.

**5. The exclude list is written outward, once.** Semgrep, Trivy and Gitleaks
each do their own filesystem walk, so a Python ignore list cannot reach them.
`excludes.py` holds one list — `.git`, `node_modules`, `vendor`, build folders,
the tool's own report folder, plus anything in your `.secignore` — and
projects it into Semgrep `--exclude` flags, Trivy `--skip-dirs`, and a
generated Gitleaks config. One list, three formats. This is why the tool can
never flag its own report or cache files, even when you write reports *into*
the folder you are scanning (there is a test for exactly that).

### `.secignore`

Drop a `.secignore` in the folder you scan, one glob per line:

```
*.min.js
legacy/
tests/fixtures/*
```

It feeds the same single list, so it reaches all external tools too.

---

## What the report contains

`report.html` is fully self-contained: plain HTML, inline styles,
**no JavaScript and no external requests**. It opens offline, anywhere.
`report.json` carries the same data for tooling.

For every finding:

* a location-first index for fast triage on large projects
* the exact relative **file path and line**
* **which tool and scan** reported it, the rules/configuration used, and confidence
* the tool's own explanation, kept separate from documentation-only context
* severity, as the tool assigned it
* CWE id and the matching OWASP Top 10:2021 category
* the code snippet captured at scan time, syntax-highlighted
* how to fix it, and an illustrative attack scenario — documentation only,
  never executed
* for CVEs, CISA KEV confirmed-exploitation status and FIRST EPSS probability
  plus percentile
* for dependency advisories, equivalent IDs supplied by Trivy and conservative
  direct-import evidence (never a claim that the vulnerable function is reachable)

Plus a coverage table showing files routed versus files the tool confirmed it
scanned, visible file types not routed to a selected code/dependency scanner,
and a Limitations section. A skipped or failed scan makes the report visibly
incomplete; Semgrep parser/time-out warnings mark a scan `PARTIAL` and are
listed in both reports.

Standards referenced: OWASP Top 10:2021, CWE Top 25, MITRE CAPEC, OWASP ASVS,
ISO/IEC 27034, NIST SSDF (SP 800-218), NIST NVD.

---

## Limitations

Read these before showing anyone a report.

* **Static analysis only.** Nothing was run and nothing was attacked. A finding
  describes code as written; it is not proof of exploitability.
* **False positives are expected.** Detection is pattern- and tool-based. Every
  finding needs manual triage.
* **No findings is not proof of safety.** `sample_vuln_app/README.md` documents
  several deliberately planted flaws that these rulesets *do not* report —
  including `eval()` of user input in JavaScript, and a hardcoded password that
  is too human-readable for entropy-based secret detection. That gap is measured
  and written down on purpose.
* **Coverage varies by language.** The same weakness (MD5 for password hashing)
  is reported in Python but missed in PHP by the free Semgrep rulesets.
* **Dependency findings come from Trivy's advisory databases** (including
  ecosystem and vendor sources) and may not apply to your configuration or
  code path. The report can show direct import evidence for several ecosystems,
  but that is not full call-path reachability analysis.
* **CISA KEV confirms exploitation in the wild; FIRST EPSS predicts probability.**
  Neither proves that this application is exploitable. Failed/skipped lookups
  remain unknown. A non-CVE advisory is marked not applicable unless Trivy
  supplies an equivalent CVE alias; the CLI never guesses that relationship.
* **Reports quote your source code.** Secret values are masked, but treat the
  report as sensitive.

---

## Tests

```bash
python -m pytest tests/ -q
```

Unit tests need no external tools. The end-to-end tests in `tests/test_e2e.py`
run the real Semgrep, Trivy and Gitleaks against `sample_vuln_app` and skip
themselves individually if a tool is missing. Between them they assert that:

* the planted vulnerabilities are actually found, by the right scan
* no tool-artifact file is ever flagged — including the deliberate worst case,
  where the report folder sits *inside* the scanned project and the scan runs
  twice
* dependency fingerprints ignore line numbers and stay identical across re-runs
* fake secret values never appear in either output file
* a missing external tool skips cleanly instead of crashing
* malformed/stale tool output cannot masquerade as a clean scan
* offline exploitation lookup stays unknown; CISA KEV findings are prioritised

---

## Docker

The image carries the CLI and all three tools; your project is mounted, never
copied in:

```bash
docker build -t secscan .
docker run --rm -v "$(pwd)/sample_vuln_app:/target" -v "$(pwd)/reports:/out" \
    secscan /target --all --report /out
```

---

## Layout

```
main.py                  CLI entry, interactive menu, orchestration
collector.py             one walk of the folder -> FileSet
router.py                FileSet + scanner -> that scanner's files
consolidator.py          merge, deduplicate, enrich
dependency_usage.py      conservative direct-import evidence for packages
reporter.py              report.html + report.json
reporter_template.html   the HTML layout (data file, no logic)
models.py                Finding, Severity, FileSet
knowledge.py             CWE -> OWASP category, fix, scenario
exploitability.py        CVE (+ Trivy CVE aliases) -> CISA KEV + FIRST EPSS
excludes.py              the one exclude list + its tool-native projections
scanners/
  __init__.py            ALL_SCANNERS - the one list
  base.py                the Scanner contract + shared helpers
  php_scanner.py         Semgrep, PHP rulesets
  js_scanner.py          Semgrep, JS/TS rulesets
  python_scanner.py      Semgrep, Python rulesets
  dependency_scanner.py  Trivy, on lockfiles
  secrets_scanner.py     Gitleaks, on everything
extensions/              empty seams for future work (see below)
sample_vuln_app/         intentionally vulnerable fixture - do not deploy
tests/                   unit tests + real end-to-end tests
```

## Future work

`extensions/` holds three deliberately empty seams, each a no-op function with
the signature it will eventually need, and their call sites written out as
comments in `main.py`:

* `ai_advisor.py` — AI-generated explanations for findings
* `history.py` — scan history and new/fixed deltas between runs
  (already cheap, because `Finding.fingerprint` is a stable identity)
* `correlation.py` — cross-scanner risk correlation, e.g. a hardcoded
  credential in the same file as an injection sink

They are stubs so that adding them later requires no restructuring.
"# finalCLI" 
