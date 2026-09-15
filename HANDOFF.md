# Handoff — static security analysis CLI

Context for a new AI session picking up this project.
Companion docs: `CLAUDE.md` (architecture rules), `README.md` (user docs).

**The goal of this project is not to find the most issues. It is to produce the
most ACCURATE report — one that never claims more than it actually verified.**
Everything below exists to serve that.

---

## 1. What the script is

A Python CLI that orchestrates three external security tools and unifies their
output. It does **not** implement its own detection. Its contribution is
*collection, consolidation and reporting*:

- decide which files each tool should see (**routing**),
- run each tool on exactly that subset,
- merge the results into one deduplicated list,
- enrich each result from two knowledge sources,
- and report the whole thing with explicit confidence and explicit gaps.

Scope is deliberately **static only** — nothing is executed, no requests are sent.

## 2. The pipeline (one job per file)

    folder ──▶ FileSet ──▶ file subsets ──▶ Finding lists ──▶ merged ──▶ usage evidence ──▶ report
           collector    router          scanners        consolidator  dependency_usage  reporter

| Module | Job |
|---|---|
| `main.py` | orchestration only — the ONLY module that calls the others |
| `excludes.py` | the ONE exclude list + its three tool-native projections |
| `collector.py` | one filesystem walk → `FileSet` grouped by type (paths only, never contents) |
| `router.py` | `FileSet ∩ scanner.file_types` — a dumb intersection, no language knowledge |
| `scanners/base.py` | the `Scanner` contract + snippet capture + subprocess runner |
| `scanners/*_scanner.py` | one per scan type; each is mostly a *declaration* |
| `consolidator.py` | dedupe by fingerprint, enrich, sort by urgency |
| `knowledge.py` | CWE → OWASP category, remediation, illustrative scenario |
| `exploitability.py` | CVE → is it actually being attacked in the real world |
| `dependency_usage.py` | conservative direct package-reference evidence |
| `reporter.py` + `reporter_template.html` | the two output files |
| `models.py` | `Finding`, `Severity`, `FileSet` |

Imports go one way only: everyone may import `models.py`; `main.py` imports
everything; a scanner imports only `base.py` + `models.py`; `consolidator.py`
imports `knowledge.py` + `exploitability.py`; `collector.py` imports
`excludes.py`; `dependency_usage.py` imports only `models.py`. Nothing else.
Acyclic, two levels deep — keep it that way.

Every module opens with a header comment stating what it RECEIVES, PRODUCES and
which module CALLS it. Keep those current when changing a signature.

## 3. The tools layer — exactly how each tool is driven

Every scanner declares what it wants (`file_types`) and how to run. A missing
tool prints `skip:` and returns `[]` — never a crash. Availability is
`shutil.which`.

**Semgrep** (`scanners/base.py::SemgrepScanner`, shared by 3 language scanners)

    semgrep scan --json --quiet --config <ruleset>... <exclude args> <files...>

- `rulesets` is a **list**, because registry coverage is split across packs:
  - php: `["p/php"]`
  - js: `["p/javascript", "p/eslint-plugin-security", "p/nodejsscan"]`
  - python: `["p/python"]`
  - The JS list is three packs because `p/javascript` alone reported **nothing**
    on plain non-framework JS. Verified, not guessed.
- File lists are batched by `batch_by_cmdline_limit()` (20 000 chars) because
  Windows caps a command line near 32k.
- Exit code 1 means "findings were found", not failure — tolerated deliberately.
- Severity mapping: semgrep `ERROR`→HIGH, `WARNING`→MEDIUM.
- CWE is read from rule metadata via `extract_cwe()`, which normalises the many
  shapes tools emit (`"cwe-78"`, `["CWE-78: ..."]`, `cwe-078`) to `CWE-78`.

**Trivy** (`scanners/dependency_scanner.py`) — one invocation per routed lockfile

    trivy fs --scanners vuln --format json --quiet --skip-dirs <list> <lockfile>

- 300s timeout; empty stdout raises `ScannerFailed` (see §6).
- Confidence is `high`: this is an advisory-database match, not a pattern guess.
- The stored `line` is **display only**. Identity is `(package, advisory_id)`.

**Gitleaks** (`scanners/secrets_scanner.py`)

    gitleaks dir <target> --config <generated.toml> --report-format json
             --report-path <report dir>/gitleaks_findings.json
             --redact --exit-code 0 --no-banner

- `--redact` so gitleaks itself never writes the secret value anywhere.
- `--exit-code 0` because findings are results, not errors.
- Declares `file_types = {"*"}` — it receives every collected file. That is the
  routing contract working, not a hole.
- Confidence is `medium` for entropy-based `generic-*` rules, `high` for specific
  ones (`aws-access-token`, `github-pat`).

**The exclude list reaches every tool.** `excludes.py` holds ONE list (`.git`,
`node_modules`, `vendor`, build dirs, the tool's own report folder, plus the
user's `.secignore`) and projects it into each tool's native format:
`--exclude` args for Semgrep, `--skip-dirs` for Trivy, and a **generated TOML
config** with `[allowlist] paths` regexes for Gitleaks. External tools do their
own filesystem walk, so an internal Python list cannot protect them. This is why
the tool can never flag its own report/cache files.

## 4. The knowledge base — two enrichment layers

Neither layer touches detection. Both add context the tools do not provide.

**`knowledge.py` — what the weakness MEANS** (offline, hand-curated)

26 CWE entries → `(owasp, remediation, scenario)`:
- `owasp` — the OWASP Top 10:2021 category
- `remediation` — how to fix it, in one plain sentence
- `scenario` — an **illustrative textbook** example so a reader who does not know
  the CWE by number understands why it matters. Labelled in the report as
  documentation-only; nothing is ever executed.
- Unknown CWEs fall back to a safe generic entry — enrichment must never crash a
  scan, and must never invent detail it does not have.

**`exploitability.py` — whether anyone is ACTUALLY attacking it** (online)

Two free public sources, joined per CVE:
- **CISA KEV** — the catalogue of vulnerabilities *confirmed* exploited in the
  wild. Being listed is the strongest signal that exists.
- **FIRST EPSS** — a daily-updated model estimating the probability of
  exploitation in the next 30 days. Most CVEs score under 1%.

Mechanics: `urllib` only, 20s timeouts, EPSS batched 100 CVEs per request, both
results cached in a 24-hour JSON file (no database). `--offline` skips it.

Six statuses: `actively exploited`, `likely exploited` (EPSS ≥ 10%), `unlikely`,
`unknown - no data`, `not applicable`, `unknown - lookup unavailable`.

Two rules here are load-bearing and must not be "simplified":
1. **A failed or skipped lookup marks every finding `unknown`, NEVER "not
   exploited".** Silence is not evidence of safety.
2. **Evidence only ever PROMOTES a finding** (`PRIORITY`: KEV=2, likely=1,
   everything else 0). Demoting on missing data would sink a CRITICAL code
   injection below a dependency finding nobody has data for.

This is what lets the report answer *"which one do I fix first?"* instead of
showing twenty identical HIGH labels — a HIGH being actively attacked now
outranks a CRITICAL that nobody has touched.

## 5. What the report contains, and why each part exists

`report.html` is self-contained — inline styles, **no JavaScript and no external
resource loading**. `report.json` is its
twin. The same `LIMITATIONS` / `STANDARDS` constants feed both, so the two files
can never disagree.

Accuracy features, each answering a specific way reports mislead people:

| In the report | Prevents |
|---|---|
| **Routing table** — files routed to each scan | overstating coverage; you can verify what was actually looked at |
| **Files confirmed scanned** — tool-reported coverage beside routed count | a tool receiving files but analysing none looking successful |
| **Status per scan** (`ran` / `PARTIAL` / `no matching files` / `skipped` / `FAILED`) | parser/time-out warnings or a crashed scan reading as clean |
| **"Report is incomplete" banner** | zero findings in an unrun area looking like zero problems |
| **Per-tool attribution** | treating all findings as equally trustworthy |
| **Confidence** (high/medium/low) | pattern guesses ranking beside database matches |
| **CWE + OWASP mapping** | findings with no standard vocabulary to triage against |
| **Snippet captured at scan time** | showing code that has since changed |
| **Secret masking incl. neighbours** | leaking adjacent secrets through the ±2 context lines |
| **Exploitation status + EPSS % + KEV** | severity alone giving no priority signal |
| **"Fix these first" banner** | the one urgent item being buried among dozens |
| **10 Limitations entries** | the reader over-trusting the whole document |
| **9 Standards citations** | claims with no traceable basis |
| **Fingerprints in JSON** | future history/delta tracking reporting churn as change |
| **Location-first quick findings list** | paths, tools and explanations being buried in long finding cards |
| **Visible unrouted file types** | unsupported project areas silently disappearing from the coverage story |
| **Trivy advisory aliases** | a GHSA with an explicit CVE equivalent missing KEV/EPSS enrichment |
| **Direct dependency usage evidence** | installed packages being mistaken for packages the application clearly imports |

## 6. Accuracy invariants currently enforced (each has a test)

1. A scan that did not run is reported as `FAILED`/`skipped`, never as 0 findings.
2. Dependency identity is `(package, advisory_id)` — never a line number, so
   lockfile churn cannot fake a new/fixed vuln.
3. Two different rules on the same line stay two findings (they can carry
   different CWEs); dedupe is `(file, line, rule_id)`.
4. Snippets are captured at scan time; the consolidator never reopens a file.
5. Every secret in a snippet window is masked, not only the reported one.
6. Fake secret values never appear in either output file.
7. The tool never flags its own artifacts — proven with the report folder placed
   *inside* the scanned project and scanned twice.
8. A missing external tool skips cleanly instead of crashing.
9. A failed exploitation lookup reads `unknown`, never "not exploited".
10. The HTML loads no external resources.
11. Partial Semgrep errors remain visible in HTML and JSON.
12. Missing direct package references are never called unreachable.

## 7. CLOSED ACCURACY GAP — Semgrep silent failures

Semgrep can abort with valid JSON containing `results: []`, `errors: [...]` and
`paths.scanned: []`. This is now closed in `SemgrepScanner.run()`: a non-empty
batch must have at least one tool-confirmed scanned path. Empty coverage,
malformed JSON and unexpected fatal exit codes become `ScannerFailed`; partial
findings survive in `partial_findings`. Unit tests cover a bad ruleset, empty
coverage without an error message, and invalid JSON.

Trivy now also rejects malformed JSON/non-zero fatal runs, and Gitleaks deletes
its previous intermediate report before every run so stale findings can never
masquerade as current output.

## 8. Other things that limit accuracy today

- **No full reachability analysis.** `dependency_usage.py` checks direct
  references for npm, Composer PSR namespaces, Python, Ruby, Rust and Go using
  the existing `FileSet`. A match proves direct use, not use of the vulnerable
  function. No match explicitly says it is **not proof of unreachability**.
  Ecosystems without reliable mappings, such as Maven coordinates, are marked
  unsupported rather than guessed.
- **No baseline / suppression file.** A triaged false positive reappears at full
  volume on every scan. There is nowhere to record "reviewed, not a problem".
- **`knowledge.py` covers 30 CWEs.** Anything else falls back to a generic entry
  — honest, but less useful.
- **Measured false negatives** are documented on purpose in
  `sample_vuln_app/README.md` (`eval()` in JS, a low-entropy hardcoded password,
  path traversal, MD5 in PHP though it *is* caught in Python). **Do not delete
  the undetected flaws to make the sample look cleaner, and do not claim they are
  detected.**

## 9. Completed accuracy work

Completed:
1. Dependency routing e2e assertion updated to **2** lockfiles.
2. Exploitation e2e tests cover honest `--offline` output and online CISA KEV
   prioritisation, with network probes that skip rather than fail offline.
3. The Semgrep silent-failure gap is closed (see §7).
4. Reports are location-first and expose file path, line, tool, scan,
   rules/configuration, tool explanation, routed count and confirmed-scanned
   count. JSON carries the same findings index and coverage facts.
5. CISA/EPSS cache entries record which source actually succeeded; partial data
   can no longer become false evidence of absence on a later run.
6. Semgrep parser/time-out warnings are preserved as `PARTIAL` scan evidence.
7. Trivy `VendorIDs` are retained, and an explicit CVE alias can receive
   CISA/EPSS enrichment; no alias is guessed.
8. Dependency direct-use evidence is reported conservatively and never hides or
   lowers an advisory.
9. The HTML report is shorter: text severity counts replace the chart, findings
   come before detailed coverage, and collected file groups are collapsible.

## 10. Environment

Windows 11, Python 3.14. `semgrep`, `trivy`, `gitleaks` installed and on PATH.
Docker NOT installed — the Dockerfile is written but never built. Real deps:
`jinja2`, `pygments`, `rich`, `pytest`; everything else stdlib on purpose. Must
keep working on native Windows and Linux/WSL — `pathlib`, `shutil.which`, no
bash-isms.

    python main.py sample_vuln_app --all --report reports
    python main.py <folder>                                  # interactive menu
    python main.py <folder> --scan php --offline
    python -m pytest tests/ -q                               # full, ~70s
    python -m pytest tests/ -q --ignore=tests/test_e2e.py    # fast, ~1s

Current state: unit tests pass. End-to-end tests skip per missing tool.
