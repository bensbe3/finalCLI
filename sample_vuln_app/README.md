# sample_vuln_app — intentionally vulnerable test fixture

**Do not deploy this. Do not copy code from it.** Every file here contains
deliberate flaws so the scanner has something real to find. It exists only to
prove the pipeline works end-to-end, the same way OWASP WebGoat or DVWA do.

Every "credential" in this folder is fake and non-functional — the strings are
shaped to match secret-detection patterns, nothing more. There is nothing here
to steal.

Run it from the project root:

```bash
python main.py sample_vuln_app --all --report reports
```

## What the tools actually report

This table records a real run, not what we hoped for. The point of a test
fixture is to tell you the truth about your own coverage.

| File | Planted flaw | Reported? | By |
|---|---|---|---|
| `public/login.php` | SQL injection (CWE-89) | yes | Semgrep `p/php` |
| `public/login.php` | Reflected XSS (CWE-79), 2 sinks | yes | Semgrep `p/php` |
| `public/tools.php` | Command injection via `system()`/`exec()` | yes | Semgrep `p/php` |
| `static/app.js` | Insecure randomness for a token (CWE-327) | yes | Semgrep `p/nodejsscan` |
| `src/runner.js` | Command injection via `child_process` (CWE-78) | yes (2 rules) | Semgrep |
| `tools/report_tool.py` | `subprocess` with `shell=True` (CWE-78) | yes | Semgrep `p/python` |
| `tools/report_tool.py` | Weak MD5 hash (CWE-327) | yes | Semgrep `p/python` |
| `config/credentials.js` | Fake AWS key, GitHub PAT, generic key | yes (3) | Gitleaks |
| `package-lock.json` | lodash 4.17.15, minimist 1.2.0 | yes (9 CVEs) | Trivy |
| `composer.lock` | phpmailer 5.2.16 | yes (known CVEs) | Trivy |
| `public/tools.php` | Path traversal via `include()` (CWE-22) | **no** | — |
| `static/app.js` | `eval()` of user input (CWE-94) | **no** | — |
| `static/app.js` | `innerHTML` sink (CWE-79) | **no** | — |
| `src/config.php` | Hardcoded DB password (CWE-798) | **no** | — |
| `src/config.php` | Weak MD5 password hash (CWE-327) | **no** | — |
| `config/credentials.js` | Low-entropy JWT signing secret | **no** | — |

## The "no" rows are the most useful part

They are measured false negatives, and they are exactly what the report's
Limitations section warns about: **absence of findings is not proof of safety.**

* **`eval()` in JavaScript** was not reported by any community ruleset tested
  (`p/javascript`, `p/eslint-plugin-security`, `p/nodejsscan`) — not even for a
  bare `eval(userInput)` in a stripped-down probe file. Semgrep's deeper
  cross-function taint analysis is a paid feature; the free packs lean on
  framework-specific patterns.
* **`innerHTML`** has the same cause: the DOM-XSS rules that would catch it
  expect a recognised framework or a taint source the free packs don't track.
* **Low-entropy secrets are invisible to Gitleaks.** The hardcoded DB password
  (`'Pa55w0rd-hardcoded-in-source'`) and the JWT signing secret
  (`'static-signing-secret-do-not-use'`) both read as ordinary English strings.
  Gitleaks keys on high-entropy values and known credential formats, so these
  slip through while the AWS-shaped key beside them is caught instantly. A
  memorable password in source is no safer than a random one — just harder to
  detect automatically.
* **Coverage differs per language, for the same weakness.** `md5()` used for
  password hashing is reported in `tools/report_tool.py` by `p/python`, but the
  identical mistake in `src/config.php` is not reported by `p/php`. Ruleset
  maturity varies by language; equal effort per language is not a safe
  assumption.
* **Path traversal** via `include($_GET['page'])` was not flagged, though the
  command-injection sinks in the same file were.

None of these are bugs in this CLI — it faithfully reports what the tools
return. They are the reason the report says every scan needs manual triage,
and they are worth demonstrating rather than hiding.

`composer.lock` deliberately pins phpmailer 5.2.16. Its
`CVE-2016-10033` advisory is listed in CISA's Known Exploited Vulnerabilities
catalogue, so the fixture verifies that confirmed real-world exploitation is
marked `actively exploited` and prioritised above prediction-only findings.

## One more thing a reader will notice

`public/tools.php` lines 7 and 15 each appear **twice** in the report, from
`php.lang.security.tainted-exec` (CWE-94) and
`php.lang.security.injection.tainted-exec` (CWE-78). These are two different
Semgrep rules that disagree about the CWE, so consolidation keeps both — its
identity rule is `(file, line, rule_id)`. Collapsing them by line alone would
silently discard one of the two CWE mappings.
