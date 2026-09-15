"""
knowledge.py — what each CWE means, in plain language.

RECEIVES:  a CWE id ("CWE-89")
PRODUCES:  its OWASP Top 10 (2021) category, a remediation hint, and an
           ILLUSTRATIVE attack scenario (documentation only — nothing
           here is ever executed)
CALLED BY: consolidator.py, while enriching findings

Categories follow OWASP Top 10:2021; the CWEs covered are drawn from
the CWE Top 25. Unknown CWEs get a safe generic entry — enrichment must
never crash a scan.
"""

from __future__ import annotations

from typing import NamedTuple


class Knowledge(NamedTuple):
    owasp: str
    remediation: str
    scenario: str  # illustrative textbook example, never executed


CWE_KNOWLEDGE: dict[str, Knowledge] = {
    "CWE-89": Knowledge(
        "A03:2021 - Injection",
        "Use parameterized queries / prepared statements; never concatenate user input into SQL.",
        "Classic textbook example: submitting `' OR '1'='1` in a login form to bypass authentication.",
    ),
    "CWE-79": Knowledge(
        "A03:2021 - Injection",
        "Encode output for its HTML context; use your framework's auto-escaping templates.",
        "A comment containing `<script>document.location=...</script>` runs in every visitor's browser.",
    ),
    "CWE-78": Knowledge(
        "A03:2021 - Injection",
        "Avoid shelling out with user input; use safe APIs or strict allow-lists, never string concatenation.",
        "A filename parameter like `report.pdf; rm -rf /` appended to a shell command executes both.",
    ),
    "CWE-77": Knowledge(
        "A03:2021 - Injection",
        "Keep untrusted data out of command strings; use APIs with separate argument lists and strict allow-lists.",
        "A crafted value introduces command syntax that the operating system interprets instead of treating as data.",
    ),
    "CWE-88": Knowledge(
        "A03:2021 - Injection",
        "Pass arguments as separate values, use `--` where supported, and allow-list options accepted from users.",
        "An input beginning with a command-line option changes how a trusted program behaves.",
    ),
    "CWE-116": Knowledge(
        "A03:2021 - Injection",
        "Encode or escape output for the exact interpreter and context that will consume it.",
        "Data safe for plain text is inserted into HTML, a shell command, or another interpreted context without the required encoding.",
    ),
    "CWE-22": Knowledge(
        "A01:2021 - Broken Access Control",
        "Resolve paths against a base directory and reject anything that escapes it.",
        "A download parameter of `../../etc/passwd` walks out of the intended folder.",
    ),
    "CWE-798": Knowledge(
        "A07:2021 - Identification and Authentication Failures",
        "Move secrets to environment variables or a secrets manager; rotate any value already committed.",
        "A cloud key committed to a repository is harvested by scanners within minutes of the push.",
    ),
    "CWE-327": Knowledge(
        "A02:2021 - Cryptographic Failures",
        "Use modern, vetted algorithms (AES-GCM, SHA-256, bcrypt/argon2 for passwords).",
        "Passwords hashed with MD5 are recovered offline with commodity hardware and rainbow tables.",
    ),
    "CWE-328": Knowledge(
        "A02:2021 - Cryptographic Failures",
        "Replace weak hashes (MD5/SHA-1) with SHA-256 or better; use dedicated password hashing.",
        "Two different files with the same MD5 digest let an attacker swap a signed artifact.",
    ),
    "CWE-330": Knowledge(
        "A02:2021 - Cryptographic Failures",
        "Use a cryptographically secure RNG (secrets module, crypto.randomBytes) for anything security-relevant.",
        "Session tokens built on Math.random() are predicted and used to hijack other users' sessions.",
    ),
    "CWE-502": Knowledge(
        "A08:2021 - Software and Data Integrity Failures",
        "Never deserialize untrusted data with pickle/unserialize; use plain JSON with schema validation.",
        "A crafted serialized object executes code the moment the server unserializes it.",
    ),
    "CWE-611": Knowledge(
        "A05:2021 - Security Misconfiguration",
        "Disable external entity resolution in every XML parser you use.",
        "An uploaded XML with an external entity reads local files into the parsed output.",
    ),
    "CWE-918": Knowledge(
        "A10:2021 - Server-Side Request Forgery (SSRF)",
        "Validate and allow-list outbound URLs; block internal address ranges.",
        "A URL parameter pointed at the cloud metadata address returns instance credentials.",
    ),
    "CWE-352": Knowledge(
        "A01:2021 - Broken Access Control",
        "Use anti-CSRF tokens and SameSite cookies on every state-changing request.",
        "A hidden form on another site silently submits a password change for a logged-in victim.",
    ),
    "CWE-434": Knowledge(
        "A04:2021 - Insecure Design",
        "Validate upload type/size server-side, store outside the web root, never trust the filename.",
        "An 'image' upload named shell.php is then requested directly and runs on the server.",
    ),
    "CWE-94": Knowledge(
        "A03:2021 - Injection",
        "Never eval() user input; use safe parsers or a restricted expression evaluator.",
        "A calculator field forwarding to eval() accepts arbitrary code instead of numbers.",
    ),
    "CWE-95": Knowledge(
        "A03:2021 - Injection",
        "Avoid dynamic code evaluation on user input entirely; allow-list expected values.",
        "Input reaching eval() lets an attacker run code with the application's privileges.",
    ),
    "CWE-1321": Knowledge(
        "A06:2021 - Vulnerable and Outdated Components",
        "Upgrade the affected package to the fixed version listed in the advisory.",
        "A crafted property assignment changes an object's prototype chain and can alter application logic in unexpected places.",
    ),
    "CWE-829": Knowledge(
        "A08:2021 - Software and Data Integrity Failures",
        "Load code or resources only from trusted, integrity-checked locations controlled by the application.",
        "An application imports executable content from a location an attacker can replace or influence.",
    ),
    "CWE-1104": Knowledge(
        "A06:2021 - Vulnerable and Outdated Components",
        "Track dependencies against advisory databases and upgrade on a schedule.",
        "A publicly documented exploit for an old library version is reused as-is against the app.",
    ),
    # The CWEs below turn up mostly on dependency advisories.
    "CWE-770": Knowledge(
        "A06:2021 - Vulnerable and Outdated Components",
        "Upgrade the affected package; enforce size/rate limits on anything user-supplied.",
        "A request that allocates unbounded memory is repeated until the service runs out.",
    ),
    "CWE-400": Knowledge(
        "A06:2021 - Vulnerable and Outdated Components",
        "Upgrade the affected package and bound the work any single request can cause.",
        "A small crafted input triggers disproportionate CPU or memory use, starving other users.",
    ),
    "CWE-1333": Knowledge(
        "A06:2021 - Vulnerable and Outdated Components",
        "Upgrade the affected package; avoid backtracking-prone regexes on user input.",
        "A long crafted string makes a vulnerable regex run for minutes (ReDoS).",
    ),
    "CWE-20": Knowledge(
        "A03:2021 - Injection",
        "Validate input against an expected type, range and format server-side.",
        "Unvalidated input reaches logic that assumed a shape it never checked.",
    ),
    "CWE-200": Knowledge(
        "A01:2021 - Broken Access Control",
        "Return only the fields a caller is entitled to; keep errors and stack traces internal.",
        "A verbose error response reveals internal paths and library versions to an attacker.",
    ),
    "CWE-915": Knowledge(
        "A08:2021 - Software and Data Integrity Failures",
        "Allow-list which fields may be set from request data; never mass-assign blindly.",
        "An extra field in a submitted form sets an attribute the form never displayed, such as a role.",
    ),
    "CWE-209": Knowledge(
        "A05:2021 - Security Misconfiguration",
        "Log details server-side; return a generic message and an error id to the caller.",
        "A stack trace in an error page reveals file paths, library versions and query fragments.",
    ),
    "CWE-203": Knowledge(
        "A07:2021 - Identification and Authentication Failures",
        "Make failure responses uniform in content and timing so they reveal nothing.",
        "A login that answers faster for unknown users lets an attacker enumerate valid accounts.",
    ),
    "CWE-732": Knowledge(
        "A01:2021 - Broken Access Control",
        "Set least-privilege permissions on files, directories and cloud resources.",
        "A world-readable configuration file exposes credentials to any local account.",
    ),
}

UNKNOWN = Knowledge(
    "Not mapped by this report",
    "Review the tool's explanation, advisory, and CWE identifier before choosing a fix.",
    "No general scenario is stored for this CWE; use the tool or advisory evidence for this finding.",
)


def lookup(cwe: str) -> Knowledge:
    """Return knowledge for a CWE id, or the safe generic entry."""
    return CWE_KNOWLEDGE.get(cwe.strip().upper(), UNKNOWN)
