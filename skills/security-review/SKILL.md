---
name: security-review
description: Use when the user asks whether code is safe or wants it audited for security - "security review", "audit this", "check for vulns", "is this exploitable", "any injection risk here", "threat model this endpoint" - covering authentication, authorisation, injection, secret handling, crypto, deserialisation, SSRF, and sensitive data exposure.
model: opus
effort: xhigh
---

# Security Review

Threat-oriented review, language-agnostic, and the security entry point for the suite. The question
is not "is this code good?" but "what can an untrusted actor make this code do?"

For general correctness and maintainability, use `code-review`. Run both before shipping something
that matters; they find different defects.

## Procedure

Follow `../../references/procedure.md` for scoping, probing and error handling. Specifically:

1. **Establish the trust boundary first.** Before reading for defects, identify what is
   attacker-controlled: request parameters, headers, cookies, uploads, webhook payloads, queue
   messages, filenames, environment on shared hosts, and any data that made a round trip through
   storage. Everything downstream of an untrusted input is in scope; everything else is context.
2. **Scope.** The diff for a change review, the tree for an audit. State which you used: a clean
   result on three files is not a clean result on the application.
3. **Probe and run** the tools below.
4. **Enrich the CVEs.** Collect CVE IDs from scanner output with
   `grep -oE 'CVE-[0-9]{4}-[0-9]{4,}'` and pipe them through `../../nvd-enrich.sh`. Grepping the
   text rather than parsing a scanner's JSON keeps this working across output-format changes and
   across any scanner added later; the script deduplicates its own input. A CVE that comes back
   `unavailable` is still reported as a finding, with the enrichment gap named in
   `## Checks skipped`.

   Each row is eight tab-separated columns, and reading them wrongly is how enrichment becomes
   decoration:

   | Column | What to do with it |
   |---|---|
   | `ID` | the CVE, uppercased and deduped |
   | `SCORE` | NVD's CVSS base score. Evidence for the finding, never its severity |
   | `SEVERITY` | NVD's own label (`CRITICAL`…`LOW`), not this suite's vocabulary. Never copy it into the severity field |
   | `VECTOR` | the CVSS vector, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/…`. This is the input to the ladder below, so carry it onto the `NVD:` line |
   | `CWE` | first `CWE-` value, or `-` when NVD recorded none |
   | `PUBLISHED` | `YYYY-MM-DD` |
   | `STATUS` | NVD's analysis state, not an error field. `Analyzed` and `Modified` are normal; `Awaiting Analysis` means the score may move; **`Rejected` means the CVE was withdrawn, so the finding is about the scanner flagging a withdrawn CVE, not about the dependency** |
   | `PROVENANCE` | `live` or `cache` are current. **`cache-stale` means the lookup failed and a past-TTL copy was served, so the score may be out of date; `unavailable` means no enrichment at all.** Both go in `## Checks skipped`: `unavailable` with the reason the script printed on stderr, `cache-stale` with the token itself as the reason, since the script prints nothing on stderr for a stale-served row |
5. **Delegate** to every language skill that applies (`review-go`, `review-bash`, `review-vue-ts`,
   `review-php`), asking each to weight its security-relevant rows (see Delegation).
6. **Walk the threat checklist below** over every file in scope.
7. **Score by exploitability** per `../../references/rubric.md` and the calibration note below, then
   merge.
8. **Emit both artifacts.**

## Capability probe

```bash
command -v semgrep
command -v gitleaks
command -v trivy
command -v snyk
snyk whoami --experimental   # exit 0 = authenticated; prints a username, never the token
../../nvd-enrich.sh --check
```

| Tool | Invocation | If absent |
|---|---|---|
| `semgrep` | `semgrep --config auto --error` | `pipx install semgrep` (note that `--config auto` fetches rules, so it needs network access) |
| `gitleaks` | `gitleaks detect --no-banner --redact` | `brew install gitleaks` / download a release binary |
| `trivy` | `trivy fs --scanners vuln,secret .` | `brew install trivy` / `apt install trivy` |
| `snyk` (SCA) | `snyk test --severity-threshold=low` | `bun add -g snyk`, then `snyk auth`. Both are the user's call: `auth` opens a browser and writes a credential to their home directory |
| `snyk` (SAST) | `snyk code test --severity-threshold=low` | as above, and read the egress note before running it on a repository that is not yours |
| `nvd-enrich.sh` | `<cve-ids> \| ../../nvd-enrich.sh` | ships with the plugin, so it is always present. Needs `curl` and `jq` and network access; without an API key it runs at a reduced lookup cap |

Several missing at once? The suite ships `review-tools.sh`, which probes and installs the whole
toolchain in one pass. **Name it in `## Checks skipped` and leave running it to the user**: a review
reports, it does not install. It also has a `snyk` subcommand that runs both scans on their own,
for when the scan is wanted without a full review pass; that one is the user's to run too.

### snyk has four states, not two

Every other tool here is present or absent. snyk can be present, authenticated, and still unable to
run the scan you asked for, and those middle states are the ones that mislead.

**Installed but not authenticated is a skipped check**, never a pass and never a finding.
`snyk test` exits non-zero on an auth failure exactly as it does on a real vulnerability, so reading
the exit code alone misfiles the same run in either direction: "clean", or "found something", when
the truth is "did not run".

Probe it with `snyk whoami`, which answers in a username. Not with `snyk config get api`, which
answers by printing the token onto stdout and from there into this report: that is the SEC-04
finding this skill raises on other people's code, committed by the review itself.

Four distinct rows, never collapsed into one:

| State | How it shows | `## Checks skipped` reason |
|---|---|---|
| binary absent | `command -v` fails | `snyk not installed` |
| present, unauthenticated | `snyk whoami` exits non-zero | `snyk installed but not authenticated` |
| authenticated, not entitled | exit 2 with `SNYK-CODE-0005` / HTTP 403 | `Snyk Code not enabled for this organisation` |
| authenticated, command failed | any other exit 2 | the exit code and the first line of the error, per `../../references/procedure.md` |

The entitlement row is not hypothetical and it is not a crash. Snyk Code is a separately licensed
product, so an account that authenticates perfectly can still be refused the SAST scan, and it is
refused with the same exit 2 a real failure uses. Read the error body, not the exit code: `403` with
`SNYK-CODE-0005` means the check did not run and nobody can fix it from the command line. Reporting
that as a crash overstates it; reporting it as a clean SAST pass is the lie this suite is built to
refuse.

Note what this state implies about the egress note below: where Snyk Code is not enabled, no source
leaves the machine, because the scan is refused before it uploads.

**`snyk code test` uploads source code to Snyk.** `snyk test` does not; it sends the dependency
graph built from manifests and lockfiles. Snyk's published policy is that code is analysed once and
cached only for the cloud provider's storage minimum (24 hours on the US/GCP tenant, 24 to 48 hours
on AWS EU/AU and private tenants), after which the code is deleted and only finding locations, issue
IDs and explanations persist, and that customer code is not used for engine training. Say this out
loud in the report when the review is of a repository the user does not own: the decision to send it
is theirs, and it is not reversible once made. `.snyk` and `--exclude` narrow what goes.

**Deduplicate against the scanners that already ran.** `snyk test` covers the ground
`trivy --scanners vuln` covers, and `snyk code test` overlaps `semgrep`. Two scanners reaching the
same defect is one finding, keyed by package plus advisory for SCA and by file, line and claim for
SAST; the corroboration goes on the finding as evidence, not into a second row. Independent
agreement is worth recording precisely because it is the strongest signal in the report, and it
stops being that if it is padded out into two.

snyk labels its own findings High/Medium/Low. Same rule as CVSS below: evidence, never severity.
Snyk leads with `SNYK-*` advisory IDs, so only the subset that also carries a CVE enriches through
`nvd-enrich.sh`; the rest are reported on the advisory ID alone.

The four scanners exit non-zero when they find something: that is a result, not a crash. snyk
separates the cases by code, verified against CLI 1.1307.0: **1** is findings, **3** is no supported
project in scope (a SKIP reading `no dependency manifest in scope`, not a clean bill), and **2** is
everything that went wrong, entitlement included, which is why 2 has to be read rather than
counted.
`nvd-enrich.sh` deliberately has no found-problems exit code, so non-zero from it always means the
enrichment step was skipped. A `semgrep` run
that cannot fetch its ruleset, a `gitleaks` run outside a git repository, or a `trivy` database
download failure *is* a crash: it goes in `## Checks skipped` with the reason, because "no secrets
found" and "the secret scanner could not run" must never read the same way.

`gitleaks` and `trivy --scanners secret` only see what is in the working tree or history they were
pointed at. A secret they miss is not a secret that is not there: the SEC-04 walk still happens by
hand.

## Delegation

Each language skill carries rows that are directly security-relevant. Run the full skill, then weigh
these rows first when scoring:

| Skill | Weight these rows |
|---|---|
| `review-go` | `GO-04` (SQL by concatenation), `GO-02` (assertion panic as a remote DoS), `GO-06` (ignored error hiding a failed authorisation check) |
| `review-bash` | `SH-01` (unquoted expansion in a destructive command), `SH-03` (`eval`), `SH-04` (predictable temp path), `SH-05` (PATH hijack), `SH-07` (arithmetic-context injection) |
| `review-vue-ts` | `VT-01`, `VT-02` (XSS sinks), `VT-03` (CSRF), `VT-04` (secret in the bundle), `VT-06` (prototype pollution) |
| `review-php` | all of `PHP-01`…`PHP-06`: every row is a security row |

**Merging:** one list, renumbered `Fn` across all passes, checklist IDs preserved, ordered by
severity then file. Rules in `../../references/rubric.md`. **No language detected:** the threat
checklist below is the whole review; say so explicitly and name the files it covered.

## Threat checklist

| ID | Look for | Why it matters | Fix direction |
|---|---|---|---|
| **SEC-01** | An endpoint, handler, job, or admin route with no authentication check; a check that is commented out, behind a feature flag, or applied by a decorator or middleware that this route bypasses; a debug or health path that exposes more than liveness; a token compared with `==` rather than a constant-time function. | Unauthenticated access to privileged functionality is the shortest path an attacker has. Middleware-based auth fails silently when a route is registered on a different router. | Deny by default: authentication at the router, not per handler, so a new route is protected unless it explicitly opts out. Compare secrets with a constant-time comparison. |
| **SEC-02** | An object fetched by an ID from the request with no check that the caller owns it; a role checked at the UI but not the API; a check on a resource's parent but not the resource; a list endpoint that filters client-side. | Broken object-level authorisation is the most commonly exploited web vulnerability and the least visible in review, because the code looks complete: it fetches, it returns, it just never asks *whose* it is. | Scope every query by the authenticated principal (`WHERE id = ? AND owner_id = ?`), and make authorisation a property of the data access layer rather than something each handler remembers. |
| **SEC-03** | Untrusted data concatenated into SQL, a shell command, a template, an LDAP or XPath query, a file path, a regular expression, or a NoSQL selector; `shell=True`, `eval`, dynamic `require`/`import`. | Injection turns data into instructions: read any table, run any command, read any file. Path traversal is the same defect with a different sink. | Parameterise (bound SQL parameters, argument arrays for exec, escaped template contexts). Where an identifier must vary, resolve it through a fixed allow-list. Validate at the boundary and escape at the sink. Both. |
| **SEC-04** | A key, token, password, private key, connection string, or webhook secret committed in source, a config file, a test fixture, a lockfile, or CI config; a secret in a log line, an error message, or a URL query string; a client-side env var holding a real credential. | A committed secret is compromised the moment it is pushed, and stays in history after it is deleted. Secrets in logs spread to every system the logs reach. | Move it to a secret store or the environment, and **say in the finding that the value needs rotating**: removing it from the file is not remediation. Add the pattern to the secret scanner's config. |
| **SEC-05** | `md5`/`sha1`/unsalted hashes for passwords; a fast hash where a KDF belongs; `random`/`Math.random`/`rand()` for a token, session ID, or password reset; ECB mode; a hardcoded or reused IV; a static salt; disabled certificate verification; a homegrown crypto construction. | Weak password hashing makes a database dump a credential dump. A predictable token is a guessable session. Disabled certificate verification makes TLS decorative. | A dedicated password KDF (`argon2id`, `bcrypt`, `scrypt`); a CSPRNG for anything secret; an authenticated cipher mode (AES-GCM, ChaCha20-Poly1305) with a per-message nonce; certificate verification always on. |
| **SEC-06** | `pickle`/`unserialize`/`Marshal.load`/Java or .NET deserialisation on untrusted bytes; YAML loaded with an unsafe loader; XML parsing with external entities enabled; a server-side request to a URL from user input; a redirect target from a request parameter. | Untrusted deserialisation is remote code execution, not data tampering. SSRF reaches the cloud metadata endpoint and internal services that trust the network position. XXE reads local files. | Use a data-only format (JSON) for anything crossing a trust boundary. For outbound requests, resolve and validate the host against an allow-list, reject private and link-local ranges, and disable redirects. Disable external entities in every XML parser. |
| **SEC-07** | A stack trace, SQL error, internal path, or full object returned in an error response; a serialiser that returns every column including password hashes and tokens; PII or card data written to logs; a verbose response distinguishing "no such user" from "wrong password"; a cache or CDN header allowing a private response to be stored. | Exposure is both an attack in itself and reconnaissance for the next one. An enumeration oracle turns an unknown user list into a known one. | Log details server-side and return a correlation ID. Serialise an explicit allow-list of fields rather than the model. Make authentication failures indistinguishable. Set cache headers deliberately on authenticated responses. |

Also weigh: missing rate limiting on authentication and expensive endpoints, uploads trusted by
client-supplied content type or extension, dependencies flagged by the scanners with a reachable call
path, CORS configured with a reflected origin plus credentials, and missing integrity checks on
anything fetched at runtime and executed.

## Severity calibration

Exploitability drives severity, not code ugliness.

- **Critical**: reachable by an unauthenticated actor with no unusual precondition, and the
  consequence is code execution, authentication bypass, or mass data access.
- **High**: reachable behind ordinary authentication, or needs a precondition the attacker can
  reasonably arrange.
- **Medium**: needs a precondition the attacker does not control (a specific race, a privileged
  position, a misconfiguration not present here), or the consequence is limited.
- **Low**: hardening. Real, worth doing, no current path to impact.

Two rules that keep the report honest: **state the path**, so severity is auditable (who sends
what, to which entry point, reaching which sink). And where you could not confirm the path, use the
confidence field (`Likely`, `Speculative`) rather than deflating the severity. A Critical/Speculative
finding is a legitimate and useful thing to report; a Critical silently downgraded to Medium because
tracing it was hard is not.

**A CVSS score is evidence, never severity.** NVD scores a vulnerability in the abstract; this
suite scores what an attacker can do in *this* codebase, and `../../references/rubric.md` makes
reachability the deciding factor. A CVSS 9.8 in a dependency with no reachable call path is not a
Critical finding here. Put the enriched fields on the finding's `NVD:` line and assign severity
from the ladder above.

Where the two diverge, say so in one clause. That divergence is the most auditable line in the
report, and writing it down is what stops a scanner's number quietly becoming the verdict.

## Output

Both artifacts, always:

1. **Human report** per the skeleton in `../../references/procedure.md`, ending in one
   `## Checks skipped` table covering every scanner and every delegated pass that did not run.
2. **Agent prompt block** per `../../references/agent-prompt.md`, carrying every severity, omitted
   entirely when there are no findings.

For any SEC-04 finding, the agent prompt block entry must say the credential requires rotation:
otherwise a downstream agent deletes the line, reports `FIXED`, and leaves a live secret in history.

When `nvd-enrich.sh` could not enrich some or all CVEs, name **NVD enrichment** in
`## Checks skipped` with the reason the script reported on stderr: no API key and the lookup cap,
a missing `jq` or `curl`, an unreachable network, or a refused key file. Several tools missing at
once is what `review-tools.sh` exists for; name it there and leave running it to the user.

## Common mistakes

- **Reporting scanner output as findings.** `semgrep` flags patterns; exploitability needs the call
  path. Read the code, then assign confidence per `../../references/rubric.md`.
- **Treating a clean scanner run as a clean review.** None of these tools find broken authorisation,
  which is the most common serious finding on this list.
- **Auditing the code and not the boundary.** A review that never asked what is attacker-controlled
  has not done the work, however many files it read.
- **Calling a crashed scanner clean.** "`gitleaks` found no secrets" and "`gitleaks` was not
  installed" are opposite claims. The second belongs in `## Checks skipped`.
- **Severity inflation.** Marking every hardening item High destroys the signal that makes the
  Critical ones actionable.
