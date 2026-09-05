# Changelog

Notable changes to `claude-review-suite`. Versions match the `version` field in
`.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`, and each has an annotated git
tag. Entries before 0.2.0 are drawn from those tag messages.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-09-05

### Added

- `snyk` joins the `security-review` toolchain: `snyk test` for dependencies and `snyk code test`
  for source. Both run inside the threat pass, so a gate that already invokes `security-review`
  picks them up with no change at the call site.
- **`probe` has a third status, `NOAUTH`.** Every other tool here is a capability the moment it is
  on `PATH`; snyk also needs an authenticated session, and an unauthenticated `snyk test` exits
  non-zero with the same code a real vulnerability produces. Reading the exit code alone turns "did
  not run" into either "clean" or "found something", both wrong and neither announcing itself.
  `ABSENT` and `NOAUTH` are counted separately, because installing a binary will not authenticate
  it.
- A fourth state, documented and given its own skipped-check reason: Snyk Code is separately
  licensed, so an authenticated account can still be refused the SAST scan with exit 2 and
  `SNYK-CODE-0005`, which is the exit code a genuine crash also uses. The error body distinguishes
  them; the exit code does not.
- `./review-tools.sh snyk [dir]` runs the two scans on their own, for when the scan is wanted
  without a full review pass. Each scan reports RAN or SKIP with a reason, and the exit code keeps
  "found nothing" apart from "could not scan": 0 clean, 1 findings, 2 neither scan ran.
- `check_snyk_probe`, the thirteenth check group, enforcing all of the above: the probe asks the
  PATH question and the auth question, the unauthenticated case is written down as a skipped check,
  `snyk auth` carries the same suggest-don't-run qualifier the installer does, and snyk is wired
  into both `TOOLS` and the dispatch table.
- `tests/snyk-probe-test.py`, run by `tests/run.sh`, watching each of those branches reject what it
  claims to. It earned its place immediately: the dispatch-table assertion was matching `auth_ok`'s
  own `snyk)` case arm, so it stayed green with the dispatch entry deleted.

### Security

- The auth probe is `snyk whoami`, which answers with a username, never `snyk config get api`, which
  answers by printing the token onto stdout and from there into the report. That is the SEC-04
  finding this suite raises on other people's code, committed by the review itself.
  `check_snyk_probe` bans it from the probe block while allowing the prose to name it, so the reason
  it is wrong survives the next edit.
- `snyk code test` uploads source to Snyk. The skill states this at probe time, with Snyk's
  published retention terms (analysed once, cached for the cloud provider's storage minimum: 24
  hours on the US/GCP tenant, 24 to 48 hours on AWS EU/AU and private tenants; then deleted, leaving
  only finding locations, issue IDs and explanations; not used for engine training), so the decision
  to send a repository is made before the scan rather than discovered after it.

## [0.3.1] - 2026-09-05

### Fixed

- `.gitleaksignore` is replaced by `.gitleaks.toml`. The old file listed two fixture paths, but it
  matches *fingerprints* (`commit:path:rule:line`) and never paths, so gitleaks rejected both entries
  as invalid on every run and suppressed nothing. `gitleaks detect` had been exiting 1 on this
  repository as a result. Emptying the file produced byte-identical output, which is how it was shown
  to be dead rather than merely suspected.
- The `TESTKEY-` placeholder in `tests/nvd-test.sh` and the design doc that introduced it is now
  allowlisted by content rather than by path, so the exemption travels with the literal instead of
  blessing whole files. The rule that a hit outside `tests/fixtures/` is real and must be rotated is
  kept, with this as its one audited exception.

### Added

- Two gitleaks gates in `tests/run.sh`, one per direction: the repository must be quiet, and a
  credential planted outside the fixtures tree must still be caught. An allowlist is one widened
  pattern away from a scanner that reports nothing and looks clean doing it, which is the failure
  this suite exists to prevent. Mutation testing confirms the two are complementary: widening either
  allowlist trips only the second gate, deleting the config trips only the first.

### Note

- The fixtures allowlist blesses that whole tree, so a genuine credential committed under
  `tests/fixtures/` would not be reported. Accepted because every file there is fabricated input by
  construction, and stated in `.gitleaks.toml` rather than left to be discovered.

## [0.3.0] - 2026-09-05

### Added

- `model` and `effort` frontmatter on every skill: all six pin `model: opus` with `effort: xhigh`.
  A review's rigour was previously a property of whichever model the session happened to be on, so
  invoking the suite from a cheap session silently got a cheaper review with nothing in the report
  saying so. The pins make it a property of the skill instead. **This changes which model your
  session uses during a review, and what it costs**, which the README now says out loud.
- `check_skill_frontmatter` requires the six skills to agree on their pins. The entry points merge
  the language passes into one severity-ordered list, and a list assembled from passes run at
  different depths is ordered by severity and luck.
- `check_skill_frontmatter` warns when a skill pins a model Claude Code refuses to apply while auto
  mode is on. Such a pin is discarded, the session model is kept, and the only trace is a
  warning-level log line, so the failure mode is a review that looks pinned and is not. `haiku`
  (`claude-haiku-4-5`) is the current member of that set, verified against CLI 2.1.261; the alias
  is resolved at runtime, so re-check it rather than trusting the list.
- `tests/frontmatter-test.py`, run by `tests/run.sh`, asserting each of those branches still
  rejects what it claims to. The branches had been verified once by hand, and that verification was
  worthless: the fixture was restored with `git checkout --`, which reverts to the index, so three
  cases ran against a file whose `model:` line had already been wiped and passed having tested
  nothing.

### Changed

- Skill frontmatter is now exactly `name`, `description`, `model` and `effort`, all four required
  and value-checked, rather than exactly `name` + `description`. Anything else still fails: Claude
  Code ignores frontmatter keys it does not recognise, so an unchecked typo would fail nowhere and
  leave the pin silently unapplied. Integer efforts are accepted but must be positive with no
  leading zeros; the harness's upper bound could not be resolved from the shipped binary, so none
  is imposed.

## [0.2.2] - 2026-07-30

### Added

- This changelog, covering every release from 0.1.0. Reconstructed from the annotated tags and the
  commits in each range rather than from memory, and cross-checked against the code: the request
  budgets, cache TTLs, paths and provenance values all verify, and the 0.1.1 entry was rewritten
  after reading the diff showed the `SEC-06` change was to the clean fixture rather than the
  vulnerable one.

No functional change from 0.2.1.

## [0.2.1] - 2026-07-30

### Changed

- The plugin description in both manifests now names NVD enrichment. It says "scanner-found CVEs
  annotated from the NIST NVD" rather than implying the suite discovers CVEs itself: it annotates
  the ones `trivy`, `govulncheck` and the audit subcommands already report.

No functional change from 0.2.0.

## [0.2.0] - 2026-07-30

### Added

- `nvd-enrich.sh`, a shipped helper that reads CVE IDs on stdin and writes one tab-separated row per
  CVE from the NIST NVD 2.0 API: ID, CVSS score, severity, vector, CWE, publication date, NVD
  analysis status, and provenance (`live`, `cache`, `cache-stale` or `unavailable`). Every input CVE
  produces exactly one row, so an enrichment gap is always visible rather than silently absent.
- NVD enrichment in `security-review`: a probe line, a capability-table row, a procedure step that
  collects CVE IDs from scanner output, and a table documenting all eight output columns and what to
  do with a `Rejected` status or a degraded provenance.
- An optional API key, read from `$NVD_API_KEY` or `${XDG_CONFIG_HOME:-~/.config}/claude-review-suite/nvd.env`.
  The file is parsed rather than sourced, is refused unless its mode is `0600` or `0400`, and the key
  value is never printed on any path. It reaches `curl` through a `0600` config file rather than a
  command-line argument, which would be world-readable in `/proc`.
- A response cache under `${XDG_CACHE_HOME:-~/.cache}/claude-review-suite/nvd`, with a TTL derived
  from NVD's own analysis status: 7 days once analysed, 24 hours while awaiting analysis, 30 days
  once rejected. A stale entry is served with `cache-stale` provenance rather than discarded when a
  fetch fails or the request budget is spent.
- Request budgets and spacing, 8 requests keyless and 50 with a key, overridable with
  `NVD_MAX_LOOKUPS`. A 403 or 429 is retried once, honouring `Retry-After`, after which the
  remaining CVEs are reported unavailable instead of retried individually.
- `nvd-enrich.sh --check`, a five-line capability report covering `curl`, `jq`, the key source, the
  cache, and network reachability, used as the skill's capability probe.
- An eleventh check group in `tests/validate.py` that fails if the severity calibration rule is
  deleted, if the enrichment step is removed from the procedure, or if the capability row or
  checks-skipped guidance goes missing.
- 47 checks in `tests/nvd-test.sh`, including a network sentinel that fails the suite if any test
  attempts a real API call.

### Changed

- `references/procedure.md`'s finding format gains an optional `NVD:` line, emitted only by
  `security-review`. It carries the CVSS vector alongside the score, because the vector is the input
  to the severity ladder while the bare score is the number most likely to be anchored on.
- Em dashes removed from every tracked file, 223 across 16 files.

### Note on severity

A CVSS score is evidence, never severity. NVD scores a vulnerability in the abstract; this suite
scores what an attacker can do in the codebase under review, and reachability decides. A CVSS 9.8 in
a dependency with no reachable call path is not a Critical finding here. Where the two diverge, the
finding says why. The validator enforces that this rule is stated; it cannot enforce that reports are
calibrated.

## [0.1.4] - 2026-07-25

### Changed

- Fixture defects made enforceable rather than asserted: content anchors, differential suites for all
  five languages, and Go reachability.

## [0.1.3] - 2026-07-25

### Fixed

- Fixture defects found and fixed by a blind criterion-1 pass, reaching 41 of 41 checklist IDs, with
  one defensible gap left open (`GO-04`).

## [0.1.2] - 2026-07-25

### Added

- Scripted trigger tests, closing criterion 3 at 8 of 8 passing.

## [0.1.1] - 2026-07-25

### Fixed

Findings from the first manual test run:

- `references/rubric.md` gained a rule for one defect that matches several checklist rows.
- The `RateCache` clean fixture no longer holds its lock across the network call, which serialised
  every reader behind one request and let a hung fetch block all of them. Two threads racing on a
  cold cache may now both fetch, and `setdefault` makes them agree on the result.
- The `SEC-06` clean fixture's comment no longer implies its SSRF guard is complete. It now ranks the
  three layers by what each one buys and names the residual gap: the address checked and the address
  the HTTP client later connects to are independent resolutions, so a host whose DNS an attacker
  controls can answer once with a public address and again with a link-local one.

## [0.1.0] - 2026-07-25

### Added

- Initial release of the code and security review skill suite: `code-review` and `security-review`
  entry points, the `review-go`, `review-bash`, `review-vue-ts` and `review-php` language skills, the
  shared rubric, procedure and agent-prompt references, and `review-tools.sh`.

[0.4.0]: https://github.com/mrevjd/claude-review-suite/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/mrevjd/claude-review-suite/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mrevjd/claude-review-suite/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/mrevjd/claude-review-suite/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/mrevjd/claude-review-suite/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mrevjd/claude-review-suite/releases/tag/v0.1.0
