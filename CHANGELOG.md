# Changelog

Notable changes to `claude-review-suite`. Versions match the `version` field in
`.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`, and each has an annotated git
tag. Entries before 0.2.0 are drawn from those tag messages.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.2]: https://github.com/mrevjd/claude-review-suite/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/mrevjd/claude-review-suite/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/mrevjd/claude-review-suite/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mrevjd/claude-review-suite/releases/tag/v0.1.0
