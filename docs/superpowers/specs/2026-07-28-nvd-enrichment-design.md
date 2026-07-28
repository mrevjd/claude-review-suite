# NVD Enrichment for `security-review`: Design

**Date:** 2026-07-28
**Status:** Approved design, pending implementation plan

## Purpose

`security-review` runs `trivy`, which reports vulnerable dependencies by CVE ID. The suite
currently has no way to say anything about those CVEs beyond the ID and whatever text the scanner
prints. This adds a lookup against the NVD 2.0 API so each CVE a scanner already found carries its
CVSS vector, CWE, publication date and NVD analysis status into the report.

The suite queries no vulnerability feed today. Nothing named NVD, NIST or CVSS appears in the
original design, the implementation plan or any commit; this is new capability, not a gap being
closed.

## Scope

**In scope:** enrichment of CVE IDs that a scanner in the existing toolchain already produced, in
`security-review` only.

**Out of scope (deliberate):**

- **Independent CVE discovery by CPE matching.** Querying NVD by product and version would reach
  things no package manager covers (system binaries, vendored C, base images), but CPE matching
  without a version-aware SBOM produces false positives, and a false positive costs this suite more
  than a missed dependency CVE does. `trivy` already covers the package ecosystems.
- **Enrichment in the language skills.** `review-go` (`govulncheck`), `review-php`
  (`composer audit`) and `review-vue-ts` (`bun audit`) also emit CVE IDs. Adding enrichment there
  would need a dedupe rule in the merge step for a CVE enriched twice by different passes. Deferred
  until `security-review` proves the shape.
- **Auto-fixing, CI wiring, dependency upgrade suggestions.** Unchanged from the suite's existing
  out-of-scope list.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| What NVD is used for | Enrich CVEs scanners found | Bounded request count, no new false positives |
| Where it runs | `security-review` only | One tool row, one skipped-check row, smallest surface |
| How it runs | A shipped helper script | Prose instructing the agent to fetch is untestable |
| Key storage | Config file plus env override | Documented location outside the repo, easy CI override |

A shipped script was chosen over two alternatives. Prose telling the agent to fetch the API itself
has no way to attach the key, no cache, no rate-limit discipline, and an output shape that depends
on the model reading the same JSON the same way twice. A `review-tools.sh nvd` subcommand would
keep the repo at one executable, but `references/procedure.md:25` forbids every skill from running
`review-tools.sh`, so an agent-invoked subcommand inside it is a footgun.

## Component: `nvd-enrich.sh`

A sibling of `review-tools.sh` at the repository root. Depends on `curl` and `jq`, both already in
`review-tools.sh`'s `TOOLS` list, so this adds no new dependency.

Unlike every other entry in a skill capability table, this script ships with the plugin and is
always present. What varies is `curl`, `jq`, the key and network reachability, so those are what
gets probed. Skills already reference sibling files by relative path (`../../references/rubric.md`),
and `../../nvd-enrich.sh` follows that pattern.

### Interface

CVE IDs on stdin, TSV on stdout, diagnostics on stderr.

```
$ printf 'CVE-2021-44228\nCVE-2020-8203\n' | ./nvd-enrich.sh
CVE-2021-44228  10    CRITICAL  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  CWE-917  2021-12-10  Analyzed  live
CVE-2020-8203   7.4   HIGH      CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H  CWE-1321 2020-07-15  Analyzed  cache
```

`10`, not `10.0`. `jq` renders a JSON number in its shortest round-tripping decimal form, so a
whole-number double always prints without a fractional part and the script cannot emit `10.0`. The
human-readable `NVD:` line in a finding may still say `CVSS 10.0`, which is how CVSS scores are
conventionally written; the TSV column is whatever `jq` produced.

Eight tab-separated columns:

| Column | Source | Notes |
|---|---|---|
| `ID` | input | uppercased, deduped |
| `SCORE` | `cvssMetricV31[0].cvssData.baseScore` | `-` when unscored |
| `SEVERITY` | `.baseSeverity` | NVD's label, not this suite's severity vocabulary |
| `VECTOR` | `.vectorString` | carries its own `CVSS:3.1/` or `CVSS:4.0/` prefix, so no separate version column is needed |
| `CWE` | `weaknesses[].description[].value` | first `CWE-` value; `-` when only `NVD-CWE-noinfo` |
| `PUBLISHED` | `.published` | date only, `YYYY-MM-DD` |
| `STATUS` | `.vulnStatus` | verbatim: `Analyzed`, `Modified`, `Awaiting Analysis`, `Rejected` |
| `PROVENANCE` | script | `live`, `cache`, `cache-stale`, `unavailable` |

Metric preference is `cvssMetricV31`, then `cvssMetricV40`, then `cvssMetricV30`, then
`cvssMetricV2`. `STATUS` is a first-class column rather than a flag because `Rejected` is
actionable on its own: a scanner flagging a withdrawn CVE is a finding about the scanner.

Input is validated against `^CVE-[0-9]{4}-[0-9]{4,}$`. Anything failing validation is dropped with
a note on stderr and never sent to the API.

**Every input CVE produces exactly one output row.** A CVE that could not be resolved gets `-` in
the data columns and `unavailable` as provenance. Silently omitting failures would hand the agent a
shorter list with no way to know it was shorter, which is the failure mode
`references/procedure.md:4` exists to prevent.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | ran and produced output, even if some rows are `unavailable` |
| `1` | could not run at all: `curl` or `jq` missing, or empty input |
| `2` | usage error |

There is deliberately no "found problems" exit code. `references/procedure.md:125` makes every
skill distinguish "the tool found problems" from "the tool crashed"; enrichment has no third
state, so non-zero always means skipped check and the skill needs no new rule to interpret it.

### `--check`

Prints a capability report and exits, mirroring `review-tools.sh probe`. This is what the skill's
probe step calls.

```
$ ./nvd-enrich.sh --check
curl     present
jq       present
key      present (nvd.env)
cache    ~/.cache/claude-review-suite/nvd  (31 entries)
network  services.nvd.nist.gov reachable
```

`--check` never prints the key itself, only its presence and source. The network line is a
`curl -sS --max-time 5 -o /dev/null -w '%{http_code}'` against the API base, so a probe on an
offline machine costs five seconds at worst rather than hanging the review.

## Key handling

Resolution order, first hit wins:

1. `$NVD_API_KEY`, if set and non-empty
2. `${XDG_CONFIG_HOME:-$HOME/.config}/claude-review-suite/nvd.env`
3. no key, keyless mode

An NVD key is a rate-limit token, not a credential to anything private, and is free on request.
The bar is "never committed, never echoed", not vault-grade storage. Three properties get it there.

**The file is parsed, not sourced.** A `source` on a config file is arbitrary code execution, and
`SH-03` in `skills/review-bash/SKILL.md` is a checklist row about that class of defect. A tool
shipping inside a review suite must not contain the bug the suite reports. Parsing is a `grep` for
`^NVD_API_KEY=` and a `cut`; comments and blank lines are tolerated, everything else ignored.

**A file with permissions looser than `0600` is refused, not read.** The script prints the exact
`chmod` needed and continues keyless. Read-and-warn was rejected: `SEC-04` treats a readable
credential as a finding, so honouring one anyway while printing a warning teaches the reader that
the warning is ignorable.

**The key never reaches a command line.** `curl -H "apiKey: $KEY"` puts it in `/proc/<pid>/cmdline`,
which is world-readable on Linux. The header is written to a `mktemp` file at `0600` with a cleanup
trap and passed via `curl --config`, which is also the `SH-04` temp-file pattern this suite teaches.

## Cache

`${XDG_CACHE_HOME:-$HOME/.cache}/claude-review-suite/nvd/CVE-YYYY-NNNN.json`. Directory `0700`.
File modes are left to the process umask, since NVD responses are public data and the `0700`
directory already bounds access.

TTL is keyed off `vulnStatus`, by file mtime:

| Status | TTL | Why |
|---|---|---|
| `Analyzed`, `Modified` | 7 days | scores get revised, but not often |
| `Awaiting Analysis`, `Undergoing Analysis`, `Received` | 24 hours | precisely the records expected to change |
| `Rejected` | 30 days | will not change again |

If a live fetch fails and a stale entry exists, the stale entry is used and the row reports
`cache-stale` rather than passing it off as fresh. Clearing the cache is `rm -rf` on the directory,
documented in the README; there is no flag for it.

## Rate limiting

NVD allows 5 requests per rolling 30 seconds unauthenticated and 50 with a key, and advises spacing
requests rather than bursting.

| | Spacing | Requests per run |
|---|---|---|
| keyless | 6s | 8 |
| keyed | 0.6s | 50 |

**The cap counts requests, not CVEs.** Counting CVEs looks equivalent and is not: a retry is a
request, so a run that retried rate-limited lookups could make roughly twice the figure above,
against an API that had already asked it to back off. Since the cap exists to bound network work, the
thing it counts has to be the thing that touches the network.

Cache hits count against neither the cap nor the spacing delay, since they make no request. A stale cache entry is served
even once the budget is spent, for the same reason: reading a file already on disk is not network
work, and discarding a cached answer at the cap costs the caller real information for nothing. It is
also the exact case the cache was built for, a large repository reviewed more than once.

`NVD_MAX_LOOKUPS` overrides the cap, and is validated: a non-numeric value is refused with a warning
and the default kept, rather than making the comparison error out per CVE and silently removing the
one guard between a 200-CVE repository and a twenty minute review. `NVD_MAX_LOOKUPS=0` is legal and
means "answer from the cache, make no requests". CVEs past the cap with no cached copy return
`unavailable` with a reason on stderr, which the report then surfaces.

On HTTP 403 or 429 the script honours `Retry-After` when present, otherwise retries once after 10s
keyed or 30s keyless. **If the retry is rate-limited too, the run is over its allowance and every
remaining CVE is marked `unavailable` without being requested.** Retrying each CVE independently
instead makes a keyless 3-CVE batch six requests and five sleeps, roughly 100 seconds of waiting with
no output until the end, which reads to the caller as a hung tool.

## Degradation

| Condition | Script behaviour | Report |
|---|---|---|
| `curl` or `jq` absent | exit 1, no output | `## Checks skipped`, naming `review-tools.sh` as a suggestion |
| no key | keyless, 6s spacing, cap 8 | notes the keyless run and the capped count |
| `nvd.env` mode looser than `0600` | refuse, warn, continue keyless | `## Checks skipped`, with the `chmod` |
| network unreachable | cache only, uncached become `unavailable` | `## Checks skipped`, with the count |
| rate-limited mid-run | remainder `unavailable` | `## Checks skipped`, with the count |
| CVE absent from NVD (404) | row marked `unavailable` | finding still reported, noted as absent from NVD |
| scanners found no CVEs | never invoked | nothing, and not a skipped check |

**Enrichment failing never suppresses the underlying finding.** `trivy` found the vulnerable
dependency; NVD only decorates it. An unenriched CVE appears in the report exactly as it does
today.

Consistent with `references/procedure.md:25`, the script is invoked by the skill but the *installer*
is not: when `curl` or `jq` is missing, the report names `review-tools.sh` and leaves running it to
the user.

## Integration into `security-review`

Four edits to `skills/security-review/SKILL.md`.

**1. Capability probe.** Add `../../nvd-enrich.sh --check` alongside the three `command -v` lines.

**2. Tool table.** One row:

| Tool | Invocation | If absent |
|---|---|---|
| `nvd-enrich.sh` | `<cve-ids> \| ../../nvd-enrich.sh` | ships with the plugin; needs `curl`, `jq`, and network. Without a key it runs at a reduced cap |

**3. Procedure step 3.** After the scanners run, collect CVE IDs from their output with
`grep -oE 'CVE-[0-9]{4}-[0-9]{4,}'` and pipe them through the script. Grepping the text rather than
parsing a scanner's JSON keeps this working across `trivy` output-format changes and across any
scanner added later, and the script deduplicates its own input. The step states that a CVE with no
enrichment is still reported.

**4. Severity calibration.** The rule below.

A fifth edit lands outside the skill: `references/procedure.md`'s finding format gains an optional
`NVD:` line, present only on findings that carry a CVE. That file is shared by all six skills, so
the line is specified as optional and no skill other than `security-review` emits it today. This is
the only shared-surface change in the design, and it is what makes the language skills cheap to add
later if enrichment proves out.

### CVSS is evidence, never severity

The one way this feature could make the product worse. CVSS is an absolute, context-free score.
This suite's rubric is the opposite: `references/rubric.md:20` makes reachability drive severity and
caps a dangerous pattern in dead code at Medium. Dropping CVSS numbers into that report invites the
agent to anchor on 9.8 and mark findings Critical with no reachable path, which is the severity
inflation `skills/security-review/SKILL.md:132` already warns against.

So: enriched fields go on their own evidence line in the finding. Severity remains assigned by the
checklist walk and the calibration ladder at `skills/security-review/SKILL.md:96-102`.

Where this suite's severity and NVD's diverge, the finding says so in one clause. That divergence
is the most informative line in the report, and stating it is a forcing function: scoring below NVD
requires writing down why.

```
[F3] Medium · Confirmed · package-lock.json:1204 · SEC-06
  What:  lodash 4.17.15 is vulnerable to prototype pollution via _.zipObjectDeep.
  NVD:   CVE-2020-8203 · CVSS 7.4 High · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
         · CWE-1321 · published 2020-07-15
  Why:   Scored below NVD because no call path reaches _.zipObjectDeep with
         attacker-controlled keys; the only caller passes a literal shape.
  Fix:   Upgrade to lodash >= 4.17.19.
```

The vector is on the line, not just the score. This example originally dropped it, which was
backwards on this document's own argument: `AV:N/AC:H/PR:N/UI:N` is exactly the input the severity
ladder consumes, and the bare `7.4` is exactly the number this section warns the agent will anchor
on. Printing the anchor while withholding the reasoning input is the opposite of the intent.

The `NVD:` line is the optional addition to the finding format in `references/procedure.md`
described above, present only on findings that carry a CVE.

## Testing

Script tests use the PATH shim already established at `tests/fixtures/bash/differential.sh:42`,
where `curl` and friends are shimmed ahead of the real binaries. No test-only branch inside
`nvd-enrich.sh` and no network access in the test run.

`tests/fixtures/nvd/` holds recorded responses: a scored CVE, an awaiting-analysis record, a
rejected record, a 404, a 403 rate-limit body, and malformed JSON.

Gates added to `tests/run.sh`:

1. `shellcheck` on `nvd-enrich.sh`. The suite lints shell and should lint its own.
2. The scored fixture produces the exact expected TSV row.
3. An unresolvable CVE still emits a row and the script still exits 0, enforcing the
   never-silently-drop invariant.
4. Empty stdin exits 1. `jq` shimmed away exits 1 with no partial output.
5. `nvd.env` at `0644` is refused, a warning is emitted, and the run continues keyless.
6. The key never appears in stdout or stderr: the full captured output is grepped for the fixture
   key value and the gate fails if it is found.

Checks added to `tests/validate.py`, so the guardrail is enforced rather than trusted:

1. `security-review`'s capability table contains the `nvd-enrich.sh` row.
2. Its severity calibration section contains the "evidence, never severity" rule.
3. Its `## Checks skipped` guidance names NVD enrichment.

If someone adds the feature and drops the guardrail, the validator fails.

### What the guardrail cannot do

`check_nvd_enrichment()` enforces that the calibration rule is **stated**, in three bounded places:
that `## Severity calibration` says CVSS is evidence and never severity, that `## Procedure` actually
invokes the script, and that `## Output` tells the reader to name a failed enrichment in
`## Checks skipped`. That is all it enforces.

It cannot enforce that reports are **calibrated**. Nothing in this suite would notice if every
finding rendered `NVD: CVSS 9.8 Critical` beside a severity of `Critical`, with no reachable call
path stated and no divergence clause anywhere, on every finding in every report. The one property
that would make this feature harmful is the one property no structural check can see, because it is a
property of judgement exercised at review time and not of text in a file.

So: a green validator run is evidence that the instruction survives, not evidence that it is
followed. Eleven passing check groups must never be read as "the reports are sound". Whether severity
tracks reachability rather than CVSS is a live-agent question, and it belongs with the other criteria
that `tests/README.md` documents as a manual protocol and deliberately does not claim as automated.

## Documentation

A README section covering: obtaining a key, creating `nvd.env` with `chmod 600`, the `NVD_API_KEY`
override, keyless behaviour and its cap, the cache location and how to clear it, and `--check`.

`.gitignore` gains a defensive `nvd.env` line, in case the file is ever created in the repository
root rather than `~/.config`.

## Files Changed

| Path | Change |
|---|---|
| `nvd-enrich.sh` | new, the helper described above |
| `skills/security-review/SKILL.md` | probe line, tool table row, procedure step 3, calibration rule |
| `references/procedure.md` | optional `NVD:` line in the finding format |
| `README.md` | key setup, keyless behaviour, cache, `--check` |
| `.gitignore` | defensive `nvd.env` |
| `tests/fixtures/nvd/` | new, recorded API responses |
| `tests/nvd-test.sh` | new, the test driver holding all script-level gates |
| `tests/run.sh` | one gate invoking the driver, plus `nvd-enrich.sh` added to `repo_scripts` |
| `tests/validate.py` | three structural checks |

No file outside this list is touched. Nothing under `~/.config` or `~/.cache` is created by the
suite: the key file is the user's to create, and the cache directory is created by the script on
first successful fetch.

## Open Items

None. Design approved 2026-07-28.
