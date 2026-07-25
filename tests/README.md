# Testing the review suite

The design names five success criteria. A script can prove some of them outright and can only
establish the preconditions for the rest, because "did the reviewer assign the right severity" is a
judgement a live agent session has to make. This file is explicit about which is which — a suite
that implied it had tested everything would be committing the exact defect the skills are written to
prevent.

Run everything a machine can check:

```bash
bash tests/run.sh          # validator + every installed linter, against the fixtures
python3 tests/validate.py  # validator alone
```

## Automated

`tests/validate.py` is a structural validator. Eight check groups, no dependencies beyond the Python
standard library.

| Check group | What it proves |
|---|---|
| `check_manifests` | `plugin.json` and `marketplace.json` parse, carry the required keys, and agree on name and version. |
| `check_references` | `rubric.md` defines all four severities and all three confidence levels; `procedure.md` documents the probe pattern and all four error-handling cases; `agent-prompt.md` carries the template slots and all three status values. |
| `check_agent_prompt_parses` | **Design criterion 4.** The agent prompt block is machine-readable: `tests/fixtures/agent-prompt/sample-block.md` parses into findings, every finding has a usable literal anchor, severities come from the rubric, IDs ascend, and the status table names all three verdicts. |
| `check_skill_frontmatter` | Every skill has exactly `name` + `description`, frontmatter within 1024 chars, name matching its directory, a description starting with "Use when" and written in third person outside quoted trigger phrases, links to all three reference documents, a "Checks skipped" requirement, and no dangling reference paths. |
| `check_tool_probes` | Every skill lists exactly the tools the design assigns it, with a `command -v` probe line. |
| `check_checklist_coverage` | **Precondition for criterion 1.** Every checklist row a skill declares is planted in one of that skill's vulnerable fixtures; every planted ID belongs to the skill that owns the fixture directory; every cross-referenced ID exists; every fixture directory has a clean counterpart. |
| `check_vuln_anchors` | **The comment is not the defect.** Every `VULN: <ID>` carries an `ANCHOR:` line naming the defective construct, which must still appear in the file — or an `ANCHOR-ABSENT:` line naming the guard whose absence *is* the defect, which must not. A positive anchor may not also appear in the clean counterpart, since a literal true of the corrected code can never detect the defect being fixed. Fixing a plant without removing its annotation fails here. |
| `check_delegation` | Both entry points delegate to all four language skills, state how findings merge, and use no `@` path links. |
| `check_trigger_distinctness` | **Precondition for criterion 3.** Language skills name their language; entry-point descriptions contain no language token; security intent words appear only in `security-review`. |

`tests/run.sh` adds real-tool checks over the fixtures — `gofmt`, `go build`, `go vet`, `shellcheck`,
`bash -n`, `php -l`, `py_compile`, `node --check` — plus a **differential suite per language**. Every
tool that is not installed is reported as `SKIP` with its reason. A check with no fixtures to run
against is also a skip, never a pass.

### Anchors and differentials are a pair

Neither half is sufficient alone, and it is worth being precise about which failure each catches:

| | Catches | Misses |
|---|---|---|
| `check_vuln_anchors` | The planted construct was deleted or rewritten — the realistic drift when someone tidies a fixture. | A fix that leaves the anchored text in place and neutralises it elsewhere (an early `return` added above an anchored dereference). |
| Differential tests | Any change that stops the fixture *behaving* defectively, however it was made. | Rows whose defect is not observable by running the code — see the coverage table below. |

Differential coverage. **Every "covered" claim below was established by mutation** — applying a
correct fix and watching the suite go red — not by inspection. That distinction is not pedantic: an
earlier version of this table listed `GO-05` and `GO-06` as covered, and a blind review caught that
both tests passed against a correct fix. See "Verifying the checks can fail".

| Fixture | Rows covered by running the code | Held by anchors only |
|---|---|---|
| `general/` | GEN-01…GEN-07 (all) | — |
| `bash/` | SH-01…SH-07 (all) | — |
| `go/` | GO-01, GO-02, GO-05, GO-07 | GO-03, GO-04, GO-06 |
| `php/` | PHP-01, PHP-02, PHP-03, PHP-05, PHP-06 | PHP-04 |
| `vue-ts/` | VT-02, VT-03, VT-06, VT-07 | VT-01, VT-04, VT-05 |
| `security/` | — | SEC-01…SEC-07 |

The gaps are honest ones, each with a reason:

- **`GO-06`** is unobservable by construction. `DecodeEvent` returns only an `Event`, so "error
  discarded" and "error logged, zero `Event` returned" look identical to every caller. Any test
  asserting the zero value passes against a correct fix — which is what the earlier one did.
- **`GO-05`** needed the consequence, not the shape. Counting descriptors around the call proves
  nothing, because the defers have all run by the time it returns. The test now walks 200 files in a
  child process with a 64-descriptor limit, where holding them open makes `os.Open` fail partway and
  the total come up short.
- **`PHP-04`** cannot be checked in-process: `session_start()` is not repeatable.
- **`VT-01`/`VT-04`/`VT-05`** live in a `.vue` SFC, which needs the Vue compiler this repo does not
  depend on.
- **`GO-03`/`GO-04`** are a leak and an injection whose effects need a live context and a real
  database rather than assertions.
- **`security/`** is a framework sketch with stubbed routes, so nothing in it is callable.

Two hazards worth knowing about, both found by these tests failing honestly:

- **Stale bytecode.** Python invalidates a `.pyc` on `(mtime, size)`. An edit changing neither —
  `+ 25` to `+ 30` inside one second — is invisible to that check, and a stale cache answers for the
  source. Two mitigations, because one is not enough: `run.sh` clears `tests/fixtures/**/__pycache__`
  before the differential gates (the `py_compile` gate above them writes those files), and
  `test_differential.py` sets `sys.dont_write_bytecode` so it adds no more. Note the asymmetry —
  `dont_write_bytecode` stops writing, not reading, so on its own it would not have helped.
- **`set -u` hides SH-07.** Under `set -u` the unset array reference in `x[$(...)]` is a *fatal*
  unbound-variable error: bash exits 127 before the command substitution runs. `vulnerable.sh` has
  no `set -u` — that is SH-02 — which is exactly what leaves SH-07 reachable. The two rows are not
  independent, and a harness with its own `set -u` demonstrates the guard rather than the defect.

What none of this proves: that a review finds the planted defects, scores them correctly, or stays
quiet on the clean fixtures. Those need an agent.

## Manual

Each step needs a live agent session. Nothing below is covered by `validate.py`.

### 1. Severity accuracy — design criterion 1

For each of the six skills, in a fresh session:

| Skill | Point it at | Expect |
|---|---|---|
| `review-go` | `tests/fixtures/go/vulnerable.go` | GO-01…GO-07 all reported |
| `review-bash` | `tests/fixtures/bash/vulnerable.sh` | SH-01…SH-07 all reported |
| `review-vue-ts` | `tests/fixtures/vue-ts/vulnerable.vue` and `vulnerable.ts` | VT-01…VT-07 all reported |
| `review-php` | `tests/fixtures/php/vulnerable.php` | PHP-01…PHP-06 all reported |
| `code-review` | `tests/fixtures/general/vulnerable.py` | GEN-01…GEN-07 all reported, plus a statement that no language-specific pass ran |
| `security-review` | `tests/fixtures/security/vulnerable.py` | SEC-01…SEC-07 all reported |

**Pass conditions.** Every `VULN:` ID in the fixture appears in the report. No ID is silently
absent — a finding the reviewer decided against must be stated as considered and dismissed, not
omitted. Severity is defensible against the rubric, and specifically these must not be under-scored:
`GO-04`, `PHP-02`, `PHP-03`, `PHP-05`, `VT-01`, `VT-02`, `VT-04`, `SEC-01`, `SEC-03`, `SEC-04`,
`SEC-06` are Critical or High on the fixture's facts. Grep the fixture for the ID list:

```bash
grep -o 'VULN: [A-Z]*-[0-9][0-9]' tests/fixtures/go/vulnerable.go | sort -u
```

### 2. False positives — design criterion 2

Point each skill at its `clean.*` fixture(s).

**Pass condition:** zero Critical and zero High findings. Medium and Low are acceptable — the clean
fixtures are realistic code, not perfect code — but each one should survive being read aloud. A
Critical or High on a clean fixture is a false positive and means the checklist row that produced it
needs its "why it matters" tightened.

**Now also scripted, with a caveat `tests/trigger-test.sh` doesn't have.** `tests/severity-test.sh`
runs all six vulnerable fixtures through a fresh headless session each and scores the report against
the planted `VULN:` IDs and the floor list above:

```bash
bash tests/severity-test.sh
```

The caveat: a fresh session that reads a fixture's own "deliberately defective... used to test the
review-X skill" header can reasonably conclude the file is inert (nothing imports it, nothing runs
it) and apply the rubric's own reachability rule to decline scoring the plants as live findings —
auditing the plants' *accuracy* instead of their severity. That happened on the first run of this
script and is a legitimate reading of the rubric, not a bug in the reviewer. Read the actual reports
before trusting the score; a raw FAIL can mean "under-scored" or it can mean "found something more
useful than what was asked." See the 2026-07-25 entry below for what that first run actually found.

### 3. Trigger behaviour — design criterion 3

**Now scripted.** `tests/trigger-test.sh` runs all eight cases:

```bash
bash tests/trigger-test.sh
```

Each case runs in a genuinely fresh headless session (`claude -p`) with the plugin installed, so the
routing decision is made by an agent that has never seen this repository — which is the whole point,
and the reason the fixtures' author cannot stand in for it. `--allowed-tools Skill` keeps each run to
the routing decision instead of paying for a full review. The script parses the stream-json
transcript for `Skill` tool calls and scores both halves: the intended skill fired, and the contender
did not. It skips (exit 0) rather than failing when the `claude` CLI is absent or the plugin is not
installed.

`claude plugin eval` would be the better instrument — it has a no-plugin ablation arm — but it is
gated behind early access. Revisit when it opens up.

The table below is the source of truth for what each case asserts; run it by hand if you want to
watch the routing happen.

| Phrasing | Must load | Must not load |
|---|---|---|
| "review this before I merge" | `code-review` | `security-review` |
| "look over this PR" | `code-review` | any language skill, when the diff is empty |
| "audit this for vulns" | `security-review` | `code-review` alone |
| "is this exploitable?" | `security-review` | `code-review` |
| "review this Go service" | `review-go` (directly, or via `code-review` delegation) | `review-php`, `review-vue-ts` |
| "check this deploy script is safe" | `review-bash`, plus `security-review` on the safety wording | `review-go` |
| "review this component" | `review-vue-ts` | `review-php` |
| "audit this PHP endpoint" | `review-php` and `security-review` | `review-go` |

**Pass condition:** the intended skill loads and the contending one does not. `check_trigger_distinctness`
only proves the descriptions cannot contend on language tokens; whether the model picks correctly is
observable behaviour and has to be observed.

### 4. Tools absent — design criterion 5

Run any language skill on a machine where its tools are not installed. This is the default state of
most machines, and it was the state of the machine this suite was built on — only `go`, `bun`, `php`,
`node`, `python3` and `jq` were present.

**Pass conditions:** the review completes rather than stopping; every absent tool appears in
`## Checks skipped` with a reason and an install hint; the agent prompt block's validation line names
only binaries that are actually present; and nowhere does the report imply a check passed when it did
not run.

To test the crash path specifically — which is the dangerous one — put a syntax error in a file and
confirm the report distinguishes "the tool found problems" from "the tool could not run".

## Last manual run — 2026-07-25

| Criterion | Result |
|---|---|
| 1. Severity accuracy | **Pass, blind.** See the two `severity-test.sh` runs below — 41/41 IDs found on the second, one (`GO-04`) still under the floor for a defensible reason, not a fixture bug. |
| 2. False positives | **Pass.** Zero Critical and zero High across all six clean fixtures. Two Mediums found and since fixed: a lock held across a network call in `general/clean.py`, and a `security/clean.py` comment claiming SSRF protection stronger than the code provided. |
| 3. Trigger behaviour | **Pass, 8/8.** Run via `tests/trigger-test.sh`. Every phrasing loaded its intended skill and no contender fired. Two confounds resolved in the suite's favour: Claude Code's built-in `/security-review` did **not** win tests 3 and 4 — `claude-review-suite:security-review` did — and no `superpowers` skill hijacked routing despite a global instruction to prefer them. |
| 4. Tools absent | **Pass.** Under `PATH=/usr/bin:/bin` (17 of 21 tools hidden), every missing linter became a `SKIP` with its reason, exit stayed 0, and no absent check was reported as passing. |

Criterion 1 also surfaced a gap the validator cannot see: one defect frequently matches two checklist
rows, and nothing said how to attribute it. `references/rubric.md` now carries the rule ("One defect
matching several checklist rows"), keyed on whether the rows imply the same fix.

### Criterion 1, blind — two `severity-test.sh` runs, 2026-07-25

The first run — same-author severity accuracy is the weakest kind of pass, so this suite ran itself
through the same blind technique that closed criterion 3. It found something more useful than a
severity score: **the fixtures' own `VULN:` annotations had real, unnoticed defects**, caught only
because a reviewer with no memory of writing them checked each claim against the code instead of
trusting the comment. Fixed as a direct result:

| Fixture | What was wrong |
|---|---|
| `php/vulnerable.php` PHP-05 | `login()` had no `password_verify` call at all — not "bypassable", absent. Added the check; the concatenated query is now the sole remaining defect. |
| `php/vulnerable.php` PHP-03 | The annotation's `%00` null-byte PoC has been dead since PHP 5.3.4. Restated without it. |
| `php/vulnerable.php` PHP-04 | `cookie_secure` was left to ambient `php.ini` instead of pinned like the other two sub-defects. Pinned. |
| `bash/vulnerable.sh` SH-02 | The annotation claimed a `pipefail` failure mode; no pipeline existed anywhere in the file. Added one (`curl \| tee ... \| tar`) where `tee`'s always-0 exit genuinely masks a failed `curl`, verified empirically before landing it. |
| `bash/vulnerable.sh` | A second, unannotated unquoted-`$DEST` site at line 55 masked the annotated SH-01 site's shellcheck signal. Quoted. |
| `go/vulnerable.go` | `TotalSize`'s swallowed errors read as an unannotated second GO-06 instance. Commented as deliberate best-effort handling instead. |
| `go` toolchain | `run.sh` only ran `gofmt -e` (a parse gate) against Go fixtures — no compile or vet gate existed at all. Added both (see `run.sh`). |
| `vue-ts/vulnerable.vue` | An 8th, unannotated defect (untyped JSON into a typed ref, no `res.ok`) contradicted the file's own three-defect header ledger. Guarded to match `clean.vue`. |
| `vue-ts/vulnerable.ts` VT-02 | `renderSearchSummary` had no caller anywhere in the fixture pair, undercutting the README's Critical/High floor for that row. Gave it one, off `location.search`. |
| `vue-ts/vulnerable.ts` VT-03 | The CSRF annotation claimed "any origin"; the request's JSON content type actually forces a CORS preflight. Restated with the real precondition. |
| `general/vulnerable.py` GEN-01 | Annotation said "off-by-one, drops the first row"; the code drops an entire page. Restated. |
| `general/vulnerable.py` GEN-04 | Annotation claimed a torn/partial read; the dict store is atomic under the GIL, so that race is impossible. Restated as the real race (duplicate fetch, last store wins) — now consistent with `clean.py`'s comment for the same mechanism. |
| `general/vulnerable.py` GEN-07 | The boundary branch was behaviourally identical to deleting it (verified), so it read as GEN-06 dead code, not an untested boundary. Removed the redundant branch so the missing lower-bound check is the only thing there. |
| `general/` | Nothing executed the fixtures' actual behaviour — `test_shipping_band.py` existed but wasn't wired into `run.sh`, and `GEN-02`/`GEN-04`/`GEN-05`/`GEN-06` had no executable check at all. Added `test_differential.py` (asserts `vulnerable.py` and `clean.py` disagree on the inputs each plant names) and wired both files into `run.sh`. |

The second run, after those fixes: 41/41 planted IDs found (zero missing, down from four), one
(`GO-04`) still under the Critical/High floor. That one is not a fixture bug — `package fixture` has
no `func main`, no test, nothing that imports it, and a reviewer applying the rubric's own
reachability rule to a package literally nothing consumes is being consistent, not wrong. Closing it
for real means giving the Go package the same kind of reachable caller VT-02 got, and `GO-07`
(unsynchronised map write) makes that harder than it sounds: a concurrent map write is an
unrecoverable Go runtime fatal error, not a panic, so a test that exercises it the obvious way takes
the whole test binary down rather than failing one case. Left as a known, accepted gap rather than
worked around under time pressure.

One more thing worth naming: the first run had `review-php`, `review-vue-ts`, and `security-review`
all decline to score their fixtures' plants as live findings — treating the "deliberately vulnerable
test fixture" framing as a reason not to. The second run, after only fixture-content edits (no skill
changes), had all three score real `[F1] Critical`-style findings instead. Same skills, same
rubric, different runs. Treat one `severity-test.sh` run as directional, not definitive — the
reachability-versus-fixture-framing judgement call is genuinely close enough to go either way.

## Adding a checklist row

The validator enforces the loop, so the order matters:

1. Add the row to the skill's checklist table with the next ID in its prefix.
2. Plant a matching defect in that skill's `vulnerable.*` fixture, annotated `VULN: <ID>`.
3. Give it an anchor on the following line — `ANCHOR:` with a literal from the defective construct,
   or `ANCHOR-ABSENT:` with the guard whose absence is the defect. Anchors must be at least 8
   characters and distinctive enough not to match incidentally. **Grep the clean fixture for the
   anchor before committing it**: a literal that also appears there is true of the correct version,
   so it can never detect the defect being fixed.
4. Write the correct counterpart into the `clean.*` fixture.
5. Add a differential check if the defect is observable by running it, and update the coverage table
   above either way. A row that lands in the anchors-only column needs a stated reason.
6. `python3 tests/validate.py` — it fails at step 1 alone, which is the point.

## Verifying the checks can fail

A check that cannot fail is worse than no check, so both mechanisms were mutation-tested: fix the
planted defect, confirm the suite goes red, restore. Results on 2026-07-25:

| Mechanism | Mutations | Caught |
|---|---|---|
| `check_vuln_anchors` (positive) | 8 | 8 |
| `check_vuln_anchors` (`ANCHOR-ABSENT`) | 4 | 4 |
| `check_vuln_anchors` vs *semantically correct* fixes (VT-05, SH-06) | 2 | 2 |
| Go differential | 5 | 4 (GO-06 is anchors-only — see above) |
| TypeScript differential | 4 | 4 |
| Python differential | 7 | 7 |
| Bash differential | 7 | 7 |

**An anchor must not match the clean fixture.** `VT-05`'s original anchor was the `defineProps<...>`
line — byte-identical in `clean.vue`, because VT-05's defect is the *absence* of validation, not the
presence of `defineProps`. Applying the real fix left `validate.py` fully green. It now anchors
`:href="props.avatarUrl"`, which only the defective version has. `SH-06` had the mirror problem: it
anchored `RELEASE=$2` while its prose described `DEST=$1`, so the canonical fix passed. Both were
found by blind review, not by the mutation runs above — mutating *deletions* is not the same as
mutating *fixes*.

Auditing the rest for the same shape turned up three more (`GO-05` anchored `defer f.Close()`, which
`clean.go` also does; `GEN-03` anchored `return written`; `SH-02`'s second site anchored a pipeline
deliberately identical in `clean.sh`). Rather than fix those and hope, `check_vuln_anchors` now
rejects any positive anchor that appears in the clean counterpart, so the whole class is closed
structurally. `ANCHOR-ABSENT` is exempt — the guard it names is *expected* in the clean fixture.

**Mutate with a correct fix, not a broken one.** The `GO-05` test originally looked green against
`defer f.Close()` → `f.Close()`, but that mutation *breaks* the function — the file is closed before
`Stat`, so the total goes wrong for a reason unrelated to the row. Against the fix a real engineer
would make (extract the loop body so `defer` runs per call, as `clean.go` does), the same test
passed. A mutation that damages the code proves nothing; it has to be the change you are afraid
someone will make.

Two more traps, both of which produced false "caught"/"missed" results before being spotted:

- **Anchors shadow naive mutations.** Replacing the first textual match hits the `ANCHOR:` comment,
  because it quotes the construct verbatim and comes first. Target the code line explicitly
  (`if "..." in l and "ANCHOR" not in l`). Three apparent misses were this.
- **Assertions that a wrong path also satisfies.** `GEN-04` counted `fetch` calls and expected two —
  but a serialised path where the first fetch fails and the second retries also reaches two, so a
  lock-guarded fix slipped through. It now asserts that both threads were *inside* `fetch`
  simultaneously, using a barrier whose successful release is the proof.
