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
| `check_delegation` | Both entry points delegate to all four language skills, state how findings merge, and use no `@` path links. |
| `check_trigger_distinctness` | **Precondition for criterion 3.** Language skills name their language; entry-point descriptions contain no language token; security intent words appear only in `security-review`. |

`tests/run.sh` adds real-tool checks over the fixtures — `gofmt`, `shellcheck`, `bash -n`, `php -l`,
`py_compile`, `node --check` — so a vulnerable fixture is confirmed *vulnerable* rather than merely
broken. Every tool that is not installed is reported as `SKIP` with its reason. A check with no
fixtures to run against is also a skip, never a pass.

What the validator does **not** prove: that a review finds the planted defects, scores them
correctly, or stays quiet on the clean fixtures. Those need an agent.

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

### 3. Trigger behaviour — design criterion 3

In a fresh session each time, issue the phrasing and observe which skill loads.

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
| 1. Severity accuracy | **Weak pass.** All 41 planted IDs locatable with defensible severity — but run by the fixtures' own author, so it does not show that the checklists lead an unprimed reviewer to the defects. Re-run blind before trusting it. |
| 2. False positives | **Pass.** Zero Critical and zero High across all six clean fixtures. Two Mediums found and since fixed: a lock held across a network call in `general/clean.py`, and a `security/clean.py` comment claiming SSRF protection stronger than the code provided. |
| 3. Trigger behaviour | **Not run.** Needs the plugin installed and a fresh session per phrasing. `check_trigger_distinctness` only proves the descriptions cannot contend on language tokens. |
| 4. Tools absent | **Pass.** Under `PATH=/usr/bin:/bin` (17 of 21 tools hidden), every missing linter became a `SKIP` with its reason, exit stayed 0, and no absent check was reported as passing. |

Criterion 1 also surfaced a gap the validator cannot see: one defect frequently matches two checklist
rows, and nothing said how to attribute it. `references/rubric.md` now carries the rule ("One defect
matching several checklist rows"), keyed on whether the rows imply the same fix.

## Adding a checklist row

The validator enforces the loop, so the order matters:

1. Add the row to the skill's checklist table with the next ID in its prefix.
2. Plant a matching defect in that skill's `vulnerable.*` fixture, annotated `VULN: <ID>`.
3. Write the correct counterpart into the `clean.*` fixture.
4. `python3 tests/validate.py` — it fails at step 1 alone, which is the point.
