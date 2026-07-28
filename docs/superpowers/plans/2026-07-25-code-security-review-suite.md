# Code & Security Review Skill Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this
> plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `claude-review-suite` Claude Code plugin (six review skills, three shared
reference documents, and an automated fixture-backed validator) per
`docs/2026-07-25-code-security-review-suite-design.md`.

**Architecture:** Content-only plugin. All behaviour lives in markdown: six `SKILL.md` files carry
triggers, capability probes and checklists; three files under `references/` carry the machinery
every skill shares (rubric, review procedure, agent prompt block). A dependency-free Python
validator under `tests/` enforces the structural invariants the design names: checklist IDs are
covered by fixtures, the agent prompt block parses, descriptions don't contend, no skill links to a
reference that doesn't exist.

**Tech Stack:** Markdown + YAML frontmatter (skills), JSON (plugin/marketplace manifests),
Python 3 stdlib (validator), Bash (test runner). No package manager, no dependencies.

## Global Constraints

- Plugin name: `claude-review-suite`. Version `0.1.0`. License MIT.
- Skill directory names, verbatim from the design: `code-review`, `security-review`, `review-go`,
  `review-bash`, `review-vue-ts`, `review-php`. Frontmatter `name` must equal directory name.
- Frontmatter carries exactly two keys, `name` and `description`; total frontmatter ≤ 1024 chars.
- `description` starts with `Use when`, third person, triggering conditions and symptoms only,
  never a summary of the skill's workflow.
- Skills reference each other by name (`review-go`), never with `@` path links.
- Skills load reference files by path relative to their own directory: `../../references/<file>.md`.
- Severity vocabulary, exactly: `Critical`, `High`, `Medium`, `Low`.
- Confidence vocabulary, exactly: `Confirmed`, `Likely`, `Speculative`.
- Agent prompt block status vocabulary, exactly: `FIXED`, `SKIPPED-STALE`, `SKIPPED-DISAGREE`.
- Finding IDs in a report: `F1`, `F2`, … Checklist IDs: `GO-nn`, `SH-nn`, `VT-nn`, `PHP-nn`,
  `GEN-nn`, `SEC-nn`.
- Capability probe is always `command -v <tool>`. An absent tool goes in "Checks skipped" with a
  reason and an install hint. A tool that crashes is a skipped check, not a clean result.
- No git operations. The working directory is not a repository and the user has not asked for
  commits; each task ends by running the validator instead of committing.
- Every task's step list ends with `python3 tests/validate.py` passing.

## File Structure

| Path | Responsibility |
|---|---|
| `.claude-plugin/plugin.json` | Plugin manifest: name, version, author, keywords. |
| `.claude-plugin/marketplace.json` | Single-plugin marketplace so `/plugin marketplace add <repo>` works. |
| `references/rubric.md` | Severity, confidence, finding format, finding ID scheme. |
| `references/procedure.md` | Shared review procedure: capability probe, language detection, report skeleton, error handling. |
| `references/agent-prompt.md` | Agent prompt block template + fill rules + validation-command derivation. |
| `skills/code-review/SKILL.md` | Entry point, general correctness/maintainability, `GEN-nn` checklist, delegation. |
| `skills/security-review/SKILL.md` | Entry point, threat-oriented, `SEC-nn` checklist, `semgrep`/`gitleaks`/`trivy` probe, delegation. |
| `skills/review-go/SKILL.md` | Go checklist `GO-01..07`, Go tool probe. |
| `skills/review-bash/SKILL.md` | Bash checklist `SH-01..07`, shell tool probe. |
| `skills/review-vue-ts/SKILL.md` | Vue/TS checklist `VT-01..07`, front-end tool probe. |
| `skills/review-php/SKILL.md` | PHP checklist `PHP-01..06`, PHP tool probe. |
| `tests/validate.py` | Structural validator. Grows one check group per task. |
| `tests/run.sh` | Runs the validator, plus any present real linters against the fixtures. |
| `tests/README.md` | The manual protocol for the criteria a script can't judge (severity accuracy, false positives, trigger behaviour). |
| `tests/fixtures/<lang>/vulnerable.*` | Known-vulnerable code, each planted defect annotated `VULN: <CHECKLIST-ID>`. |
| `tests/fixtures/<lang>/clean.*` | Known-clean counterpart, annotated `CLEAN-FIXTURE`. |
| `tests/fixtures/agent-prompt/sample-block.md` | A filled agent prompt block the validator parses, proving the template is machine-readable. |
| `README.md` | Install, what each skill does, the `/security-review` name-collision note. |

**Deviations from the design's layout, deliberate:** `references/procedure.md` (third reference
file: the probe/report/error-handling machinery is shared by all six skills and belongs in exactly
one place), `.claude-plugin/marketplace.json` (the design's documented install command requires
it), `tests/` (the design's Testing section requires fixtures), `README.md`.

## Checklist ID Registry

Fixed here so tasks written out of order agree. Every ID must be planted in a vulnerable fixture.

**Go**: `GO-01` nil dereference after error · `GO-02` unchecked type assertion · `GO-03` goroutine
and `context` leak · `GO-04` string-built `database/sql` query · `GO-05` `defer` inside a loop ·
`GO-06` ignored error · `GO-07` data race on shared state.

**Bash**: `SH-01` unquoted expansion / word splitting · `SH-02` missing `set -euo pipefail` ·
`SH-03` `eval` · `SH-04` unsafe temp file creation · `SH-05` PATH assumption · `SH-06` unvalidated
positional parameter · `SH-07` command substitution in an arithmetic context.

**Vue/TS**: `VT-01` `v-html` sink · `VT-02` `innerHTML` assignment · `VT-03` missing CSRF handling
on `fetch` · `VT-04` secret in the client bundle · `VT-05` unvalidated prop crossing a trust
boundary · `VT-06` prototype pollution · `VT-07` `any` masking a type error.

**PHP**: `PHP-01` superglobal reaching a sink unvalidated · `PHP-02` `unserialize` on untrusted
input · `PHP-03` LFI/RFI · `PHP-04` weak session configuration · `PHP-05` SQL built by
concatenation · `PHP-06` missing output escaping.

**General (`code-review`)**: `GEN-01` unhandled edge case or off-by-one · `GEN-02` error swallowed
or misreported · `GEN-03` resource not released on every path · `GEN-04` concurrency/ordering
assumption · `GEN-05` API contract violated (caller expectations, return shape) · `GEN-06` dead or
duplicated logic · `GEN-07` untested behaviour that a test could pin cheaply.

**Security (`security-review`)**: `SEC-01` missing or bypassable authentication · `SEC-02` broken
authorisation / IDOR · `SEC-03` injection (SQL, command, template, path) · `SEC-04` secret in
source or log · `SEC-05` weak crypto or bad randomness · `SEC-06` untrusted deserialisation or
SSRF · `SEC-07` sensitive data exposure through response, log, or error.

## Tool Probe Registry

Verbatim from the design; the validator asserts each skill lists exactly these.

| Skill | Tools |
|---|---|
| `review-go` | `go vet`, `staticcheck`, `gosec`, `govulncheck`, `errcheck` |
| `review-bash` | `shellcheck`, `shfmt` |
| `review-vue-ts` | `tsc --noEmit`, `eslint`, `bun audit`, `knip` |
| `review-php` | `php -l`, `phpstan`, `composer audit` |
| `security-review` | `semgrep`, `gitleaks`, `trivy` |
| `code-review` | none of its own; delegates |

---

### Task 1: Plugin scaffold and validator skeleton

**Files:**
- Create: `tests/validate.py`
- Create: `tests/run.sh`
- Create: `.claude-plugin/plugin.json`
- Create: `.claude-plugin/marketplace.json`

**Interfaces:**
- Consumes: nothing.
- Produces: `check(name, fn)` registration and a `fail(msg)`/`ok()` reporting contract that every
  later task's checks plug into. `SKILLS`: the list of the six skill directory names.
  `ROOT`: repository root as a `pathlib.Path`. `read(path)` → file text.

- [ ] **Step 1: Write the failing test, validator skeleton with manifest checks**

`tests/validate.py`:

```python
#!/usr/bin/env python3
"""Structural validator for claude-review-suite. Stdlib only."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ["code-review", "security-review", "review-go", "review-bash",
          "review-vue-ts", "review-php"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
CONFIDENCES = ["Confirmed", "Likely", "Speculative"]
STATUSES = ["FIXED", "SKIPPED-STALE", "SKIPPED-DISAGREE"]

failures = []
warnings = []


def fail(msg):
    failures.append(msg)


def warn(msg):
    warnings.append(msg)


def read(rel):
    path = ROOT / rel
    if not path.exists():
        fail(f"missing file: {rel}")
        return None
    return path.read_text(encoding="utf-8")


def load_json(rel):
    text = read(rel)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"{rel}: invalid JSON: {exc}")
        return None


def check_manifests():
    plugin = load_json(".claude-plugin/plugin.json")
    if plugin:
        for key in ("name", "description", "version", "author", "license"):
            if key not in plugin:
                fail(f"plugin.json: missing key {key!r}")
        if plugin.get("name") != "claude-review-suite":
            fail("plugin.json: name must be 'claude-review-suite'")
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(plugin.get("version", ""))):
            fail("plugin.json: version must be semver x.y.z")

    market = load_json(".claude-plugin/marketplace.json")
    if market and plugin:
        entries = market.get("plugins") or []
        if len(entries) != 1:
            fail("marketplace.json: expected exactly one plugin entry")
        else:
            entry = entries[0]
            if entry.get("name") != plugin.get("name"):
                fail("marketplace.json: plugin name disagrees with plugin.json")
            if entry.get("version") != plugin.get("version"):
                fail("marketplace.json: version disagrees with plugin.json")
            if entry.get("source") != "./":
                fail("marketplace.json: source must be './'")


CHECKS = [check_manifests]


def main():
    for check in CHECKS:
        check()
    for msg in warnings:
        print(f"WARN  {msg}")
    for msg in failures:
        print(f"FAIL  {msg}")
    total = len(CHECKS)
    if failures:
        print(f"\n{len(failures)} failure(s) across {total} check group(s)")
        return 1
    print(f"OK    {total} check group(s) passed, {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `python3 tests/validate.py`
Expected: exit 1, `FAIL  missing file: .claude-plugin/plugin.json` and the marketplace equivalent.

- [ ] **Step 3: Write the manifests**

`.claude-plugin/plugin.json`:

```json
{
  "name": "claude-review-suite",
  "description": "Code and security review skills for Go, Bash, Vue/TypeScript and PHP that emit a human report plus a re-verifiable agent prompt block",
  "version": "0.1.0",
  "author": {
    "name": "Evan Davies",
    "email": "evan.davies@gmail.com"
  },
  "license": "MIT",
  "keywords": [
    "code-review",
    "security-review",
    "static-analysis",
    "go",
    "bash",
    "vue",
    "typescript",
    "php"
  ]
}
```

`.claude-plugin/marketplace.json` mirrors it with `"source": "./"` and an `owner` block.

- [ ] **Step 4: Add the test runner**

`tests/run.sh`: `set -euo pipefail`, run `python3 tests/validate.py`, then run any present real
linter against the fixtures (`shellcheck` on `tests/fixtures/bash/*.sh`, `php -l` on
`tests/fixtures/php/*.php`, `gofmt -e` on `tests/fixtures/go/*.go`), reporting each absent tool as
a skipped check rather than a failure, the same discipline the skills themselves must follow.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 tests/validate.py && bash tests/run.sh`
Expected: `OK` from the validator; `run.sh` reports skipped linters for whatever is absent.

---

### Task 2: Shared reference documents

**Files:**
- Create: `references/rubric.md`, `references/procedure.md`, `references/agent-prompt.md`
- Create: `tests/fixtures/agent-prompt/sample-block.md`
- Modify: `tests/validate.py` (add `check_references`, `check_agent_prompt_parses`)

**Interfaces:**
- Consumes: `read`, `fail`, `CHECKS` from Task 1.
- Produces: `parse_block(text)` → `list[dict]` with keys `id`, `severity`, `path`, `lines`,
  `anchor`, `issue`, `expect`. Task 8's manual protocol reuses it. The three reference documents
  are the contract every skill in Tasks 3–7 links to.

- [ ] **Step 1: Write the failing checks**

Append to `tests/validate.py` and add both to `CHECKS`:

```python
def check_references():
    rubric = read("references/rubric.md")
    if rubric:
        for sev in SEVERITIES:
            if not re.search(rf"^\|?\s*\*?\*?{sev}\b", rubric, re.M):
                fail(f"rubric.md: severity {sev!r} not defined")
        for conf in CONFIDENCES:
            if conf not in rubric:
                fail(f"rubric.md: confidence {conf!r} not defined")
        for heading in ("## Severity", "## Confidence", "## Finding format"):
            if heading not in rubric:
                fail(f"rubric.md: missing section {heading!r}")

    proc = read("references/procedure.md")
    if proc:
        if "command -v" not in proc:
            fail("procedure.md: capability probe pattern 'command -v' not documented")
        for heading in ("## Capability probe", "## Language detection",
                        "## Report skeleton", "## Error handling"):
            if heading not in proc:
                fail(f"procedure.md: missing section {heading!r}")
        for case in ("crash", "no findings", "Checks skipped"):
            if case.lower() not in proc.lower():
                fail(f"procedure.md: error handling does not cover {case!r}")

    prompt = read("references/agent-prompt.md")
    if prompt:
        for token in ("Anchor:", "Issue:", "Expect:", "~L"):
            if token not in prompt:
                fail(f"agent-prompt.md: template missing {token!r}")
        for status in STATUSES:
            if status not in prompt:
                fail(f"agent-prompt.md: status {status!r} not in the required table")
        if "all severities" not in prompt.lower():
            fail("agent-prompt.md: must state the block carries all severities")


ANCHOR_RE = re.compile(r"^\s*Anchor:\s+`(?P<anchor>.+)`\s*$")
ENTRY_RE = re.compile(
    r"^\[(?P<id>F\d+)\]\s+(?P<severity>\w+)\s+·\s+@(?P<path>[^,]+),\s+~(?P<lines>L[\d\-]+)\s*$")


def parse_block(text):
    """Parse an agent prompt block into findings. Raises ValueError on a malformed entry."""
    findings, current = [], None
    for line in text.splitlines():
        entry = ENTRY_RE.match(line)
        if entry:
            if current:
                findings.append(current)
            current = dict(entry.groupdict())
            continue
        if current is None:
            continue
        anchor = ANCHOR_RE.match(line)
        if anchor:
            current["anchor"] = anchor.group("anchor")
        for field in ("Issue", "Expect"):
            m = re.match(rf"^\s*{field}:\s+(?P<v>\S.*)$", line)
            if m:
                current[field.lower()] = m.group("v").strip()
    if current:
        findings.append(current)
    return findings


def check_agent_prompt_parses():
    sample = read("tests/fixtures/agent-prompt/sample-block.md")
    if sample is None:
        return
    findings = parse_block(sample)
    if len(findings) < 2:
        fail("sample-block.md: expected at least two findings to parse")
    for f in findings:
        for field in ("anchor", "issue", "expect"):
            if not f.get(field):
                fail(f"sample-block.md: {f['id']} missing {field}")
        if f["severity"] not in SEVERITIES:
            fail(f"sample-block.md: {f['id']} severity {f['severity']!r} not in rubric")
        if f.get("anchor", "").strip() in ("", "..."):
            fail(f"sample-block.md: {f['id']} anchor is not a usable literal snippet")
    ids = [f["id"] for f in findings]
    if ids != sorted(ids, key=lambda s: int(s[1:])):
        fail("sample-block.md: finding IDs are not in ascending order")
    for status in STATUSES:
        if status not in sample:
            fail(f"sample-block.md: status table missing {status!r}")
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 tests/validate.py`
Expected: exit 1, `missing file: references/rubric.md` plus the other three missing files.

- [ ] **Step 3: Write `references/rubric.md`**

Sections, in order: `## Severity` (table: level, meaning, examples: Critical = exploitable now or
data loss; High = likely exploitable or wrong results in normal use; Medium = wrong under specific
conditions, or a real maintainability hazard; Low = smell, hardening, or style with a correctness
argument), `## Confidence` (Confirmed = verified by reading the code path or a tool reproduced it;
Likely = the pattern is present and the guard is absent, but the reachability is not fully traced;
Speculative = worth a human look, may be a false positive; and an explicit instruction that
Speculative findings are reported, never dropped and never promoted), `## Finding format` (the
`Fn` ID scheme, severity · confidence · `file:line`, what is wrong, why it matters, concrete fix
direction, and the checklist ID that caught it), `## Merging findings from multiple skills`
(renumber `Fn` across the merged list, keep the checklist ID so provenance survives, drop exact
duplicates, keep the higher severity when two skills disagree).

- [ ] **Step 4: Write `references/procedure.md`**

Sections, in order: `## Capability probe` (`command -v <tool>` per binary before any tool runs;
record present/absent up front; never invoke an unprobed binary), `## Language detection` (from the
diff when one exists (`git diff --name-only`), otherwise from the tree; extension → skill map:
`.go`→review-go, `.sh`/`.bash`/`bash` shebang→review-bash, `.vue`/`.ts`/`.tsx`→review-vue-ts,
`.php`→review-php; anything else → the general reviewer, stating that no language-specific pass
ran), `## Review procedure` (probe → detect → run tools → walk the checklist by hand → merge →
report), `## Report skeleton` (findings grouped by severity, then the `## Checks skipped` section
with tool, reason, install hint), `## Error handling` (the four design cases: no tools present;
tool exits non-zero: distinguish "found problems" from "crashed", a crash is a skipped check and
never a clean result; language undetected; empty diff or no findings: emit the report with an
explicit no-findings statement, still list skipped checks, emit no agent prompt block).

- [ ] **Step 5: Write `references/agent-prompt.md`**

The template exactly as the design shows it, plus the fill rules: anchor by content not line
number (`~` marks line numbers as hints; failure to match the anchor means `SKIPPED-STALE` by
definition); state intent and acceptance criteria, never a diff; every finding self-contained; the
mandatory status table with all three statuses kept distinct; the block carries **all severities**,
Critical through Low; validation commands are derived from the capability probe, so an absent
binary never appears; no block at all when there are no findings.

- [ ] **Step 6: Write `tests/fixtures/agent-prompt/sample-block.md`**

A filled block with three findings across three severities (reuse the design's `F1`
(`internal/auth/session.go`) example, add a `review-vue-ts` finding and a `review-bash` finding),
each with a real anchor snippet, followed by the validation command line and the status table.

- [ ] **Step 7: Run to verify pass**

Run: `python3 tests/validate.py`
Expected: `OK`.

---

### Task 3: `review-go` skill and Go fixtures

**Files:**
- Create: `skills/review-go/SKILL.md`
- Create: `tests/fixtures/go/vulnerable.go`, `tests/fixtures/go/clean.go`
- Modify: `tests/validate.py` (add `check_skill_frontmatter`, `check_tool_probes`,
  `check_checklist_coverage`)

**Interfaces:**
- Consumes: `read`, `fail`, `warn`, `SKILLS`, `CHECKS`.
- Produces: `frontmatter(text)` → `(dict, body)`; `ID_RE` matching `(GO|SH|VT|PHP|GEN|SEC)-\d\d`;
  `TOOLS` mapping skill name → required tool strings. Tasks 4–7 add rows to `TOOLS` and fixtures
  only; these three check functions are written once here and cover every later skill.

- [ ] **Step 1: Write the failing checks**

Append to `tests/validate.py`, add all three to `CHECKS`:

```python
ID_RE = re.compile(r"\b((?:GO|SH|VT|PHP|GEN|SEC)-\d\d)\b")

TOOLS = {
    "review-go": ["go vet", "staticcheck", "gosec", "govulncheck", "errcheck"],
    "review-bash": ["shellcheck", "shfmt"],
    "review-vue-ts": ["tsc --noEmit", "eslint", "bun audit", "knip"],
    "review-php": ["php -l", "phpstan", "composer audit"],
    "security-review": ["semgrep", "gitleaks", "trivy"],
}

FIXTURE_DIRS = {
    "review-go": "tests/fixtures/go",
    "review-bash": "tests/fixtures/bash",
    "review-vue-ts": "tests/fixtures/vue-ts",
    "review-php": "tests/fixtures/php",
    "code-review": "tests/fixtures/general",
    "security-review": "tests/fixtures/security",
}


def frontmatter(text):
    """Split YAML frontmatter from body. Only flat `key: value` pairs are supported."""
    if not text.startswith("---\n"):
        return None, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return None, text
    raw = text[4:end]
    data = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            data[key.strip()] = value.strip()
    data["__raw__"] = text[: end + 5]
    return data, text[end + 5:]


def check_skill_frontmatter():
    for name in SKILLS:
        rel = f"skills/{name}/SKILL.md"
        text = read(rel)
        if text is None:
            continue
        fm, body = frontmatter(text)
        if fm is None:
            fail(f"{rel}: no YAML frontmatter")
            continue
        keys = {k for k in fm if k != "__raw__"}
        if keys != {"name", "description"}:
            fail(f"{rel}: frontmatter keys must be exactly name+description, got {sorted(keys)}")
        if len(fm["__raw__"]) > 1024:
            fail(f"{rel}: frontmatter is {len(fm['__raw__'])} chars, limit 1024")
        if fm.get("name") != name:
            fail(f"{rel}: frontmatter name {fm.get('name')!r} != directory {name!r}")
        if not re.fullmatch(r"[A-Za-z0-9-]+", fm.get("name", "")):
            fail(f"{rel}: name may only contain letters, numbers, hyphens")
        desc = fm.get("description", "")
        if not desc.startswith("Use when"):
            fail(f"{rel}: description must start with 'Use when'")
        if len(desc) > 500:
            warn(f"{rel}: description is {len(desc)} chars (aim for <500)")
        for pronoun in (" I ", " I'", "we ", "you "):
            if pronoun in f" {desc.lower()} ":
                fail(f"{rel}: description must be third person (found {pronoun.strip()!r})")
        # every skill emits the shared artifacts, so every skill must link the machinery
        for ref in ("../../references/rubric.md", "../../references/procedure.md",
                    "../../references/agent-prompt.md"):
            if ref not in body:
                fail(f"{rel}: body does not reference {ref}")
        if "Checks skipped" not in body:
            fail(f"{rel}: body must require a 'Checks skipped' section")
        for ref in re.findall(r"\.\./\.\./([A-Za-z0-9_./-]+\.md)", body):
            if not (ROOT / ref).exists():
                fail(f"{rel}: dangling reference ../../{ref}")


def check_tool_probes():
    for name, tools in TOOLS.items():
        text = read(f"skills/{name}/SKILL.md")
        if text is None:
            continue
        for tool in tools:
            if tool not in text:
                fail(f"skills/{name}/SKILL.md: tool probe {tool!r} not listed")
        binary = tools[0].split()[0]
        if f"command -v {binary}" not in text:
            fail(f"skills/{name}/SKILL.md: no 'command -v {binary}' probe line")


def check_checklist_coverage():
    """Every checklist ID a skill declares must be planted in that skill's vulnerable fixtures,
    and every ID planted in a fixture must be declared by a skill. Silent gaps are a defect."""
    declared = {}
    for name in SKILLS:
        text = read(f"skills/{name}/SKILL.md")
        if text is None:
            continue
        ids = set(ID_RE.findall(text))
        if not ids:
            fail(f"skills/{name}/SKILL.md: declares no checklist IDs")
        declared[name] = ids

    for name, ids in declared.items():
        fixture_dir = ROOT / FIXTURE_DIRS[name]
        if not fixture_dir.is_dir():
            fail(f"missing fixture directory: {FIXTURE_DIRS[name]}")
            continue
        vulnerable, clean = {}, []
        for path in sorted(fixture_dir.iterdir()):
            if not path.is_file():
                continue
            body = path.read_text(encoding="utf-8")
            planted = set(re.findall(r"VULN:\s*((?:GO|SH|VT|PHP|GEN|SEC)-\d\d)", body))
            if path.name.startswith("vulnerable"):
                if not planted:
                    fail(f"{path.relative_to(ROOT)}: vulnerable fixture plants no 'VULN: <ID>'")
                vulnerable[path.name] = planted
            elif path.name.startswith("clean"):
                clean.append(path)
                if planted:
                    fail(f"{path.relative_to(ROOT)}: clean fixture must not plant VULN ids")
                if "CLEAN-FIXTURE" not in body:
                    fail(f"{path.relative_to(ROOT)}: clean fixture must be marked CLEAN-FIXTURE")
        if not clean:
            fail(f"{FIXTURE_DIRS[name]}: no clean fixture (false-positive check needs one)")
        covered = set().union(*vulnerable.values()) if vulnerable else set()
        for missing in sorted(ids - covered):
            fail(f"{name}: checklist {missing} has no fixture coverage")
        for stray in sorted(covered - ids):
            fail(f"{FIXTURE_DIRS[name]}: plants {stray}, which {name} does not declare")
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 tests/validate.py`
Expected: exit 1, `missing file: skills/code-review/SKILL.md` … through all six skills, plus
missing fixture directories.

- [ ] **Step 3: Write `skills/review-go/SKILL.md`**

Frontmatter:

```yaml
---
name: review-go
description: Use when reviewing or auditing Go code - .go files, a go.mod module, "review this Go service", "check this handler before I merge" - covering nil dereference after an error, unchecked type assertions, goroutine and context leaks, SQL built by string concatenation, defer inside loops, ignored errors, and data races.
---
```

Body sections: `## Overview` (one paragraph: guidance is the baseline, tools sharpen it) ·
`## Procedure` (numbered, five steps, pointing at `../../references/procedure.md`) ·
`## Capability probe` (a fenced block of `command -v go staticcheck gosec govulncheck errcheck`
style lines with the exact invocation for each present tool: `go vet ./...`, `staticcheck ./...`,
`gosec -quiet ./...`, `govulncheck ./...`, `errcheck ./...`, and the install hint for each absent
one) · `## Checklist` (a table: ID, what to look for, why it matters, fix direction; one row per
`GO-01`…`GO-07`, each row concrete enough to search for, e.g. `GO-02`: "a type assertion without
the two-value form: `v := x.(T)` where `x` can be another type; panics at runtime and takes the
process down; use `v, ok := x.(T)` and handle `!ok`") · `## Output` (both artifacts, per
`../../references/rubric.md` and `../../references/agent-prompt.md`; the validation command line
is derived from the probe: `go build ./... && go vet ./... && go test ./...` with absent tools
omitted) · `## Common mistakes` (reporting a `gosec` hit without checking reachability; calling a
missing tool a clean result).

- [ ] **Step 4: Write the Go fixtures**

`tests/fixtures/go/vulnerable.go`: package `fixture`, compiles under `gofmt -e`, one planted
defect per ID with a `// VULN: GO-0n` comment on the offending line:

| ID | Planted defect |
|---|---|
| GO-01 | `row, err := db.Query(...)`; log the error, then use `row` anyway. |
| GO-02 | `cfg := raw.(map[string]string)` on an `any` that may hold something else. |
| GO-03 | `go func() { <-ch }()` with nothing ever sending, and a `context.WithCancel` whose `cancel` is never called. |
| GO-04 | `db.Query("SELECT * FROM users WHERE name = '" + name + "'")`. |
| GO-05 | `for _, p := range paths { f, _ := os.Open(p); defer f.Close() }`. |
| GO-06 | `json.Unmarshal(b, &v)` with the error discarded via `_ =`. |
| GO-07 | a shared `map[string]int` written from two goroutines with no mutex. |

`tests/fixtures/go/clean.go`: the same seven situations written correctly (checked errors,
two-value assertion, `defer cancel()`, parameterised query, closure-scoped `defer`, handled
`Unmarshal` error, `sync.Mutex`-guarded map), header comment `// CLEAN-FIXTURE`.

- [ ] **Step 5: Run to verify Go checks pass**

Run: `python3 tests/validate.py 2>&1 | grep -E 'review-go|fixtures/go'`
Expected: no output (the remaining failures belong to the not-yet-written skills).
Run: `gofmt -e tests/fixtures/go/*.go >/dev/null && go vet ./tests/fixtures/go/ ; echo "vet exit $?"`
Expected: `gofmt` clean; `go vet` flags the vulnerable file: a non-zero exit here is the fixture
working, and `clean.go` must not be among the flagged lines.

---

### Task 4: `review-bash` skill and Bash fixtures

**Files:**
- Create: `skills/review-bash/SKILL.md`
- Create: `tests/fixtures/bash/vulnerable.sh`, `tests/fixtures/bash/clean.sh`

**Interfaces:**
- Consumes: `TOOLS["review-bash"]` and the three check functions from Task 3; no validator changes.
- Produces: nothing new.

- [ ] **Step 1: Confirm the checks already fail for this skill**

Run: `python3 tests/validate.py 2>&1 | grep -E 'review-bash|fixtures/bash'`
Expected: `missing file: skills/review-bash/SKILL.md` and `missing fixture directory`.

- [ ] **Step 2: Write `skills/review-bash/SKILL.md`**

Frontmatter:

```yaml
---
name: review-bash
description: Use when reviewing or auditing shell scripts - .sh or .bash files, a bash/sh shebang, "review this script", "is this deploy script safe" - covering unquoted expansions and word splitting, missing set -euo pipefail, eval, unsafe temp files, PATH assumptions, unvalidated positional parameters, and command substitution in arithmetic contexts.
---
```

Same section order as `review-go`. Probe block: `command -v shellcheck`, `command -v shfmt`;
invocations `shellcheck -S style <files>` and `shfmt -d <files>`; install hints
(`apt install shellcheck` / `go install mvdan.cc/sh/v3/cmd/shfmt@latest`). Checklist rows
`SH-01`…`SH-07` per the registry. Validation line derived from the probe, `bash -n <files>` as the
always-available floor since `bash` is the interpreter under review.

- [ ] **Step 3: Write the Bash fixtures**

`tests/fixtures/bash/vulnerable.sh`:

| ID | Planted defect |
|---|---|
| SH-01 | `rm -rf $DEST/$NAME` unquoted. |
| SH-02 | shebang with no `set -euo pipefail` at all. |
| SH-03 | `eval "$USER_CMD"`. |
| SH-04 | `TMP=/tmp/build.$$` then writing to it. |
| SH-05 | bare `curl`/`tar` calls with `PATH` assumed, plus `PATH=$PATH:.`. |
| SH-06 | `$1` used as a path with no arity or content check. |
| SH-07 | `if (( $(cat count.txt) > 10 ))`: unvalidated substitution inside `(( ))`. |

`tests/fixtures/bash/clean.sh`: `#!/usr/bin/env bash`, `set -euo pipefail`, quoted expansions,
`mktemp` with an EXIT trap, absolute or `command -v`-resolved binaries, `[[ $# -eq 1 ]]` guard,
integer-validated arithmetic, no `eval`; header comment `# CLEAN-FIXTURE`.

- [ ] **Step 4: Run to verify pass**

Run: `python3 tests/validate.py 2>&1 | grep -E 'review-bash|fixtures/bash' ; bash -n tests/fixtures/bash/clean.sh && echo "clean.sh parses"`
Expected: no grep output; `clean.sh parses`.

---

### Task 5: `review-vue-ts` skill and Vue/TS fixtures

**Files:**
- Create: `skills/review-vue-ts/SKILL.md`
- Create: `tests/fixtures/vue-ts/vulnerable.vue`, `tests/fixtures/vue-ts/vulnerable.ts`,
  `tests/fixtures/vue-ts/clean.vue`, `tests/fixtures/vue-ts/clean.ts`

**Interfaces:**
- Consumes: Task 3's check functions and `TOOLS["review-vue-ts"]`.
- Produces: nothing new. Note the coverage check unions all `vulnerable*` files in the directory,
  so splitting `VT-nn` across the `.vue` and `.ts` fixtures is fine.

- [ ] **Step 1: Confirm the checks fail for this skill**

Run: `python3 tests/validate.py 2>&1 | grep -E 'review-vue-ts|fixtures/vue-ts'`
Expected: missing SKILL.md and missing fixture directory.

- [ ] **Step 2: Write `skills/review-vue-ts/SKILL.md`**

Frontmatter:

```yaml
---
name: review-vue-ts
description: Use when reviewing or auditing Vue or TypeScript front-end code - .vue, .ts or .tsx files, "review this component", "audit this front end" - covering v-html and innerHTML XSS sinks, missing CSRF handling on fetch, secrets shipped in the client bundle, unvalidated props crossing trust boundaries, prototype pollution, and any masking type errors.
---
```

Probe block: `command -v tsc` / `bunx tsc --noEmit`, `command -v eslint`, `command -v bun` →
`bun audit`, `command -v knip`. Per the user's global preference, prefer `bun`/`bunx` over
`npm`/`npx` in every hint. Checklist rows `VT-01`…`VT-07`.

- [ ] **Step 3: Write the Vue/TS fixtures**

`vulnerable.vue`: `VT-01` `<div v-html="userBio">`; `VT-05` a `defineProps<{ html: string }>()`
whose value flows straight into that sink; `VT-04` an inlined `const API_KEY = "sk_live_..."`.
`vulnerable.ts`: `VT-02` `el.innerHTML = query`; `VT-03` a state-changing `fetch('/api/transfer',
{ method: 'POST' })` with no CSRF token and `credentials: 'include'`; `VT-06`
`function merge(t: any, s: any)` assigning `t[k] = s[k]` over `__proto__`; `VT-07` a function typed
`(r: any) => r.data.items` hiding a shape error.
`clean.vue` / `clean.ts`: interpolation instead of `v-html`, `textContent`, a CSRF header read
from a meta tag, key from `import.meta.env` server-side proxy note, typed props with a validator,
`Object.hasOwn` + prototype-key rejection in the merge, a discriminated-union response type. Both
carry a `CLEAN-FIXTURE` comment.

- [ ] **Step 4: Run to verify pass**

Run: `python3 tests/validate.py 2>&1 | grep -E 'review-vue-ts|fixtures/vue-ts'`
Expected: no output.

---

### Task 6: `review-php` skill and PHP fixtures

**Files:**
- Create: `skills/review-php/SKILL.md`
- Create: `tests/fixtures/php/vulnerable.php`, `tests/fixtures/php/clean.php`

**Interfaces:**
- Consumes: Task 3's check functions and `TOOLS["review-php"]`.
- Produces: nothing new.

- [ ] **Step 1: Confirm the checks fail for this skill**

Run: `python3 tests/validate.py 2>&1 | grep -E 'review-php|fixtures/php'`
Expected: missing SKILL.md and missing fixture directory.

- [ ] **Step 2: Write `skills/review-php/SKILL.md`**

Frontmatter:

```yaml
---
name: review-php
description: Use when reviewing or auditing PHP code - .php files, a composer.json project, "review this PHP app", "audit this endpoint" - covering superglobal data flow into sinks, unserialize on untrusted input, local and remote file inclusion, weak session configuration, SQL built by concatenation, and missing output escaping.
---
```

Probe block: `command -v php` → `php -l <files>`, `command -v phpstan` → `phpstan analyse`,
`command -v composer` → `composer audit`. Checklist rows `PHP-01`…`PHP-06`.

- [ ] **Step 3: Write the PHP fixtures**

`vulnerable.php`: `PHP-01` `$_GET['id']` reaching a query and a shell call unvalidated; `PHP-02`
`unserialize($_COOKIE['prefs'])`; `PHP-03` `include $_GET['page'] . '.php'`; `PHP-04`
`session_start()` with `session.cookie_httponly = 0` / no `cookie_secure` / no
`session_regenerate_id`; `PHP-05` `"SELECT … WHERE email = '" . $_POST['email'] . "'"`; `PHP-06`
`echo $row['name']` with no escaping.
`clean.php`: prepared statements with bound parameters, `json_decode` instead of `unserialize`,
an allow-list for the include target, hardened session cookie params plus
`session_regenerate_id(true)`, `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` on output;
`// CLEAN-FIXTURE` header. Must pass `php -l`.

- [ ] **Step 4: Run to verify pass**

Run: `python3 tests/validate.py 2>&1 | grep -E 'review-php|fixtures/php' ; php -l tests/fixtures/php/clean.php && php -l tests/fixtures/php/vulnerable.php`
Expected: no grep output; both files report "No syntax errors detected": the fixtures are
vulnerable, not broken.

---

### Task 7: Entry-point skills, delegation, and trigger distinctness

**Files:**
- Create: `skills/code-review/SKILL.md`, `skills/security-review/SKILL.md`
- Create: `tests/fixtures/general/vulnerable.py`, `tests/fixtures/general/clean.py`
- Create: `tests/fixtures/security/vulnerable.py`, `tests/fixtures/security/clean.py`
- Modify: `tests/validate.py` (add `check_delegation`, `check_trigger_distinctness`)

**Interfaces:**
- Consumes: everything from Tasks 1–3.
- Produces: the delegation contract. Each entry point names all four language skills by bare name
  and links `../../references/procedure.md` for detection.

- [ ] **Step 1: Write the failing checks**

Append to `tests/validate.py`, add both to `CHECKS`:

```python
LANGUAGE_SKILLS = ["review-go", "review-bash", "review-vue-ts", "review-php"]
LANGUAGE_TOKENS = {
    "review-go": [r"\bGo\b", r"\.go\b"],
    "review-bash": [r"\bshell\b", r"\.sh\b"],
    "review-vue-ts": [r"\bVue\b", r"\bTypeScript\b"],
    "review-php": [r"\bPHP\b"],
}


def check_delegation():
    for name in ("code-review", "security-review"):
        text = read(f"skills/{name}/SKILL.md")
        if text is None:
            continue
        _, body = frontmatter(text)
        for target in LANGUAGE_SKILLS:
            if target not in body:
                fail(f"skills/{name}/SKILL.md: does not delegate to {target}")
        if "@skills/" in body or "@references/" in body:
            fail(f"skills/{name}/SKILL.md: uses an @ path link (force-loads context)")
        if "merge" not in body.lower():
            fail(f"skills/{name}/SKILL.md: does not say how multi-language findings merge")


def check_trigger_distinctness():
    """Entry points match intent; language skills match language + intent. Descriptions must not
    contend."""
    descs = {}
    for name in SKILLS:
        text = read(f"skills/{name}/SKILL.md")
        if text is None:
            continue
        fm, _ = frontmatter(text)
        if fm:
            descs[name] = fm.get("description", "")

    for name, patterns in LANGUAGE_TOKENS.items():
        desc = descs.get(name, "")
        if not any(re.search(p, desc) for p in patterns):
            fail(f"{name}: description names no language token, so it cannot win on language")
        for entry in ("code-review", "security-review"):
            for pattern in patterns:
                if re.search(pattern, descs.get(entry, "")):
                    fail(f"{entry}: description contains language token {pattern!r} "
                         f"(contends with {name})")

    if not re.search(r"secur|vuln|audit|exploit", descs.get("security-review", ""), re.I):
        fail("security-review: description carries no security intent words")
    if re.search(r"\bvuln|\bexploit", descs.get("code-review", ""), re.I):
        fail("code-review: description carries security intent words "
             "(contends with security-review)")
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 tests/validate.py`
Expected: exit 1, `missing file: skills/code-review/SKILL.md`, `missing file:
skills/security-review/SKILL.md`, missing general/security fixture directories.

- [ ] **Step 3: Write `skills/code-review/SKILL.md`**

Frontmatter:

```yaml
---
name: code-review
description: Use when the user asks for a review of code they have written or changed - "review this", "look over this PR", "before I merge", "any bugs in this", "is this ready to ship" - covering correctness, error handling, resource lifetime, API contracts, maintainability, and test gaps.
---
```

Body: `## Overview` · `## Procedure` (probe, detect languages per
`../../references/procedure.md`, delegate to `review-go` / `review-bash` / `review-vue-ts` /
`review-php` for every language present, run the general checklist on everything else, then merge
all findings into one list under `../../references/rubric.md`) · `## Delegation` (multiple
languages → every matching skill runs; findings merge and `Fn` IDs are renumbered across the
merged list, checklist IDs preserved; no language detected → the general checklist runs and the
report states that no language-specific pass ran) · `## General checklist` (`GEN-01`…`GEN-07`) ·
`## Output` · `## Common mistakes`.

- [ ] **Step 4: Write `skills/security-review/SKILL.md`**

Frontmatter:

```yaml
---
name: security-review
description: Use when the user asks whether code is safe or wants it audited for security - "security review", "audit this", "check for vulns", "is this exploitable", "any injection risk" - covering authentication, authorisation, injection, secret handling, crypto, deserialisation, SSRF, and sensitive data exposure.
---
```

Body mirrors `code-review`, with: the `semgrep` / `gitleaks` / `trivy` probe block (invocations
`semgrep --config auto --error`, `gitleaks detect --no-banner`, `trivy fs --scanners vuln,secret .`
plus install hints); the `SEC-01`…`SEC-07` checklist; delegation to the four language skills
instructing them to weight their security-relevant checklist rows (`GO-04`, `SH-01`/`SH-03`,
`VT-01`…`VT-04`/`VT-06`, `PHP-01`…`PHP-06`); a `## Severity calibration` note that exploitability
by an untrusted actor drives severity, not code ugliness.

- [ ] **Step 5: Write the general and security fixtures**

`tests/fixtures/general/vulnerable.py`: Python, so it also exercises the design's
"non-supported language falls back to the general reviewer" path. One planted defect per
`GEN-01`…`GEN-07`: an off-by-one slice; `except Exception: pass`; a file opened without a context
manager on an early-return path; a module-level mutable cache mutated from a thread; a function
documented as returning a list that returns `None` on one branch; a duplicated fee calculation that
disagrees with its twin; an untested boundary branch marked `VULN: GEN-07`.
`tests/fixtures/security/vulnerable.py`, one planted defect per `SEC-01`…`SEC-07`: an endpoint
with the auth decorator commented out; an object fetched by ID with no owner check;
`os.system("ping " + host)`; a hardcoded `AWS_SECRET`; `hashlib.md5` for passwords plus
`random.random()` for a token; `pickle.loads(request.data)` and a `requests.get(user_url)` SSRF;
a traceback and full user record returned in an error response.
Clean counterparts for both, each `CLEAN-FIXTURE`, each passing `python3 -m py_compile`.

- [ ] **Step 6: Run to verify pass**

Run: `python3 tests/validate.py`
Expected: `OK` (all check groups pass, all six skills and all six fixture directories present).

---

### Task 8: Manual test protocol, README, and end-to-end self-review

**Files:**
- Create: `tests/README.md`, `README.md`
- Modify: `tests/run.sh` (add the Python compile checks for the new fixtures)

**Interfaces:**
- Consumes: everything.
- Produces: the documented manual protocol covering the design's success criteria 1, 2, 3 and 5.

- [ ] **Step 1: Write `tests/README.md`**

Two sections. `## Automated`: what `validate.py` proves (design criterion 4 fully; criterion 1's
coverage precondition: every checklist ID has a fixture; structural invariants) and the one-line
command to run it. `## Manual`: a numbered protocol for what a script cannot judge, one entry per
remaining criterion, each with the exact prompt to issue, the fixture to point it at, and the pass
condition:

1. **Severity accuracy (criterion 1):** for each language, invoke the skill against
   `vulnerable.*`; pass = every `VULN:` ID is reported, Critical/High assignments match the
   fixture's annotation, no ID silently absent.
2. **False positives (criterion 2):** invoke against `clean.*`; pass = zero Critical and zero High
   findings.
3. **Trigger behaviour (criterion 3):** issue each skill's intended phrasing in a fresh session
   and confirm the intended skill loads and the others do not: the phrasing list lives here, one
   row per skill, plus two cross-checks ("review this Go service" must not load
   `security-review`; "audit this for vulns" must not load `code-review` alone).
4. **Tools absent (criterion 5):** run with the linters uninstalled; pass = the review completes
   and every absent tool appears in "Checks skipped" with a reason and an install hint.

State plainly that steps 1–4 require a live agent session and are not covered by `validate.py`.

- [ ] **Step 2: Write the root `README.md`**

Install commands from the design, a table of the six skills and their triggers, the dual-output
explanation, the tool probe table, and a **Name collision** note: Claude Code ships a built-in
`/security-review` command, so invoke this one as `claude-review-suite:security-review` when both
are present.

- [ ] **Step 3: Extend `tests/run.sh`**

Add `python3 -m py_compile` over `tests/fixtures/general/*.py` and `tests/fixtures/security/*.py`,
and `node --check` over `tests/fixtures/vue-ts/*.ts` only if `node` is present (skip `.vue`, which
`node` cannot parse), again reporting absent tools as skipped, not failed.

- [ ] **Step 4: Run the full suite**

Run: `bash tests/run.sh`
Expected: validator `OK`; every fixture that a present tool can check passes its syntax check;
absent tools listed as skipped.

- [ ] **Step 5: End-to-end self-review (dogfood)**

Follow `skills/review-go/SKILL.md` by hand against `tests/fixtures/go/vulnerable.go`. Produce the
full report and agent prompt block into a scratch file, then check it against the automated
parser:

Run: `python3 -c "import sys; sys.path.insert(0,'tests'); import validate; print(len(validate.parse_block(open('/tmp/selfreview.md').read())))"`
Expected: the finding count equals the number of `VULN:` IDs in the fixture, every entry parses
with an anchor, and the "Checks skipped" section lists the absent Go tools. Fix any skill wording
that made this awkward, then re-run `python3 tests/validate.py`.

- [ ] **Step 6: Final verification**

Run: `bash tests/run.sh && python3 tests/validate.py`
Expected: `OK`. Report to the user which of the design's five success criteria are automated and
which remain manual, with no claim of having run the manual ones.

---

## Self-Review

**Spec coverage.** Package layout → Task 1 (manifests) + Tasks 2–7 (files) · entry-point skills →
Task 7 · language skills → Tasks 3–6 · trigger contention → Task 7 `check_trigger_distinctness` ·
hybrid tooling model and probe table → Task 3 `check_tool_probes`, one probe block per skill ·
review checklists → the ID registry, enforced by `check_checklist_coverage` · shared rubric →
Task 2 · dual output → Task 2 (`agent-prompt.md`) + each skill's `## Output` section · the four
re-verification rules → Task 2 Step 5, with rules 1 and 4 machine-checked by
`check_agent_prompt_parses` · validation commands derived from the probe → each skill's `## Output`
· error handling, all four cases → Task 2 `references/procedure.md`, asserted by
`check_references` · testing, criterion 4 → automated in Task 2; criteria 1, 2, 3, 5 → documented
protocol in Task 8, honestly labelled manual.

**Placeholder scan.** No TBDs. Every checklist ID has a named planted defect. Every validator
function is written out in full. Skill bodies are specified by section with the exact frontmatter
verbatim and concrete row content, which is the level at which prose must be authored rather than
copied.

**Type consistency.** `fail`/`warn`/`read`/`load_json`/`frontmatter`/`parse_block`/`ROOT`/`SKILLS`/
`CHECKS` are defined in Tasks 1–3 and used with those exact names later. `TOOLS`, `FIXTURE_DIRS`,
`ID_RE`, `LANGUAGE_SKILLS` and `LANGUAGE_TOKENS` are keyed by skill directory name throughout.
`FIXTURE_DIRS` covers all six entries in `SKILLS`, so `check_checklist_coverage` cannot
`KeyError`. Severity, confidence and status vocabularies come from the three module-level lists,
so the rubric, the template, the sample block and the parser cannot drift apart.
