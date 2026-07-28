# Code & Security Review Skill Suite: Design

**Date:** 2026-07-25
**Status:** Approved design, pending implementation plan

## Purpose

A suite of Claude Agent Skills that review code for correctness and security,
emit a human-readable report, and emit a machine-consumable prompt block that a
downstream coding agent can act on, with mandatory re-verification so stale
findings are never blindly applied.

## Scope

**In scope:** review and reporting for Go, Bash, Vue/TypeScript, PHP, plus
language-agnostic general and security review.

**Out of scope (deliberate):**
- Auto-fixing. The suite reports; the human or a separate agent applies changes.
- CI or git-hook wiring. Separable concern, bolt on later.
- Languages outside the four above: Perl and Python fall back to the general
  reviewer, which handles them without language-specific depth.

## Package Layout

Distributed as a single Claude Code plugin so it versions and installs with one
command on any machine.

```
claude-review-suite/
├── .claude-plugin/
│   └── plugin.json
├── references/
│   ├── rubric.md            # severity, confidence, finding format
│   └── agent-prompt.md      # agent prompt block template + fill rules
└── skills/
    ├── code-review/SKILL.md
    ├── security-review/SKILL.md
    ├── review-go/SKILL.md
    ├── review-bash/SKILL.md
    ├── review-vue-ts/SKILL.md
    └── review-php/SKILL.md
```

Install:

```
/plugin marketplace add <user-repo>
/plugin install claude-review-suite@<marketplace-name>
```

## Components

### Entry-point skills

`code-review`: general correctness and maintainability. Triggers on review
intent ("review this", "before I merge", "look over this PR").

`security-review`: threat-oriented, language-agnostic. Triggers on security
intent ("audit", "is this safe", "security review", "check for vulns").

Both detect languages present in the diff or tree and delegate to the matching
language skill(s). When multiple languages are present, each language skill runs
and findings merge into one list under the shared rubric.

### Language skills

`review-go`, `review-bash`, `review-vue-ts`, `review-php`. Each is invokable
standalone ("review this Go service") as well as via delegation.

Trigger descriptions are written so entry-point skills match intent words and
language skills match language + intent, avoiding trigger contention.

## Hybrid Tooling Model

Guidance is the baseline; tools sharpen it when present. Each skill begins with
a capability probe, runs what exists, and explicitly states which checks were
skipped and why. Silent gaps are a defect.

| Skill | Tools probed |
|---|---|
| review-go | `go vet`, `staticcheck`, `gosec`, `govulncheck`, `errcheck` |
| review-bash | `shellcheck`, `shfmt` |
| review-vue-ts | `tsc --noEmit`, `eslint`, `bun audit`, `knip` |
| review-php | `php -l`, `phpstan`, `composer audit` |
| security-review | `semgrep`, `gitleaks`, `trivy` |

Probe pattern: `command -v <tool>` per binary. Absent tools are recorded in a
"checks skipped" section of the report with the reason and the install hint.

## Review Checklists

Each language skill carries a concrete checklist. Generic instruction ("look for
bugs") is explicitly insufficient.

**Go:** nil dereference after error, unchecked type assertions, goroutine and
`context` leaks, string-built `database/sql` queries, `defer` inside loops,
ignored errors, data races on shared state.

**Bash:** unquoted expansion and word splitting, missing `set -euo pipefail`,
`eval`, unsafe temp file creation, PATH assumptions, unvalidated positional
parameters, command substitution in arithmetic contexts.

**Vue/TS:** `v-html` sinks, `innerHTML` assignment, missing CSRF handling on
`fetch` calls, secrets present in the client bundle, unvalidated props crossing
trust boundaries, prototype pollution, `any` masking type errors.

**PHP:** superglobal data flow, `unserialize` on untrusted input, LFI/RFI,
weak session configuration, SQL built by concatenation, missing output escaping.

## Shared Rubric (`references/rubric.md`)

All six skills reference this so findings merge coherently.

**Severity:** Critical, High, Medium, Low.

**Confidence:** Confirmed, Likely, Speculative. Exists so uncertain findings have
a home, neither silently dropped nor overstated.

**Finding format:** stable ID, severity, confidence, `file:line`, what is wrong,
why it matters, concrete fix direction.

## Dual Output

Every review emits two artifacts.

### 1. Human report

Findings grouped by severity, followed by the "checks skipped" section.

### 2. Agent prompt block

A fenced, copy-pasteable block appended to the report, containing **all
severities**, Critical through Low. Template lives in
`references/agent-prompt.md`.

```
Verify each finding against current code. Fix only still-valid issues, skip
the rest with a brief reason, keep changes minimal, and validate.

[F1] Critical · @internal/auth/session.go, ~L112-118
  Anchor: `if err == nil { return tok, nil }`
  Issue:  Token returned before signature verification completes.
  Expect: Verification runs and errors propagate before any return path
          yields a token.

[F2] Medium · @web/src/components/Feed.vue, ~L44
  ...

After fixing, run: go vet ./... && staticcheck ./... && go test ./...
Report a table: ID | FIXED | SKIPPED-STALE | SKIPPED-DISAGREE | reason.
```

### Rules that make re-verification real

1. **Anchor by content, not line number.** Every finding carries a short literal
   snippet from the cited location. The receiving agent relocates the code by
   matching that snippet. Failure to match means the finding is `SKIPPED-STALE`
   by definition. The `~` prefix on line numbers marks them as hints.

2. **State intent and acceptance criteria, never a diff.** A patch in the block
   gets pasted without thought, defeating verification. Describing the required
   end state forces the agent to read current code.

3. **Findings are self-contained.** The receiving agent has none of the review
   context, so each entry restates enough of the "why" to be judged alone.

4. **Mandatory status table.** Every finding ID must return a verdict. Silence is
   how findings get dropped. `SKIPPED-STALE` (code moved) and `SKIPPED-DISAGREE`
   (agent judged the finding wrong) stay distinct: the latter is a signal about
   review quality, and collapsing them loses it.

Validation commands in the block are derived from the same capability probe the
review used, so the block never instructs the agent to run an absent binary.

## Error Handling

- **No tools present:** review proceeds on guidance alone; every probe failure is
  listed in "checks skipped".
- **Tool exits non-zero:** distinguish "tool found problems" from "tool crashed".
  A crash is reported as a skipped check, not as a clean result.
- **Language undetected:** general reviewer handles the file and states that no
  language-specific pass ran.
- **Empty diff or no findings:** emit the report with an explicit "no findings"
  statement and still list skipped checks. No agent prompt block is emitted.

## Testing

Per-skill fixture files carrying known-vulnerable and known-clean code. Success
criteria:

1. Known vulnerabilities in fixtures are found at correct severity.
2. Clean fixtures produce no Critical or High findings (false-positive check).
3. Skills trigger on their intended phrasings and not on each other's.
4. Agent prompt block parses and every finding carries a usable anchor.
5. With tools uninstalled, review still completes and reports skipped checks.

## Open Items

None. Design approved 2026-07-25.
