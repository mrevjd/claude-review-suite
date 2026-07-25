# Shared Review Procedure

The procedure every skill in this suite follows. Guidance is the baseline; tools sharpen it when
they are installed. **A gap the reader cannot see is a defect** — every check that did not run gets
named in the report.

## Capability probe

Probe before reviewing, not while reviewing. Never invoke a binary you have not probed.

```bash
for tool in <tool> <tool> <tool>; do
  printf '%-14s ' "$tool"
  command -v "$tool" >/dev/null 2>&1 && echo present || echo absent
done
```

Record the result up front and use it twice: it decides which tools run, and it decides which
validation commands may appear in the agent prompt block. The block must never instruct a
downstream agent to run a binary this machine does not have.

Absent tools go straight into the report's `## Checks skipped` section with a reason and an install
hint. Do not silently omit them, and do not treat "no tool output" as "no problems".

**Never install anything.** The suite ships `review-tools.sh`, which probes and installs the whole
toolchain in one pass (`./review-tools.sh probe`, `./review-tools.sh install`). When something is
missing, **name that script in `## Checks skipped` and leave running it to the user.** A review
reports; installing binaries, writing outside the repository, and invoking sudo are the user's
decisions, not the review's — and a review that quietly changes the machine it is inspecting is no
longer a review.

## Language detection

Detect scope first, then language.

**Scope.** If the user named files or a diff, that is the scope. Otherwise prefer the working diff:

```bash
git diff --name-only HEAD          # uncommitted work
git diff --name-only <base>...HEAD # a branch or PR
```

Fall back to the tree only when there is no diff, or when the user asked for a whole-project
review. Say which scope you used in the report — a reader who thinks you reviewed the tree when you
reviewed three files draws the wrong conclusion from a clean result.

**Language.** Map every file in scope:

| Pattern | Skill |
|---|---|
| `*.go`, `go.mod`, `go.sum` | `review-go` |
| `*.sh`, `*.bash`, `*.bats`, extensionless with a `#!/…sh`/`#!/…bash` shebang | `review-bash` |
| `*.vue`, `*.ts`, `*.tsx`, `*.mts`, `*.cts` | `review-vue-ts` |
| `*.php`, `composer.json` | `review-php` |
| anything else (`*.py`, `*.pl`, `*.rb`, `*.sql`, Dockerfiles, YAML, …) | no language pass; the general checklist in `code-review`, or the threat checklist in `security-review`, handles it |

Every language present gets its pass. Two languages in scope means two passes, then one merged
list per `rubric.md`.

## Review procedure

1. **Probe.** Run the capability probe for this skill's tool list. Record present/absent.
2. **Scope and detect.** Establish the file set, map it to languages, and state both in the report.
3. **Run what exists.** Run each present tool with the invocation this skill specifies. Read the
   output; do not paste it. Tool hits become findings only after you look at the code they point
   at.
4. **Walk the checklist by hand.** Every row, against every file in scope. This is the part that
   does not depend on tooling, and it is the part that finds what the linters cannot: missing
   authorisation, wrong trust boundary, a guard that exists but is bypassable. Tool output is not a
   substitute for the checklist walk.
5. **Score and merge.** Assign severity and confidence per `rubric.md`. Merge multi-language
   results into one list and renumber.
6. **Emit both artifacts.** The human report below, then the agent prompt block per
   `agent-prompt.md` — unless there are no findings, in which case no block is emitted.

## Report skeleton

```markdown
# <Code|Security> review: <scope>

**Scope:** 7 files from `git diff --name-only main...HEAD` (Go, Vue/TS)
**Passes run:** review-go, review-vue-ts
**Tools run:** go vet, errcheck
**Verdict:** 2 Critical, 1 High, 3 Medium, 1 Low

## Critical

[F1] Critical · Confirmed · internal/auth/session.go:112-118 · GO-01
  What:   ...
  Why:    ...
  Fix:    ...

## High
...

## Medium
...

## Low
...

## Checks skipped

| Check | Reason | Install |
|---|---|---|
| staticcheck | not installed | `go install honnef.co/go/tools/cmd/staticcheck@latest` |
| gosec | crashed: `panic: load: no packages` (exit 2) | already installed; see note below |
| bun audit | no `bun.lock` in scope | n/a |

<agent prompt block per agent-prompt.md, only when there is at least one finding>
```

Findings are grouped by severity, worst first. A severity with no findings is omitted; do not print
empty headings.

## Error handling

Four cases, all of which must show up in the report rather than in silence.

**No tools present.** The review proceeds on the checklist alone. This is a supported mode, not a
failure. Every probe miss is listed in `## Checks skipped`, and the report says plainly that the
findings rest on manual inspection only. Point the reader at `review-tools.sh install` once, in that
table — do not stop and ask whether to install, and do not run it.

**Tool exits non-zero.** Distinguish the two meanings, because they are opposites:

- *The tool found problems.* Normal. `go vet`, `shellcheck`, `semgrep` and friends all exit
  non-zero when they have something to say. Read the output and turn it into findings.
- *The tool crashed.* A panic, a usage error, a missing config, a build failure that stopped
  analysis, exit 127, exit 2 with no diagnostics. **A crash is a skipped check.** It goes in
  `## Checks skipped` with the exit code and the first line of the error. Never report a crashed
  tool as a clean result — "gosec found nothing" and "gosec did not run" are different claims, and
  conflating them is the most dangerous thing this suite can do.

Tell them apart by whether the output contains parseable diagnostics. If in doubt, treat it as a
crash and say why you were unsure.

**Language undetected.** No file in scope maps to a language skill. The general reviewer handles
the files, and the report states explicitly that no language-specific pass ran and which files that
affected. Do not skip the files.

**Empty diff or no findings.** Emit the report anyway, with an explicit statement — "no findings"
or "no changes in scope" — and still list `## Checks skipped`. A clean report whose skipped-checks
table is five rows long tells the reader something a bare "looks good" hides. **Emit no agent
prompt block:** a block with zero findings invites a downstream agent to invent work.
