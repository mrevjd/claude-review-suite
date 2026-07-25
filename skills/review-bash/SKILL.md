---
name: review-bash
description: Use when reviewing or auditing shell scripts - .sh or .bash files, a file with a bash or sh shebang, "review this script", "is this deploy script safe", "audit this cron job" - covering unquoted expansions and word splitting, missing set -euo pipefail, eval, unsafe temp file creation, PATH assumptions, unvalidated positional parameters, and command substitution in arithmetic contexts.
---

# Review Bash

Correctness and security review for shell. Shell fails quietly and destructively: the same script
works for months and then deletes the wrong directory the first time a variable is empty. The
checklist runs whether or not `shellcheck` is installed.

## Procedure

Follow `../../references/procedure.md`. Probe, scope, run what exists, walk the checklist by hand,
score per `../../references/rubric.md`, emit both artifacts.

## Capability probe

```bash
command -v shellcheck
command -v shfmt
```

| Tool | Invocation | If absent |
|---|---|---|
| `shellcheck` | `shellcheck -S style <files>` | `apt install shellcheck` / `brew install shellcheck` |
| `shfmt` | `shfmt -d <files>`, with `-i <n>` set to the project's indent width | `go install mvdan.cc/sh/v3/cmd/shfmt@latest` |

Several missing at once? The suite ships `review-tools.sh`, which probes and installs the whole
toolchain in one pass. **Name it in `## Checks skipped` and leave running it to the user** — a review
reports, it does not install.

`bash -n <file>` is the always-available floor — `bash` is the interpreter under review, so it is
present by definition. It only catches syntax errors, so it is a floor and not a substitute.

`shellcheck` exits non-zero when it finds problems; that is a result. Exit 127, or a complaint about
an unsupported shebang, is a crash and belongs in `## Checks skipped`.

## Checklist

| ID | Look for | Why it matters | Fix direction |
|---|---|---|---|
| **SH-01** | Any `$VAR` or `$(cmd)` outside double quotes, especially as an argument to `rm`, `cp`, `mv`, `test`, or a loop over `$(ls)`. | The value is word-split and glob-expanded. An empty value vanishes, turning `rm -rf "$DIR/$SUB"` into `rm -rf /`; a value with a space becomes two arguments. This is the single most destructive shell defect. | Quote every expansion: `"$VAR"`, `"$(cmd)"`, `"${arr[@]}"`. Deliberate splitting is done with an explicit array, not by leaving quotes off. |
| **SH-02** | No `set -euo pipefail` (or equivalent) near the top; or `set -e` alone with pipelines whose failures matter. | Without `-e` the script marches past failures; without `-u` a typo'd variable silently expands to empty; without `-o pipefail` a failing producer in a pipe reports success. Errors get promoted into corrupted state. | `set -euo pipefail` immediately after the shebang. Where a command is allowed to fail, mark that one site explicitly with `|| true` or an `if`. |
| **SH-03** | `eval`, `bash -c "$var"`, `source "$user_input"`, or a command assembled into a string and then run. | The value becomes code. Any injected `;` or `$(...)` runs with the script's privileges, which for a deploy or cron script is usually root. | Use arrays for dynamic argument lists (`cmd=(rsync -a); "${cmd[@]}"`). Where a caller must select behaviour, dispatch through a `case` over a fixed allow-list. |
| **SH-04** | `/tmp/name.$$`, `/tmp/$RANDOM`, a fixed `/tmp` path, or `mktemp` whose result is never cleaned up. | PIDs and fixed names are predictable, so a local attacker can pre-create the path as a symlink and redirect the write. An uncleaned temp dir leaks contents that were meant to be transient. | `tmp="$(mktemp -d)"` plus `trap 'rm -rf "$tmp"' EXIT`. Never construct a temp path by hand. |
| **SH-05** | Bare command names in a script run by cron, systemd, or sudo; `PATH` assembled with a relative entry or a trailing/leading `:`; `PATH=$PATH:.`. | A writable or attacker-controlled directory earlier in `PATH` substitutes a different binary. An empty `PATH` element means the current directory. Cron's `PATH` is not the shell's, so bare names also just break. | Set an explicit `PATH` at the top, or resolve binaries once with `command -v` and fail loudly if absent. Never put `.` or an empty element in `PATH`. |
| **SH-06** | `$1`, `$2`, `$@` used without an arity check; no `${1:?message}`; no validation of a positional that becomes a path, a host, or a command argument. | An absent argument expands to empty and the script operates on the wrong target — the classic `rm -rf "$1"/` disaster. A `../` in an unvalidated path argument escapes the intended directory. | Check `$#` and fail with usage, or use `${1:?usage: ...}`. Validate the content, not just the presence, when it becomes a path or hostname. |
| **SH-07** | `$(...)`, `${VAR}`, or unvalidated input inside `(( ))`, `$(( ))`, or `let`. | Arithmetic contexts evaluate their contents, so a value like `x[$(id)]` or `1,y=$(rm -rf /)` executes. It is command injection through a construct that looks like maths. | Validate the value matches `^-?[0-9]+$` before it reaches an arithmetic context, or use `case`/`[[ ... =~ ]]` on the string instead of arithmetic. |

Beyond the checklist, also weigh: `trap` missing for a script that creates state, `cd` without
`|| exit`, `read` without `-r`, `[ ]` where `[[ ]]` is needed for a possibly-empty operand, and
writes to a path derived from a variable that was never confirmed non-empty.

## Output

Both artifacts, always:

1. **Human report** per the skeleton in `../../references/procedure.md`, ending in a
   `## Checks skipped` table with reason and install hint for every tool that did not run.
2. **Agent prompt block** per `../../references/agent-prompt.md`, all severities, omitted entirely
   when there are no findings.

Derive the block's validation line from the probe. With everything present:
`shellcheck -S style <files> && shfmt -d <files>`. With nothing present:
`bash -n <files>`, which always works.

## Common mistakes

- **Reporting every unquoted expansion at one severity.** An unquoted variable in an `echo` is Low.
  The same defect in an argument to `rm -rf` is Critical. Severity follows consequence.
- **Treating `shellcheck` clean as review complete.** `shellcheck` does not know that `$1` is a
  path deleted later, that the script runs as root from cron, or that a temp file holds secrets.
- **Recommending `set -e` as a cure-all.** It does not fire inside command substitutions, most
  conditionals, or the left side of a pipe without `pipefail`. Say what actually guards the case.
- **Calling a missing `shellcheck` a clean result.** It goes in `## Checks skipped`.
