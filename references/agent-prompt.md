# Agent Prompt Block

The second artifact of every review: a fenced, copy-pasteable block that a downstream coding agent
can act on. It is appended after `## Checks skipped`.

Its whole design goal is that **findings get re-verified before they get applied**. A review goes
stale the moment someone edits the file. A block that can be pasted and obeyed without re-reading
the code is a machine for applying obsolete fixes.

## Template

````markdown
## Agent prompt

```
Verify each finding against current code. Fix only still-valid issues, skip the rest with a
brief reason, keep changes minimal, and validate.

[F1] Critical · @internal/auth/session.go, ~L112-118
  Anchor: `if err == nil { return tok, nil }`
  Issue:  Token returned before signature verification completes, so a forged token
          reaches the caller as valid.
  Expect: Verification runs and errors propagate before any return path yields a token.

[F2] Medium · @web/src/components/Feed.vue, ~L44
  Anchor: `<div v-html="post.body" />`
  Issue:  Post bodies are author-controlled and reach v-html unsanitised, giving stored
          XSS in every reader's session.
  Expect: Post bodies render as text, or pass through a sanitiser whose allow-list
          excludes script, style, and event-handler attributes.

After fixing, run: go vet ./... && go test ./... && bunx tsc --noEmit
Report a table: ID | FIXED | SKIPPED-STALE | SKIPPED-DISAGREE | reason.
```
````

## Fill rules

### 1. Anchor by content, not line number

Every finding carries a short literal snippet copied from the cited location — enough to be unique
in the file, short enough to survive reformatting. The receiving agent relocates the code by
matching that snippet.

- The `~` prefix on line numbers marks them as **hints**. They are where the code was, not where it
  is.
- **If the anchor does not match, the finding is `SKIPPED-STALE` by definition.** Not "search
  harder", not "fix something nearby". The anchor failing to match is the stale signal working.
- Pick anchors that are stable: the offending expression itself, not the blank line above it. Avoid
  anchoring on a line that appears twenty times in the file (`}`, `return nil`).
- Copy it verbatim, including spacing inside the snippet. Do not paraphrase, do not reflow, do not
  fix its style.

### 2. State intent and acceptance criteria, never a diff

`Issue:` says what is wrong. `Expect:` says what must be true when the fix is done.

- **Never put a patch, diff, or replacement code block in the entry.** A patch gets pasted without
  thought, which defeats the entire verification step. If you have written the fix, you have
  removed the agent's reason to read the current code.
- `Expect:` describes an end state that the agent can check the code against — "errors propagate
  before any return path yields a token" — not an action to perform.
- Naming an API is fine (`use the two-value type assertion form`). Writing the caller's line for
  them is not.

### 3. Findings are self-contained

The receiving agent has none of the review context: no report, no diff, no conversation. Each entry
restates enough of the *why* to be judged on its own, including the trust boundary or the caller
that makes it matter. An entry that only makes sense after reading the report above it is a broken
entry.

### 4. Mandatory status table

The block always closes by requiring a table with one row per finding ID. Silence is how findings
get dropped.

| Status | Meaning |
|---|---|
| `FIXED` | Anchor matched, finding still valid, change made. |
| `SKIPPED-STALE` | Anchor did not match current code — the code moved, changed, or was already fixed. |
| `SKIPPED-DISAGREE` | Anchor matched, but the agent judged the finding wrong, and says why. |

Keep `SKIPPED-STALE` and `SKIPPED-DISAGREE` distinct. They mean opposite things about the review:
stale means the review aged, disagree means the review may have been wrong. Collapsing them into
one "skipped" bucket destroys the only feedback signal on review quality this suite has.

Every ID in the block must appear in the table. An ID with no row is a dropped finding.

## Contents and scope

- The block carries **all severities**, Critical through Low. Filtering to the scary ones hides the
  cheap fixes, and the downstream agent is the wrong place to make a triage decision the reviewer
  already made.
- Finding IDs match the human report exactly. `F3` in the block is `F3` above it.
- Order follows the report: worst severity first.
- Paths are repo-relative with an `@` prefix.
- **No findings means no block.** Do not emit an empty block or a block that says "nothing found" —
  it invites a downstream agent to invent work.

## Validation commands

The `After fixing, run:` line is derived from the same capability probe the review used.

- Include a command only if its binary probed **present**. The block must never tell an agent to run
  a tool that is not installed.
- Prefer the cheap, definitive checks: compile, typecheck, test. A formatter's opinion is not
  validation.
- Chain with `&&` so the first failure stops the run.
- If nothing relevant is installed, say so instead of inventing a command:
  `After fixing, run: (no validation tooling available on this machine -- re-read the changed
  hunks instead)`.
