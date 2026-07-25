# Shared Review Rubric

Every skill in this suite scores findings against this rubric. That is what lets a Go finding and a
Vue finding sit in one merged list without the reader having to guess whose scale is whose.

## Severity

Severity answers "how bad is the consequence, and how reachable is it?" — not "how ugly is the
code".

| Level | Meaning | Typical examples |
|---|---|---|
| **Critical** | Exploitable now by an untrusted actor, or causes data loss / corruption on a normal path. No preconditions the attacker does not already control. | Unauthenticated RCE, SQL injection reachable from a public route, credential leak in a shipped artifact, auth check that never runs. |
| **High** | Likely exploitable with a modest precondition, or produces wrong results / crashes during ordinary use. | Injection behind a login, missing authorisation on an object fetch, nil dereference on a common error path, unbounded goroutine leak in a request handler. |
| **Medium** | Wrong or unsafe only under specific conditions, or a maintainability hazard that will produce defects. | Race that needs contention to show, resource leak that needs a long-lived process, error swallowed so failures report as success, missing escaping on data that is currently trusted. |
| **Low** | Hardening, smell, or style with a correctness argument behind it. No current defect. | Missing `set -euo pipefail` in a script that happens to work, `any` masking a type that is currently correct, duplicated logic that has not diverged yet. |

Rules:

- Reachability drives severity. A dangerous pattern in dead code is at most Medium; say in the
  finding that it is unreachable and why.
- Do not inflate. If the worst realistic outcome is a confusing log line, it is Low.
- Do not deflate to avoid an argument. Severity is a claim about consequence, and it is defensible
  or it is wrong.
- Two skills disagreeing about the same code keep the higher severity in the merged list.

## Confidence

Confidence answers "how sure am I that this finding is real?" It is orthogonal to severity — a
Critical/Speculative finding is legitimate and useful.

| Level | Meaning |
|---|---|
| **Confirmed** | The code path was read end to end, or a tool reproduced it. The finding is a fact about the code as written. |
| **Likely** | The dangerous pattern is present and no guard was found, but reachability was not fully traced (callers outside the reviewed scope, dynamic dispatch, framework magic). |
| **Speculative** | Worth a human look. May be a false positive. Reported because silently dropping it is worse. |

Rules:

- **Speculative findings are reported, never dropped.** The confidence label exists precisely so
  that uncertain findings have somewhere to live.
- **Speculative findings are never promoted to make a report look stronger.** If the trace was not
  done, say so.
- If a tool flagged something and the code path was not verified, that is Likely at best. A tool
  hit is not a confirmation.
- State what would raise the confidence: "confirm by checking whether `handleUpload` is reachable
  from an unauthenticated route".

## Finding format

Each finding is one entry with these parts, in this order:

```
[F3] High · Likely · internal/api/users.go:88 · GO-02
  What:   `claims := tok.Claims.(jwt.MapClaims)` asserts without the two-value form.
  Why:    A token carrying different claims panics the handler and takes the process
          down with it -- a remote unauthenticated crash.
  Fix:    Use `claims, ok := tok.Claims.(jwt.MapClaims)` and reject the request when
          `!ok`.
```

| Part | Rule |
|---|---|
| ID | `F1`, `F2`, … Sequential within one report. Stable for the whole life of that report so the agent prompt block and the status table agree. |
| Severity | One of Critical, High, Medium, Low. Exactly those words. |
| Confidence | One of Confirmed, Likely, Speculative. Exactly those words. |
| Location | `file:line`, repo-relative. A range (`file:88-94`) when the issue spans lines. |
| Checklist ID | The rubric row that caught it (`GO-02`, `SH-04`, `SEC-03`, …). Preserves provenance through merging and makes coverage auditable. |
| What | The defect, quoting the offending construct. Not a category name. |
| Why | The consequence, concretely. "Unvalidated input" is not a consequence; "a `../` path reaches `include` and serves `/etc/passwd`" is. |
| Fix | A direction, not a patch. Enough that a competent engineer knows what end state to reach. |

Anti-patterns in findings:

- A "What" that restates the checklist row instead of the code (`GO-06 ignored error` — where?).
- A "Why" that stops at the category (`this is a security risk`).
- A fix that is a diff. Diffs get applied without thought; see `agent-prompt.md`.
- A finding with no location. If it cannot be located it cannot be verified or fixed.

## One defect matching several checklist rows

Checklist rows overlap by design — a data-flow row and a sink row will both match the same line.
Three rules, and the third is the one that decides:

1. **One defect is one finding**, however many rows match it. Emitting `F3` and `F4` for the same
   line inflates the count and makes the report look worse than the code is.
2. **Attribute to the most specific row** — the one naming the sink or the consequence — and list
   the others on the same line so provenance is not lost:

   ```
   [F2] High · Confirmed · app/Http/Users.php:88 · PHP-05 (also PHP-01)
   ```

3. **Unless the rows imply different fixes, in which case they are separate findings.** This is the
   test to apply, not a judgement call about which row feels primary. If closing one row leaves the
   other's row still open, the reader has two pieces of work and needs two entries.

Worked examples:

| Rows matched | Same fix? | Result |
|---|---|---|
| `VT-05` prop crossing a trust boundary + `VT-01` reaching `v-html` | Yes — stop rendering it as HTML and both close | One finding, `VT-01 (also VT-05)` |
| `PHP-01` superglobal into a sink + `PHP-05` SQL by concatenation | Yes — bind the parameter and both close | One finding, `PHP-05 (also PHP-01)` |
| `GEN-01` mishandled boundary + `GEN-07` that boundary is untested | **No** — fixing the branch does not add the test, and the test is what stops it regressing | Two findings |

The same rule governs the agent prompt block: one block entry per finding, so a merged finding
produces one entry and one row in the status table.

## Merging findings from multiple skills

When an entry-point skill delegated to more than one language skill:

1. Concatenate all findings, then **renumber `Fn` sequentially across the merged list**. No
   duplicate IDs, no per-language numbering.
2. **Keep the checklist ID.** It is the only record of which pass found what.
3. Drop exact duplicates — same file, same line, same defect. Note the merge if two skills phrased
   it differently and both phrasings add something.
4. Where severities disagree, **keep the higher one** and say in the finding that assessments
   differed.
5. Order the report by severity, then by file. Do not group by language: the reader wants the worst
   thing first, whatever language it is in.
