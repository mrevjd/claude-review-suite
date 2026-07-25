---
name: code-review
description: Use when the user asks for a review of code they have written or changed - "review this", "look over this PR", "before I merge", "any bugs in this", "is this ready to ship", "give this a once-over" - covering correctness, error handling, resource lifetime, API contracts, maintainability, and missing test coverage.
---

# Code Review

General correctness and maintainability review, and the entry point for the review suite. Detects
what languages are in scope, delegates to the language reviewers that apply, and merges everything
into one list under one rubric.

For a threat-oriented pass — authentication, injection, secrets, crypto — use `security-review`
instead. The two are complements, not substitutes: this skill asks "is this correct?", that one asks
"can this be attacked?".

## Procedure

Follow `../../references/procedure.md` for scoping, probing and error handling. Specifically:

1. **Scope.** Prefer the working diff (`git diff --name-only HEAD`, or `<base>...HEAD` for a branch
   or PR) over the whole tree, unless the user asked for the tree. State which you used.
2. **Detect languages** across every file in scope, using the extension map in
   `../../references/procedure.md`.
3. **Delegate.** For each language present, run the matching skill — `review-go`, `review-bash`,
   `review-vue-ts`, `review-php` — including its capability probe and its full checklist.
4. **Run the general checklist below** over every file in scope. It applies to files a language
   skill already covered as well: the language checklists look for language-specific traps, this one
   looks for logic and lifecycle defects that no linter has an opinion about.
5. **Merge and score** per `../../references/rubric.md`.
6. **Emit both artifacts** — report, then agent prompt block.

## Delegation

- **Several languages in scope:** every matching language skill runs. None is skipped for being a
  small part of the diff.
- **Merging:** concatenate all findings, renumber `Fn` sequentially across the merged list, and keep
  each finding's checklist ID so provenance survives. Order by severity then file — never group by
  language, because the reader wants the worst thing first regardless of what it is written in. Where
  two passes disagree on severity, keep the higher. Full rules in
  `../../references/rubric.md`.
- **No language detected** (Python, Perl, Ruby, SQL, Dockerfiles, config): the general checklist
  below is the whole review. Say explicitly in the report that no language-specific pass ran, and
  which files that affected. Do not skip those files.
- **One tool probe per delegated skill.** Every absent tool from every pass lands in the single
  `## Checks skipped` table at the end of the report. Where several are missing, name the suite's
  `review-tools.sh` there as the one-shot remedy — **suggest it, never run it.** A review reports;
  installing binaries is the user's decision.

## General checklist

Language-agnostic. Walk every row against every file in scope.

| ID | Look for | Why it matters | Fix direction |
|---|---|---|---|
| **GEN-01** | Boundary handling — empty collection, single element, off-by-one in a slice or loop bound, zero or negative quantity, integer division truncating, a "cannot happen" branch that can. | The happy path is what gets tested by hand; boundaries are where the defects live and where the data eventually goes. | Handle the boundary explicitly, or reject it at the entry point with a clear error. Add the case to a test rather than reasoning about it once. |
| **GEN-02** | An error caught and discarded, logged instead of returned, replaced with a default that looks like success, or flattened so the caller cannot distinguish "empty" from "failed". Also: an error message that omits what was being attempted. | A swallowed error converts a loud failure into silent wrong data, and the bug surfaces far from its cause. This is the most expensive defect class to debug later. | Propagate with context added, or handle it here in a way a reader can see is deliberate — with a comment saying why swallowing is correct. |
| **GEN-03** | A file, socket, lock, transaction, subscription, timer, or listener released on the happy path but not on an early return, an exception path, or a loop's error branch. | Leaks are invisible in tests and fatal in long-running processes: descriptor exhaustion, a lock held forever, a transaction never rolled back. | Tie release to scope — the language's `defer`/`with`/`try-finally`/RAII equivalent — so no future early return can bypass it. |
| **GEN-04** | Shared mutable state touched from more than one thread, task, or request; an assumption that two operations are atomic; check-then-act on something another actor can change; ordering assumed between independent async operations. | Races pass every test on a quiet machine and corrupt data under load. "It has always worked" is not evidence of correctness here. | Make the invariant explicit: one owner, a lock with a documented scope, an atomic operation, or a compare-and-swap. State what the invariant is in a comment. |
| **GEN-05** | The implementation contradicting its contract — a documented return type or range that a branch violates, a nullable value returned where callers assume non-null, a mutated argument the caller still owns, a changed signature with a caller left un-updated, an error type callers do not handle. | Callers were written against the contract, not the implementation. A silent contract change turns into a defect in code nobody touched. | Bring one side into line with the other and update every caller. If the contract changes, changing it deliberately and everywhere is the fix. |
| **GEN-06** | Unreachable branches, a parameter or field nobody reads, commented-out logic, and the same rule implemented twice in two places where the copies have already drifted. | Dead code is read as live by the next person and duplicated logic diverges — one copy gets the fix, the other keeps the bug. | Delete the dead path. Extract the duplicated rule into one place, or state in a comment why the copies must stay independent. |
| **GEN-07** | A behaviour that is cheap to pin and currently untested — the boundary from GEN-01, the error path from GEN-02, a bug this change fixes with no regression test, or a branch a reviewer had to reason about to trust. | An untested behaviour is one refactor away from silently breaking. The gap matters most exactly where the review had to think hardest. | Name the specific test worth adding and the case it pins. Do not ask for coverage in general — ask for the one case that would have caught this. |

Also weigh, without inventing findings: naming that misleads about what the code does, a function
doing several unrelated things, a comment contradicting the code beneath it, and configuration or
magic values inlined where they will need changing per environment.

## Output

Both artifacts, always:

1. **Human report** per the skeleton in `../../references/procedure.md`, ending in one
   `## Checks skipped` table covering every pass that ran.
2. **Agent prompt block** per `../../references/agent-prompt.md`, carrying every severity from
   Critical to Low, omitted entirely when there are no findings.

The block's validation line is derived from the union of the delegated probes — for a Go plus Vue/TS
diff with both toolchains present: `go test ./... && bunx tsc --noEmit`. Absent binaries never
appear.

## Common mistakes

- **Reporting style as though it were correctness.** Formatting preferences are not findings. A
  naming problem is a finding only when it misleads about behaviour.
- **Skipping the general checklist because a language skill already ran.** They look for different
  things. A perfectly idiomatic function can still leak a transaction on its error path.
- **Letting the language passes fragment the report.** One merged, renumbered, severity-ordered list.
  Four separate mini-reports make the reader do the triage.
- **Reviewing the diff without reading its surroundings.** A changed line can be correct and still
  break its caller. Read enough context to judge the contract.
- **Padding.** Ten Low findings do not add up to a High one, and they bury it.
