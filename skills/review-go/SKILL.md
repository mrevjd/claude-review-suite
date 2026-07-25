---
name: review-go
description: Use when reviewing or auditing Go code - .go files, a go.mod module, "review this Go service", "check this handler before I merge", "audit this package" - covering nil dereference after an error, unchecked type assertions, goroutine and context leaks, SQL built by string concatenation, defer inside loops, ignored errors, and data races on shared state.
---

# Review Go

Correctness and security review for Go. The checklist is the baseline and runs whether or not any
tool is installed; present tools sharpen it. A check that did not run is named in the report — never
omitted, never reported as clean.

## Procedure

Follow `../../references/procedure.md`. In short: probe, scope, run what exists, walk the checklist
by hand over every file in scope, score per `../../references/rubric.md`, emit both artifacts.

## Capability probe

```bash
command -v go            # go vet, go build, go test
command -v staticcheck
command -v gosec
command -v govulncheck
command -v errcheck
```

| Tool | Invocation | If absent |
|---|---|---|
| `go vet` | `go vet ./...` | install Go — nothing else here works either |
| `staticcheck` | `staticcheck ./...` | `go install honnef.co/go/tools/cmd/staticcheck@latest` |
| `gosec` | `gosec -quiet ./...` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| `govulncheck` | `govulncheck ./...` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| `errcheck` | `errcheck ./...` | `go install github.com/kisielk/errcheck@latest` |

Several missing at once? The suite ships `review-tools.sh`, which probes and installs the whole
toolchain in one pass. **Name it in `## Checks skipped` and leave running it to the user** — a review
reports, it does not install.

These tools exit non-zero when they find something. That is a result, not a crash — see the error
handling rules in `../../references/procedure.md`. A build failure that stops analysis *is* a crash:
`staticcheck` cannot report on a package that does not compile, so a compile error means every
tool-based check is skipped, not passed.

## Checklist

Walk every row against every file in scope. `go vet` catches a minority of these; the rest need
reading.

| ID | Look for | Why it matters | Fix direction |
|---|---|---|---|
| **GO-01** | A value used after the error that produced it was non-nil — `x, err := f(); if err != nil { log.Print(err) }` then `x.Field`, or a `return` missing from the error branch. | Go returns zero values alongside errors, so the "handled" path dereferences nil and panics. In a handler that is a remote crash. | The error branch returns, continues, or assigns a usable fallback. No path reaches the value with the error unhandled. |
| **GO-02** | A one-value type assertion — `v := x.(T)` — where `x` is `any`/`interface{}` from JSON, a map, a context value, or a plugin boundary. | A different concrete type panics and takes the process down. Untrusted input reaching one of these is a denial of service. | Two-value form `v, ok := x.(T)` with an explicit `!ok` path, or a type switch with a `default`. |
| **GO-03** | `go func()` whose exit condition depends on a channel nobody may write, a send on an unbuffered channel with no reader, `context.WithCancel`/`WithTimeout` whose `cancel` is not deferred, or a goroutine that ignores `ctx.Done()`. | Leaked goroutines and timers accumulate per request until the process dies. Leaks are invisible in tests and fatal in production. | `defer cancel()` at every `WithCancel`/`WithTimeout`. Every goroutine has a `select` on `ctx.Done()` or a guaranteed-closed channel. |
| **GO-04** | A `database/sql` query string built with `+`, `fmt.Sprintf`, or `strings.Join` around a value that came from a request, a file, or a database. | SQL injection. Identifiers cannot be parameterised, so this is often the real thing rather than a false positive. | Placeholders (`?`, `$1`) with args passed to `Query`/`Exec`. Where an identifier must vary, validate it against a fixed allow-list of known column or table names. |
| **GO-05** | `defer` inside a `for` body — typically `defer f.Close()` or `defer rows.Close()`. | Deferred calls run at function exit, not iteration exit, so descriptors and locks pile up for the whole loop. Over a large input set this exhausts the fd limit. | Move the body into a function (named or closure) called per iteration, or close explicitly at the end of the iteration and on every error path. |
| **GO-06** | `_ = f()` on a function returning `error`, a bare call whose error is discarded, unchecked `defer f.Close()` on a *writable* file, or an ignored `rows.Err()` after a range over `rows`. | Silent failure. A discarded write error means the caller reports success on data that never landed; a missing `rows.Err()` hides a truncated result set that looks like an empty one. | Every error is checked, wrapped with context (`fmt.Errorf("...: %w", err)`), or explicitly ignored with a comment saying why it is safe. |
| **GO-07** | A map, slice, or struct field written from more than one goroutine with no mutex or channel discipline; `sync.WaitGroup` reused across rounds; a captured loop variable in a pre-1.22 module; lazy init with no `sync.Once`. | Data races corrupt memory and crash non-deterministically. Concurrent map write is an unrecoverable fatal error — no recover, no graceful shutdown. | Guard shared state with `sync.Mutex`/`RWMutex`, hand ownership to one goroutine over a channel, or use `sync/atomic`. Confirm with `go test -race`. |

Beyond the checklist, also weigh: `context` not threaded through call chains that do I/O, `time.After`
in a loop, unbounded `io.ReadAll` on a request body, and `http.Client` with no timeout.

## Output

Both artifacts, always:

1. **Human report** per the skeleton in `../../references/procedure.md` — findings grouped by
   severity, then a `## Checks skipped` table naming every absent or crashed tool with its reason and
   install hint.
2. **Agent prompt block** per `../../references/agent-prompt.md`, appended after that table, carrying
   every severity. Omit the block entirely when there are no findings.

Derive the block's validation line from the probe. With the full toolchain present:
`go build ./... && go vet ./... && staticcheck ./... && go test -race ./...`. Drop each absent tool
rather than substituting a different one; `go build ./...` alone is a legitimate floor.

## Common mistakes

- **Passing off a `gosec` hit as a finding without reading the code.** `gosec` flags patterns, not
  reachability. Read the call site, then assign confidence per `../../references/rubric.md`.
- **Calling a missing tool a clean result.** "`govulncheck` reported nothing" and "`govulncheck` is
  not installed" are different claims. The second belongs in `## Checks skipped`.
- **Skipping the manual walk because the tools were quiet.** Authorisation gaps, wrong trust
  boundaries, and misthreaded `context` do not appear in any linter's output.
- **Reporting `defer` in a loop as Critical.** It is a resource leak; severity depends on the
  iteration count and process lifetime. Score consequence, not category.
