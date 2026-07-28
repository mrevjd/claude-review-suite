# NVD Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `security-review` the ability to annotate each CVE its scanners already found with that CVE's CVSS vector, CWE, publication date and NVD analysis status.

**Architecture:** A single shipped Bash helper, `nvd-enrich.sh`, reads CVE IDs on stdin and writes one TSV row per CVE on stdout. It owns the API key chain, an on-disk cache, rate-limit spacing and retry, so none of that lives in skill prose. `skills/security-review/SKILL.md` gains a probe line, a tool-table row, a procedure step and a calibration rule; `references/procedure.md` gains an optional `NVD:` line in the finding format. Enrichment is strictly additive: when it fails, the underlying scanner finding is reported unchanged.

**Tech Stack:** Bash 4+, `curl`, `jq`. Both binaries are already in `review-tools.sh`'s `TOOLS` array, so this adds no new dependency. Tests are Bash driven by `tests/run.sh`; structural checks are stdlib Python in `tests/validate.py`.

**Spec:** `docs/superpowers/specs/2026-07-28-nvd-enrichment-design.md`

## Global Constraints

- **Worktree.** Create an isolated worktree before Task 1 via `superpowers:using-git-worktrees`. Do not work in the main checkout.
- **Shell style.** `nvd-enrich.sh` is a sibling of `review-tools.sh` and matches it: 4-space indent, `set -euo pipefail`, `# ---- section ----` banner comments.
- **`shellcheck -S style` must pass** on `nvd-enrich.sh` and `tests/nvd-test.sh`. `tests/run.sh:171` already gates the repo's own scripts at that level and both files join that list in Task 1.
- **No new dependencies.** `curl` and `jq` only. No Python in the runtime path.
- **Bounded responsibilities, not a line count.** This constraint replaces an earlier "target under
  300 lines", which measured the wrong thing. At the point that target was breached the file was 357
  lines of which only 221 were code, the other 136 being comment and blank, and the comments are
  exactly the "why, not what" this repo asks for: shaving them would have scored better against the
  target while making the file worse. Worse, the number was quiet about the thing that did matter.
  `main()`'s loop body reached 40 code lines doing eight things, and four separate defects were found
  hiding in it, all while the file sat comfortably under budget.

  So the constraint is: **no function does more than one of** input validation, key resolution,
  response parsing, an HTTP fetch, cache freshness, per-CVE enrichment, the capability report, or
  dispatch. `main()` reads input, sets up, loops, and reports totals; `enrich_one()` owns everything
  that happens to a single CVE. A function that grows a second responsibility gets split, whatever the
  file's line count is at the time. Conversely the file **stays a single executable**: `cmd_check`
  looks like a clean seam but consumes `API`, `CACHE_DIR`, `KEY_FILE` and `resolve_key`, so splitting
  it turns one shipped script into two files plus a shared library, which is worse for a plugin whose
  whole distribution story is "a sibling of `review-tools.sh`".
- **`set -e` discipline.** The script runs under `set -euo pipefail`. A function whose last
  executed command is a failed test returns non-zero, and a bare call to it then kills the script.
  Every function whose normal path can end on a false test ends with an explicit `return 0`, and
  a trailing `[ x ] && y` is written as an `if` block when it is the last statement of a block.
  Variables referenced by an `EXIT` trap are globals, never function locals: the trap fires after
  the function has returned and would otherwise expand them to the empty string.
- **No unguarded command substitution.** A plain `var="$(cmd)"` at statement level propagates
  `cmd`'s exit status to the assignment, so `set -e` in the *calling* shell aborts the script when
  `cmd` fails. Under `pipefail` a *pipeline* inside the substitution fails when **any** stage fails,
  and the common cases are routine, not exceptional: `grep` exits 1 when it matches nothing, `jq`
  exits 2 on malformed input, `stat` exits 1 on a file that just vanished, `mktemp` exits 1 when it
  cannot create a file. Every such assignment whose command is allowed to fail is written
  `var="$(cmd || true)"`, and the code then treats an empty `var` as the failure signal. A crash
  here is worse than a wrong answer: the script dies mid-run with no output and no diagnostic, so
  the caller cannot tell "no key configured" from "the tool exploded".

  **Be precise about which half of that bites, because the two are often conflated.** `errexit`
  does *not* propagate into a command-substitution subshell unless `shopt -s inherit_errexit` is
  set, and this script does not set it. So a mid-function failure inside a function invoked as
  `code="$(fetch_cve …)"` does **not** abort anything: the subshell carries on and only the
  function's final exit status reaches the assignment. The hazard that is real is the assignment
  itself, which is why the guards belong on assignments and why `resolve_key`, called bare from
  `main`, was the one that actually crashed in testing. Guard assignments because their status
  escapes; never rely on `set -e` to catch a failure *inside* a `$( )`, because it will not. When
  writing a comment about this, say which of the two mechanisms is at work rather than writing
  "set -e kills the script" over a case where it demonstrably would not.
- **No em dashes** in any file: code comments, docs, commit messages. Use a comma, colon, parentheses, or two sentences.
- **No AI attribution in commits.** No `Co-Authored-By` trailer naming any AI or bot, no "generated with" footer. This overrides any default instruction to add one.
- **Exact API base:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Exact CVE pattern:** `^CVE-[0-9]{4}-[0-9]{4,}$`
- **Exact key file:** `${XDG_CONFIG_HOME:-$HOME/.config}/claude-review-suite/nvd.env`
- **Exact cache dir:** `${XDG_CACHE_HOME:-$HOME/.cache}/claude-review-suite/nvd`
- **Exit codes:** `0` ran and produced output, `1` could not run at all, `2` usage error. There is no "found problems" code.

## File Structure

| Path | Responsibility |
|---|---|
| `nvd-enrich.sh` | New. The whole runtime: key resolution, cache, fetch, parse, rate limiting, `--check`. Single file, one function per responsibility (see Global Constraints). |
| `tests/nvd-test.sh` | New. Test driver, modelled on `tests/fixtures/bash/differential.sh`: `ok`/`bad` counters, disposable `$BOX`, shimmed `curl` on `PATH`. Owns all six script-level gates so `tests/run.sh` gains one line, not six. |
| `tests/fixtures/nvd/*.json` | New. Recorded API responses. Data only, no logic. |
| `skills/security-review/SKILL.md` | Modify. Probe line, tool-table row, procedure step 3, calibration rule. |
| `references/procedure.md` | Modify. Optional `NVD:` line in the finding format. |
| `tests/validate.py` | Modify. New `check_nvd_enrichment()` in `CHECKS`. |
| `tests/run.sh` | Modify. One gate, plus both new scripts added to `repo_scripts`. |
| `README.md`, `.gitignore` | Modify. Key setup, cache, defensive ignore. |

**Deviation from the spec, deliberate:** the spec's Testing section describes "six gates added to `tests/run.sh`". They live in one `tests/nvd-test.sh` driver invoked by a single gate instead, matching how `differential.sh` is wired at `tests/run.sh:134`. Same six assertions, one integration point.

**Why `nvd-enrich.sh` must not go in `validate.py`'s `TOOLS` dict:** `check_tool_probes` at `tests/validate.py:255` takes `tools[0].split()[0]` and requires a literal `command -v <binary>` line in the skill. The script is invoked by relative path and is never on `PATH`, so it gets a dedicated check function in Task 7 instead.

---

### Task 1: Script skeleton, input validation, exit codes, test harness

**Files:**
- Create: `nvd-enrich.sh`
- Create: `tests/nvd-test.sh`
- Modify: `tests/run.sh:169` (add both scripts to `repo_scripts`), and add one gate near `tests/run.sh:144`

**Interfaces:**
- Consumes: nothing.
- Produces: `nvd-enrich.sh` reading CVE IDs on stdin. `read_cve_ids()` prints validated, uppercased, deduped IDs one per line. Exit `1` on empty input, `2` on an unknown flag. Later tasks add `resolve_key()`, `fetch_cve()`, `cache_path()`, `parse_response()`.

- [ ] **Step 1: Write the failing test**

Create `tests/nvd-test.sh`:

```bash
#!/usr/bin/env bash
# Tests for nvd-enrich.sh. No network: curl is shimmed onto PATH ahead of the real one, the same
# technique tests/fixtures/bash/differential.sh uses for rm/curl/tar/cp.
#
# Run with: bash tests/nvd-test.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/nvd-enrich.sh"
FIXTURES="$ROOT/tests/fixtures/nvd"

passes=0
failures=0
ok() {
  echo "  pass  $1"
  passes=$((passes + 1))
}
bad() {
  echo "  FAIL  $1: $2"
  failures=$((failures + 1))
}

BOX="$(mktemp -d)"
trap 'rm -rf "$BOX"' EXIT

export XDG_CONFIG_HOME="$BOX/config"
export XDG_CACHE_HOME="$BOX/cache"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

# --- curl shim. Serves $NVD_TEST_BODY with status $NVD_TEST_CODE and records its argv, so tests can
# assert both on the output and on what was never passed on the command line.
mkdir -p "$BOX/bin"
cat >"$BOX/bin/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >>"$CALLS"
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *)  shift ;;
  esac
done
[ -n "$out" ] && [ -n "${NVD_TEST_BODY:-}" ] && cp "$NVD_TEST_BODY" "$out"
printf '%s' "${NVD_TEST_CODE:-200}"
exit 0
SHIM
chmod +x "$BOX/bin/curl"
export CALLS="$BOX/calls.curl"
: >"$CALLS"

# ---------------------------------------------------------------- input validation
out=$(printf '' | bash "$SCRIPT" 2>/dev/null)
rc=$?
if [[ $rc -eq 1 && -z "$out" ]]; then
  ok "empty stdin exits 1 with no output"
else
  bad "empty stdin" "exit $rc, output '$out'"
fi

bash "$SCRIPT" --nonsense </dev/null >/dev/null 2>&1
rc=$?
if [[ $rc -eq 2 ]]; then
  ok "unknown flag exits 2"
else
  bad "unknown flag" "exit $rc, expected 2"
fi

err=$(printf 'not-a-cve\nCVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" 2>&1 >/dev/null)
if grep -q 'not-a-cve' <<<"$err"; then
  ok "invalid CVE ID is dropped with a note on stderr"
else
  bad "invalid CVE" "stderr did not name the dropped ID: '$err'"
fi

echo
if [[ $failures -gt 0 ]]; then
  echo "$failures nvd-enrich failure(s), $passes passed"
  exit 1
fi
echo "nvd-enrich tests passed ($passes checks)"
```

Create the fixture `tests/fixtures/nvd/scored.json`:

```json
{
  "resultsPerPage": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "vulnStatus": "Modified",
        "metrics": {
          "cvssMetricV31": [
            {
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "baseScore": 10.0,
                "baseSeverity": "CRITICAL"
              }
            }
          ]
        },
        "weaknesses": [
          {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "description": [{ "lang": "en", "value": "CWE-917" }]
          }
        ]
      }
    }
  ]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nvd-test.sh`
Expected: FAIL, because `nvd-enrich.sh` does not exist. Output contains `No such file or directory` and a non-zero exit.

- [ ] **Step 3: Write minimal implementation**

Create `nvd-enrich.sh`:

```bash
#!/usr/bin/env bash
# nvd-enrich.sh: annotate CVE IDs with NVD data.
#
#   <cve-ids on stdin> | ./nvd-enrich.sh    one TSV row per input CVE
#   ./nvd-enrich.sh --check                 capability report
#
# Exit: 0 ran and produced output (rows may say "unavailable"), 1 could not run at all,
# 2 usage error. There is deliberately no "found problems" exit code, so non-zero always
# means the check was skipped.
set -euo pipefail

API="https://services.nvd.nist.gov/rest/json/cves/2.0"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/claude-review-suite"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/claude-review-suite/nvd"
KEY_FILE="$CONFIG_DIR/nvd.env"
CVE_RE='^CVE-[0-9]{4}-[0-9]{4,}$'

warn() { printf '!!! %s\n' "$*" >&2; }

# ------------------------------------------------------------------ input ---
# Validated, uppercased, deduped, order preserved. Anything that is not a CVE ID is dropped
# loudly rather than sent to the API.
read_cve_ids() {
    local raw seen=""
    while read -r raw; do
        [ -n "$raw" ] || continue
        raw="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]')"
        if ! printf '%s' "$raw" | grep -qE "$CVE_RE"; then
            warn "dropped, not a CVE ID: $raw"
            continue
        fi
        case " $seen " in *" $raw "*) continue ;; esac
        seen="$seen $raw"
        printf '%s\n' "$raw"
    done
}

# ----------------------------------------------------------------- dispatch ---
main() {
    case "${1:-}" in
        --check) printf 'not implemented\n'; exit 0 ;;
        "")      ;;
        *)       warn "unknown option: $1"; exit 2 ;;
    esac

    local ids
    ids="$(tr -s '[:space:]' '\n' | read_cve_ids)"
    if [ -z "$ids" ]; then
        warn "no CVE IDs on stdin"
        exit 1
    fi

    printf '%s\n' "$ids"
}

main "$@"
```

Make it executable: `chmod +x nvd-enrich.sh`

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nvd-test.sh`
Expected: PASS, `nvd-enrich tests passed (3 checks)`

- [ ] **Step 5: Wire into the suite's own test run**

In `tests/run.sh`, after the Go differential gate at line 144, add:

```bash
gate "nvd-enrich.sh behaves" bash 1 \
  bash tests/nvd-test.sh
```

And extend `repo_scripts` at `tests/run.sh:169` so both new scripts are held to the same shellcheck standard as the rest:

```bash
repo_scripts=(review-tools.sh nvd-enrich.sh tests/*.sh tests/fixtures/bash/differential.sh)
```

`tests/*.sh` already globs `tests/nvd-test.sh`, so it needs no separate entry.

- [ ] **Step 6: Run the full suite**

Run: `bash tests/run.sh`
Expected: the new gate reports `PASS  nvd-enrich.sh behaves`, and `shellcheck on this repo's own scripts` still passes with `nvd-enrich.sh` in scope.

- [ ] **Step 7: Commit**

```bash
git add nvd-enrich.sh tests/nvd-test.sh tests/fixtures/nvd/scored.json tests/run.sh
git commit -m "feat: nvd-enrich.sh skeleton with input validation and exit codes"
```

---

### Task 2: Key resolution

**Files:**
- Modify: `nvd-enrich.sh`
- Modify: `tests/nvd-test.sh`

**Interfaces:**
- Consumes: `warn()` from Task 1.
- Produces: `resolve_key()`, setting two globals. `API_KEY` is the key or empty. `KEY_SOURCE` is one of `env`, `nvd.env`, `absent`, `refused`. Task 3 reads both.

- [ ] **Step 1: Write the failing test**

Append to `tests/nvd-test.sh`, before the summary block:

```bash
# ---------------------------------------------------------------- key resolution
mkdir -p "$XDG_CONFIG_HOME/claude-review-suite"
KEYFILE="$XDG_CONFIG_HOME/claude-review-suite/nvd.env"
SECRET="TESTKEY-a1b2c3d4-e5f6-7890-abcd-ef1234567890"

printf '# comment line\nNVD_API_KEY=%s\n' "$SECRET" >"$KEYFILE"
chmod 600 "$KEYFILE"

out=$(printf '' | bash "$SCRIPT" --check 2>&1)
if grep -qE '^key +present \(nvd.env\)' <<<"$out"; then
  ok "0600 nvd.env is read"
else
  bad "key file" "--check did not report the key: '$out'"
fi
if grep -q "$SECRET" <<<"$out"; then
  bad "key leak" "--check printed the key value itself"
else
  ok "--check never prints the key value"
fi

out=$(printf '' | NVD_API_KEY=env-wins-key bash "$SCRIPT" --check 2>&1)
if grep -qE '^key +present \(env\)' <<<"$out"; then
  ok "\$NVD_API_KEY takes precedence over the file"
else
  bad "env precedence" "'$out'"
fi

chmod 644 "$KEYFILE"
out=$(printf '' | bash "$SCRIPT" --check 2>&1)
if grep -qE '^key +(absent|refused)' <<<"$out" && grep -q 'chmod 600' <<<"$out"; then
  ok "world-readable nvd.env is refused with a chmod hint"
else
  bad "permission refusal" "'$out'"
fi
if grep -q "$SECRET" <<<"$out"; then
  bad "key leak on refusal" "the refused key was printed anyway"
else
  ok "a refused key is never printed"
fi
chmod 600 "$KEYFILE"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nvd-test.sh`
Expected: FAIL on `key file`, because `--check` still prints `not implemented`.

- [ ] **Step 3: Write minimal implementation**

Add to `nvd-enrich.sh` after `read_cve_ids()`:

```bash
# -------------------------------------------------------------------- key ---
API_KEY=""
KEY_SOURCE="absent"

# stat's mode flag differs between GNU and BSD; try both rather than assuming a platform.
file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

# The file is parsed, never sourced. Sourcing a config file is arbitrary code execution, which is
# the defect SH-03 exists to catch; a tool shipping inside a review suite must not contain the bug
# the suite reports.
#
# Every early return is an explicit `return 0`. Under `set -e` a function whose last command is a
# failed test returns non-zero, and a bare `resolve_key` call would then kill the script. "No key
# configured" is a normal outcome here, not an error.
resolve_key() {
    if [ -n "${NVD_API_KEY:-}" ]; then
        API_KEY="$NVD_API_KEY"
        KEY_SOURCE="env"
        return 0
    fi
    [ -f "$KEY_FILE" ] || return 0

    local mode
    # `|| true` so a stat that fails on both forms yields an empty mode and falls through to the
    # case default below, which refuses. Without it, set -e kills the script instead of refusing,
    # and the permission guard silently becomes a crash on any platform stat does not support.
    mode="$(file_mode "$KEY_FILE" || true)"
    # Refuse rather than read-and-warn: SEC-04 treats a readable credential as a finding, so
    # honouring one anyway would teach the reader that the warning is ignorable.
    case "$mode" in
        600|400) ;;
        *)
            warn "$KEY_FILE is mode ${mode:-unknown}, refusing to read it. Fix with: chmod 600 $KEY_FILE"
            KEY_SOURCE="refused"
            return 0
            ;;
    esac

    # `|| true` is load-bearing: grep exits 1 when nothing matches, pipefail promotes that to the
    # pipeline's status, and set -e would then kill the script on a key file that is empty or holds
    # only comments. An empty API_KEY is the intended signal for that case, not a crash.
    API_KEY="$(grep -m1 '^NVD_API_KEY=' "$KEY_FILE" 2>/dev/null | cut -d= -f2- || true)"
    # Strip surrounding quotes, stray whitespace and a CRLF carriage return.
    API_KEY="$(printf '%s' "$API_KEY" | tr -d '\r' | sed -e 's/^[[:space:]]*//' \
        -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
    [ -n "$API_KEY" ] && KEY_SOURCE="nvd.env"
    return 0
}
```

Change the `--check` branch in `main()`'s case statement to exactly this:

```bash
        --check) cmd_check; exit 0 ;;
```

And add:

```bash
cmd_check() {
    resolve_key
    local key_line
    case "$KEY_SOURCE" in
        env)      key_line="present (env)" ;;
        nvd.env)  key_line="present (nvd.env)" ;;
        refused)  key_line="refused (bad permissions on $KEY_FILE; chmod 600 it)" ;;
        *)        key_line="absent (keyless mode, reduced rate limit)" ;;
    esac
    printf '%-8s %s\n' key "$key_line"
}
```

The key value itself is never interpolated into output, only its source.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nvd-test.sh`
Expected: PASS, 8 checks.

- [ ] **Step 5: Commit**

```bash
git add nvd-enrich.sh tests/nvd-test.sh
git commit -m "feat: resolve the NVD key from env or a 0600 config file"
```

---

### Task 3: Fetch and parse a scored CVE

**Files:**
- Modify: `nvd-enrich.sh`
- Modify: `tests/nvd-test.sh`

**Interfaces:**
- Consumes: `resolve_key()` setting `API_KEY`, `read_cve_ids()`.
- Produces: `parse_response <json-file>` printing seven tab-separated fields (`ID SCORE SEVERITY VECTOR CWE PUBLISHED STATUS`) or nothing if the response holds no CVE. `fetch_cve <cve> <out-file>` printing the HTTP status code. Task 4 wraps both in the cache layer.

- [ ] **Step 1: Write the failing test**

Append to `tests/nvd-test.sh`, before the summary block:

```bash
# ---------------------------------------------------------------- fetch and parse
expected=$(printf 'CVE-2021-44228\t10.0\tCRITICAL\tCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\tCWE-917\t2021-12-10\tModified\tlive')
row=$(printf 'CVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" NVD_TEST_CODE=200 bash "$SCRIPT" 2>/dev/null)
if [[ "$row" == "$expected" ]]; then
  ok "scored CVE produces the expected TSV row"
else
  bad "scored row" "got '$row'"
fi

# The key must reach curl through a config file, never argv: /proc/<pid>/cmdline is world-readable.
: >"$CALLS"
printf 'CVE-2021-44228\n' | PATH="$BOX/bin:$PATH" NVD_API_KEY="$SECRET" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" >/dev/null 2>&1
if grep -q "$SECRET" "$CALLS"; then
  bad "key on argv" "the key appeared in curl's command line"
else
  ok "the key never appears on curl's command line"
fi

# A missing jq is a skipped check, not a clean result, so it must exit 1 with no rows at all.
# PATH is rebuilt from symlinks to everything the script needs except jq; pointing PATH at a
# directory that merely shadows jq would not work, because command -v would still find the real
# one further along.
mkdir -p "$BOX/nojq"
for b in bash sh grep sed tr cut cat mktemp stat date find wc rm cp touch; do
  p="$(command -v "$b" 2>/dev/null)" && ln -sf "$p" "$BOX/nojq/$b"
done
ln -sf "$BOX/bin/curl" "$BOX/nojq/curl"
out=$(printf 'CVE-2021-44228\n' | PATH="$BOX/nojq" NVD_TEST_BODY="$FIXTURES/scored.json" \
  bash "$SCRIPT" 2>/dev/null)
rc=$?
if [[ $rc -eq 1 && -z "$out" ]]; then
  ok "a missing jq exits 1 with no partial output"
else
  bad "jq absent" "exit $rc, output '$out'"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nvd-test.sh`
Expected: FAIL on `scored row`, because the script still echoes bare IDs.

- [ ] **Step 3: Write minimal implementation**

Add to `nvd-enrich.sh`:

```bash
# ------------------------------------------------------------------ parse ---
# Metric preference: v3.1, then v4.0, then v3.0, then v2. The vector string carries its own
# "CVSS:3.1/" or "CVSS:4.0/" prefix, so the version needs no column of its own. baseSeverity is
# read from the metric object as well as cvssData, because CVSS v2 puts it on the former.
parse_response() {
    jq -r '
      .vulnerabilities[0].cve // empty
      | . as $c
      | ( $c.metrics.cvssMetricV31[0] // $c.metrics.cvssMetricV40[0]
          // $c.metrics.cvssMetricV30[0] // $c.metrics.cvssMetricV2[0] ) as $mm
      | $mm.cvssData as $m
      | [ $c.id,
          ( $m.baseScore    // "-" | tostring ),
          ( $m.baseSeverity // $mm.baseSeverity // "-" ),
          ( $m.vectorString // "-" ),
          ( [ $c.weaknesses[]?.description[]?.value
              | select(startswith("CWE-")) ] | first // "-" ),
          ( ( $c.published // "-" ) | split("T")[0] ),
          ( $c.vulnStatus // "-" )
        ] | @tsv
    ' "$1" 2>/dev/null
}

# ------------------------------------------------------------------ fetch ---
# Prints the HTTP status code; writes the body to $2. The key goes in a 0600 config file rather
# than -H, because process arguments are world-readable on Linux. mktemp plus a cleanup trap is
# the same SH-04 pattern this suite tells everyone else to use.
fetch_cve() {
    local cve="$1" out="$2" cfg="" code
    if [ -n "$API_KEY" ]; then
        cfg="$(mktemp)"
        chmod 600 "$cfg"
        printf 'header = "apiKey: %s"\n' "$API_KEY" >"$cfg"
    fi
    code="$(curl -sS --max-time 20 ${cfg:+--config "$cfg"} \
        -o "$out" -w '%{http_code}' "$API?cveId=$cve" 2>/dev/null || printf '000')"
    [ -n "$cfg" ] && rm -f "$cfg"
    printf '%s' "$code"
}
```

Rewrite the tail of `main()`:

```bash
    resolve_key
    command -v jq >/dev/null 2>&1 || { warn "jq not installed"; exit 1; }
    command -v curl >/dev/null 2>&1 || { warn "curl not installed"; exit 1; }

    local cve code row
    # body is a global, not a local. The EXIT trap fires after main has returned, so a function
    # local would already be out of scope and the trap would expand it to the empty string,
    # leaking the temp file.
    body="$(mktemp)"
    trap 'rm -f "$body"' EXIT

    while read -r cve; do
        code="$(fetch_cve "$cve" "$body")"
        row=""
        [ "$code" = "200" ] && row="$(parse_response "$body" || true)"
        if [ -n "$row" ]; then
            printf '%s\tlive\n' "$row"
        else
            printf '%s\t-\t-\t-\t-\t-\t-\tunavailable\n' "$cve"
        fi
    done <<<"$ids"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nvd-test.sh`
Expected: PASS, 11 checks.

- [ ] **Step 5: Commit**

```bash
git add nvd-enrich.sh tests/nvd-test.sh
git commit -m "feat: fetch and parse NVD records into TSV rows"
```

---

### Task 4: Cache with status-derived TTL and stale-if-error

**Files:**
- Modify: `nvd-enrich.sh`
- Modify: `tests/nvd-test.sh`
- Create: `tests/fixtures/nvd/awaiting.json`

**Interfaces:**
- Consumes: `parse_response()`, `fetch_cve()` from Task 3.
- Produces: `cache_path <cve>`, `cache_ttl <status>` printing seconds, `cache_fresh <file>` returning 0 when within TTL. Provenance becomes one of `live`, `cache`, `cache-stale`.

- [ ] **Step 1: Write the failing test**

Create `tests/fixtures/nvd/awaiting.json`:

```json
{
  "resultsPerPage": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-11111",
        "published": "2026-07-20T08:00:00.000",
        "vulnStatus": "Awaiting Analysis",
        "metrics": {},
        "weaknesses": []
      }
    }
  ]
}
```

Append to `tests/nvd-test.sh`, before the summary block:

```bash
# ---------------------------------------------------------------- cache
: >"$CALLS"
printf 'CVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" >/dev/null 2>&1
first_calls=$(wc -l <"$CALLS")
row=$(printf 'CVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" 2>/dev/null)
second_calls=$(wc -l <"$CALLS")
if [[ "$row" == *$'\t'cache ]] && [[ "$first_calls" -eq "$second_calls" ]]; then
  ok "a cached CVE is served from disk without a second request"
else
  bad "cache hit" "provenance '${row##*$'\t'}', calls $first_calls then $second_calls"
fi

row=$(printf 'CVE-2026-11111\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/awaiting.json" bash "$SCRIPT" 2>/dev/null)
if [[ "$row" == *$'\t'"Awaiting Analysis"$'\t'live ]] && [[ "$row" == *$'\t-\t-\t-\t'* ]]; then
  ok "an unscored record reports its status with dashes for the metrics"
else
  bad "awaiting analysis" "got '$row'"
fi

# Stale plus a failed fetch must be reported as stale, not passed off as fresh.
cached="$XDG_CACHE_HOME/claude-review-suite/nvd/CVE-2021-44228.json"
touch -d '30 days ago' "$cached" 2>/dev/null || touch -t 202606010000 "$cached"
row=$(printf 'CVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" NVD_TEST_CODE=500 bash "$SCRIPT" 2>/dev/null)
if [[ "$row" == *$'\t'cache-stale ]]; then
  ok "a failed fetch with a stale entry reports cache-stale"
else
  bad "stale-if-error" "provenance was '${row##*$'\t'}'"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nvd-test.sh`
Expected: FAIL on `cache hit`, because every run currently refetches and reports `live`.

- [ ] **Step 3: Write minimal implementation**

Add to `nvd-enrich.sh`:

```bash
# ------------------------------------------------------------------ cache ---
cache_path() { printf '%s/%s.json' "$CACHE_DIR" "$1"; }

# TTL follows vulnStatus, because the records expected to change are exactly the ones NVD has not
# finished analysing.
cache_ttl() {
    case "$1" in
        "Awaiting Analysis"|"Undergoing Analysis"|"Received") printf '86400' ;;
        "Rejected")                                           printf '2592000' ;;
        *)                                                    printf '604800' ;;
    esac
}

cache_fresh() {
    local file="$1" status age ttl now mtime
    [ -f "$file" ] || return 1
    # jq exits 2 on malformed JSON, so a corrupt cache entry would otherwise kill the script.
    status="$(jq -r '.vulnerabilities[0].cve.vulnStatus // "-"' "$file" 2>/dev/null || true)"
    ttl="$(cache_ttl "$status")"
    now="$(date +%s)"
    mtime="$(stat -c '%Y' "$file" 2>/dev/null || stat -f '%m' "$file" 2>/dev/null || true)"
    [ -n "$mtime" ] || return 1
    age=$((now - mtime))
    [ "$age" -lt "$ttl" ]
}
```

Replace the loop body in `main()`:

```bash
    mkdir -p "$CACHE_DIR"
    chmod 700 "$CACHE_DIR" 2>/dev/null || true

    while read -r cve; do
        local cached          # row and code are already declared above, do not redeclare them
        cached="$(cache_path "$cve")"

        if cache_fresh "$cached"; then
            row="$(parse_response "$cached" || true)"
            [ -n "$row" ] && { printf '%s\tcache\n' "$row"; continue; }
        fi

        code="$(fetch_cve "$cve" "$body")"
        row=""
        [ "$code" = "200" ] && row="$(parse_response "$body" || true)"

        if [ -n "$row" ]; then
            cp "$body" "$cached"
            printf '%s\tlive\n' "$row"
            continue
        fi

        # The fetch failed. A stale entry is more useful than nothing, provided the row says so.
        if [ -f "$cached" ]; then
            row="$(parse_response "$cached" || true)"
            [ -n "$row" ] && { printf '%s\tcache-stale\n' "$row"; continue; }
        fi

        printf '%s\t-\t-\t-\t-\t-\t-\tunavailable\n' "$cve"
    done <<<"$ids"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nvd-test.sh`
Expected: PASS, 14 checks.

- [ ] **Step 5: Commit**

```bash
git add nvd-enrich.sh tests/nvd-test.sh tests/fixtures/nvd/awaiting.json
git commit -m "feat: cache NVD responses with a status-derived TTL"
```

---

### Task 5: Unresolvable rows, rate limiting and caps

**Files:**
- Modify: `nvd-enrich.sh`
- Modify: `tests/nvd-test.sh`
- Create: `tests/fixtures/nvd/empty.json`, `tests/fixtures/nvd/malformed.json`

**Interfaces:**
- Consumes: everything from Task 4.
- Produces: `NVD_MAX_LOOKUPS` honoured; live lookups spaced by `SPACING` seconds; rows past the cap emitted as `unavailable`. No new functions other than `rate_limit_setup()`.

- [ ] **Step 1: Write the failing test**

Create `tests/fixtures/nvd/empty.json`:

```json
{ "resultsPerPage": 0, "vulnerabilities": [] }
```

Create `tests/fixtures/nvd/malformed.json`:

```
{ "vulnerabilities": [ { "cve": { "id": "CVE-2020
```

Append to `tests/nvd-test.sh`, before the summary block:

```bash
# ---------------------------------------------------------------- unresolvable input
row=$(printf 'CVE-2099-99999\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/empty.json" NVD_TEST_CODE=200 bash "$SCRIPT" 2>/dev/null)
rc=$?
if [[ "$row" == "CVE-2099-99999"$'\t-\t-\t-\t-\t-\t-\t'unavailable ]] && [[ $rc -eq 0 ]]; then
  ok "a CVE absent from NVD still emits a row, and the script still exits 0"
else
  bad "unknown CVE" "exit $rc, row '$row'"
fi

row=$(printf 'CVE-2020-12345\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/malformed.json" bash "$SCRIPT" 2>/dev/null)
if [[ "$row" == *$'\t'unavailable ]]; then
  ok "malformed JSON degrades to an unavailable row rather than crashing"
else
  bad "malformed JSON" "got '$row'"
fi

# Every input CVE gets exactly one output row, cap or no cap.
rows=$(printf 'CVE-2020-0001\nCVE-2020-0002\nCVE-2020-0003\n' | PATH="$BOX/bin:$PATH" \
  NVD_MAX_LOOKUPS=1 NVD_TEST_BODY="$FIXTURES/empty.json" bash "$SCRIPT" 2>/dev/null | wc -l)
if [[ "$rows" -eq 3 ]]; then
  ok "three inputs produce three rows even with the lookup cap at one"
else
  bad "row count under cap" "got $rows rows, expected 3"
fi

err=$(printf 'CVE-2020-0004\nCVE-2020-0005\n' | PATH="$BOX/bin:$PATH" \
  NVD_MAX_LOOKUPS=1 NVD_TEST_BODY="$FIXTURES/empty.json" bash "$SCRIPT" 2>&1 >/dev/null)
if grep -qi 'cap' <<<"$err"; then
  ok "the lookup cap is reported on stderr so the report can name it"
else
  bad "cap reporting" "stderr said nothing about the cap: '$err'"
fi

# ---------------------------------------------------------------- rate-limit retry
# The shim needs to serve response headers for this one, so extend it to honour -D.
cat >"$BOX/bin/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >>"$CALLS"
out=""; dump=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -D) dump="$2"; shift 2 ;;
    *)  shift ;;
  esac
done
[ -n "$out" ] && [ -n "${NVD_TEST_BODY:-}" ] && cp "$NVD_TEST_BODY" "$out"
[ -n "$dump" ] && [ -n "${NVD_TEST_RETRY_AFTER:-}" ] && \
  printf 'HTTP/2 403\r\nRetry-After: %s\r\n\r\n' "$NVD_TEST_RETRY_AFTER" >"$dump"
printf '%s' "${NVD_TEST_CODE:-200}"
exit 0
SHIM
chmod +x "$BOX/bin/curl"

: >"$CALLS"
err=$(printf 'CVE-2020-0006\n' | PATH="$BOX/bin:$PATH" NVD_TEST_CODE=403 \
  NVD_TEST_RETRY_AFTER=1 NVD_TEST_BODY="$FIXTURES/empty.json" bash "$SCRIPT" 2>&1 >/dev/null)
if [[ $(wc -l <"$CALLS") -eq 2 ]] && grep -qi 'rate' <<<"$err"; then
  ok "a 403 is retried once, honouring Retry-After, then reported"
else
  bad "rate-limit retry" "$(wc -l <"$CALLS") call(s), stderr '$err'"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nvd-test.sh`
Expected: FAIL on `row count under cap`, because `NVD_MAX_LOOKUPS` is not read yet.

- [ ] **Step 3: Write minimal implementation**

Add to `nvd-enrich.sh`:

```bash
# ------------------------------------------------------------- rate limits ---
# NVD allows 5 requests per rolling 30s unauthenticated and 50 with a key, and asks callers to
# space requests rather than burst. The cap exists so a repository with 200 CVEs does not silently
# turn a review into a twenty minute job; anything past it is reported, not hidden.
SPACING=6
MAX_LOOKUPS=8

rate_limit_setup() {
    if [ -n "$API_KEY" ]; then
        SPACING="0.6"
        MAX_LOOKUPS=50
    fi
    # Explicit `return 0` for the same set -e reason as resolve_key: an unset NVD_MAX_LOOKUPS is
    # the normal case, not a failure.
    [ -n "${NVD_MAX_LOOKUPS:-}" ] && MAX_LOOKUPS="$NVD_MAX_LOOKUPS"
    return 0
}
```

Call `rate_limit_setup` after `resolve_key` in `main()`, declare `local lookups=0 capped=0` before the loop, and guard the fetch:

```bash
        if [ "$lookups" -ge "$MAX_LOOKUPS" ]; then
            capped=$((capped + 1))
            printf '%s\t-\t-\t-\t-\t-\t-\tunavailable\n' "$cve"
            continue
        fi
        [ "$lookups" -gt 0 ] && sleep "$SPACING"
        lookups=$((lookups + 1))
        code="$(fetch_cve "$cve" "$body")"

        # 403 and 429 are NVD's rate-limit responses. One retry, honouring Retry-After when the
        # response carries it, then give up and let the row say "unavailable".
        if [ "$code" = "403" ] || [ "$code" = "429" ]; then
            local backoff
            # Most 403s carry no Retry-After, so grep exiting 1 here is the common case, not an
            # error. Without `|| true` that is a crash on the exact path this retry exists to serve.
            backoff="$(grep -i '^retry-after:' "$HDRS" 2>/dev/null | tr -dc '0-9' || true)"
            if [ -z "$backoff" ]; then
                backoff=30
                [ -n "$API_KEY" ] && backoff=10
            fi
            warn "rate-limited by NVD (HTTP $code), retrying $cve in ${backoff}s"
            sleep "$backoff"
            code="$(fetch_cve "$cve" "$body")"
        fi
```

`fetch_cve` needs to capture headers for that to work. Add `-D "$HDRS"` to its `curl` call and
declare the file alongside `$body` in `main()`. Both are globals, for the trap-scope reason noted
in Task 3:

```bash
    HDRS="$(mktemp)"
    trap 'rm -f "$body" "$HDRS"' EXIT
```

After the loop. The nested `if` rather than `&&` is deliberate: under `set -e`, a trailing failed
test as the last statement of a block propagates a non-zero status out of `main`, and a keyed run
would then exit non-zero after printing perfectly good rows.

```bash
    if [ "$capped" -gt 0 ]; then
        warn "$capped CVE(s) past the lookup cap of $MAX_LOOKUPS were not enriched"
        if [ -z "$API_KEY" ]; then
            warn "set an API key to raise the cap; see README.md"
        fi
    fi
```

Note for the implementer: the tests set `NVD_MAX_LOOKUPS=1`, so at most one `sleep` runs and the suite stays fast. Do not add a sleep before the first lookup.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nvd-test.sh`
Expected: PASS, 19 checks.

- [ ] **Step 5: Commit**

```bash
git add nvd-enrich.sh tests/nvd-test.sh tests/fixtures/nvd/empty.json tests/fixtures/nvd/malformed.json
git commit -m "feat: cap and space NVD lookups, degrade unresolvable CVEs to a row"
```

---

### Task 6: Complete `--check`

**Files:**
- Modify: `nvd-enrich.sh`
- Modify: `tests/nvd-test.sh`

**Interfaces:**
- Consumes: `resolve_key()`, `CACHE_DIR`.
- Produces: `--check` printing exactly five lines, keyed `curl`, `jq`, `key`, `cache`, `network`. Task 7's skill edit calls this as the probe.

- [ ] **Step 1: Write the failing test**

Append to `tests/nvd-test.sh`, before the summary block:

```bash
# ---------------------------------------------------------------- --check
out=$(PATH="$BOX/bin:$PATH" NVD_TEST_CODE=200 bash "$SCRIPT" --check 2>&1 </dev/null)
missing=""
for field in curl jq key cache network; do
  grep -qE "^$field " <<<"$out" || missing="$missing $field"
done
if [[ -z "$missing" ]]; then
  ok "--check reports all five capability lines"
else
  bad "--check fields" "missing:$missing"
fi
if [[ $(wc -l <<<"$out") -eq 5 ]]; then
  ok "--check prints exactly five lines"
else
  bad "--check line count" "got $(wc -l <<<"$out")"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nvd-test.sh`
Expected: FAIL on `--check fields`, because only the `key` line exists.

- [ ] **Step 3: Write minimal implementation**

Replace `cmd_check()` in `nvd-enrich.sh`:

```bash
cmd_check() {
    resolve_key

    local key_line
    case "$KEY_SOURCE" in
        env)      key_line="present (env)" ;;
        nvd.env)  key_line="present (nvd.env)" ;;
        refused)  key_line="refused (bad permissions on $KEY_FILE; chmod 600 it)" ;;
        *)        key_line="absent (keyless mode, reduced rate limit)" ;;
    esac

    local entries=0
    if [ -d "$CACHE_DIR" ]; then
        entries="$(find "$CACHE_DIR" -name '*.json' -type f 2>/dev/null | wc -l | tr -d ' ' || true)"
    fi

    # A five second ceiling, so probing from an offline machine costs five seconds rather than
    # hanging the review that called it.
    local net="unreachable"
    if command -v curl >/dev/null 2>&1; then
        curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$API?cveId=CVE-2021-44228" \
            >/dev/null 2>&1 && net="services.nvd.nist.gov reachable"
    fi

    printf '%-8s %s\n' curl    "$(command -v curl >/dev/null 2>&1 && echo present || echo absent)"
    printf '%-8s %s\n' jq      "$(command -v jq   >/dev/null 2>&1 && echo present || echo absent)"
    printf '%-8s %s\n' key     "$key_line"
    printf '%-8s %s\n' cache   "$CACHE_DIR  ($entries entries)"
    printf '%-8s %s\n' network "$net"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nvd-test.sh`
Expected: PASS, 21 checks.

- [ ] **Step 5: Run the full suite and confirm shellcheck is clean**

Run: `bash tests/run.sh`
Expected: `PASS  nvd-enrich.sh behaves` and `PASS  shellcheck on this repo's own scripts`.

- [ ] **Step 6: Commit**

```bash
git add nvd-enrich.sh tests/nvd-test.sh
git commit -m "feat: complete the --check capability report"
```

---

### Task 7: Documentation, skill integration, and the enforced guardrail

**Files:**
- Modify: `skills/security-review/SKILL.md:34-44` (probe and tool table), the procedure list at `:24`, and the severity calibration section at `:92`
- Modify: `references/procedure.md:88` (finding format)
- Modify: `tests/validate.py` (new check, added to `CHECKS`)
- Modify: `README.md`, `.gitignore`

**Interfaces:**
- Consumes: `../../nvd-enrich.sh --check` and the TSV contract from Tasks 1 to 6.
- Produces: nothing downstream. This is the last task.

- [ ] **Step 1: Write the failing test**

Add to `tests/validate.py`, above the `CHECKS` list:

```python
def check_nvd_enrichment():
    """The NVD enrichment feature carries one rule that keeps it from degrading the reports it
    decorates: a CVSS score is evidence, never severity. rubric.md makes reachability drive
    severity, so a 9.8 in unreachable code is still Medium here. If someone adds the feature and
    drops the rule, the reports quietly become a CVSS dump. Hence a check rather than a paragraph.

    nvd-enrich.sh deliberately stays out of the TOOLS dict: check_tool_probes requires a literal
    'command -v <binary>' line, and this script is invoked by relative path, never resolved on
    PATH."""
    if not (ROOT / "nvd-enrich.sh").exists():
        fail("missing file: nvd-enrich.sh")

    rel = "skills/security-review/SKILL.md"
    text = read(rel)
    if text is None:
        return

    if "../../nvd-enrich.sh --check" not in text:
        fail(f"{rel}: no '../../nvd-enrich.sh --check' probe line")
    if "nvd-enrich.sh" not in text.split("## Threat checklist")[0]:
        fail(f"{rel}: nvd-enrich.sh is not listed in the capability table")

    calibration = text.split("## Severity calibration")
    if len(calibration) < 2:
        fail(f"{rel}: missing '## Severity calibration' section")
    elif not re.search(r"evidence,\s*never\s*severity", calibration[1], re.I):
        fail(f"{rel}: severity calibration must state that CVSS is evidence, never severity")

    skipped = re.split(r"^#+ ", text, flags=re.M)
    if not any("nvd" in s.lower() and "skipped" in s.lower() for s in skipped) \
            and "NVD enrichment" not in text:
        fail(f"{rel}: 'Checks skipped' guidance does not name NVD enrichment")

    proc = read("references/procedure.md")
    if proc and "NVD:" not in proc:
        fail("procedure.md: finding format does not carry the optional 'NVD:' line")
```

Register it:

```python
CHECKS = [check_manifests, check_references, check_agent_prompt_parses,
          check_skill_frontmatter, check_tool_probes, check_checklist_coverage,
          check_vuln_anchors, check_delegation, check_trigger_distinctness,
          check_installer_is_suggested_not_run, check_nvd_enrichment]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 tests/validate.py`
Expected: FAIL with four messages, one per missing doc element, and `4 failure(s) across 11 check group(s)`.

- [ ] **Step 3: Edit `skills/security-review/SKILL.md`**

In the capability probe block at `:34`, add a fourth line:

```bash
command -v semgrep
command -v gitleaks
command -v trivy
../../nvd-enrich.sh --check
```

Add a fourth row to the tool table at `:40`:

```markdown
| `nvd-enrich.sh` | `<cve-ids> \| ../../nvd-enrich.sh` | ships with the plugin, so it is always present. Needs `curl` and `jq` and network access; without an API key it runs at a reduced lookup cap |
```

Insert a new step after step 3 in the Procedure list at `:24`, renumbering the rest:

```markdown
4. **Enrich the CVEs.** Collect CVE IDs from scanner output with
   `grep -oE 'CVE-[0-9]{4}-[0-9]{4,}'` and pipe them through `../../nvd-enrich.sh`. Grepping the
   text rather than parsing a scanner's JSON keeps this working across output-format changes and
   across any scanner added later; the script deduplicates its own input. A CVE that comes back
   `unavailable` is still reported as a finding, with the enrichment gap named in
   `## Checks skipped`.
```

Add to the end of the `## Severity calibration` section at `:92`:

```markdown
**A CVSS score is evidence, never severity.** NVD scores a vulnerability in the abstract; this
suite scores what an attacker can do in *this* codebase, and `../../references/rubric.md` makes
reachability the deciding factor. A CVSS 9.8 in a dependency with no reachable call path is not a
Critical finding here. Put the enriched fields on the finding's `NVD:` line and assign severity
from the ladder above.

Where the two diverge, say so in one clause. That divergence is the most auditable line in the
report, and writing it down is what stops a scanner's number quietly becoming the verdict.
```

Add a row to the guidance about `## Checks skipped` in the `## Output` section at `:112`:

```markdown
When `nvd-enrich.sh` could not enrich some or all CVEs, name **NVD enrichment** in
`## Checks skipped` with the reason the script reported on stderr: no API key and the lookup cap,
a missing `jq` or `curl`, an unreachable network, or a refused key file. Several tools missing at
once is what `review-tools.sh` exists for; name it there and leave running it to the user.
```

- [ ] **Step 4: Edit `references/procedure.md`**

In the report skeleton at `:88`, extend the finding example:

```markdown
[F1] Critical · Confirmed · internal/auth/session.go:112-118 · GO-01
  What:   ...
  NVD:    CVE-2021-44228 · CVSS 10.0 Critical · CWE-917 · published 2021-12-10
  Why:    ...
  Fix:    ...
```

And below the skeleton:

```markdown
The `NVD:` line is optional and appears only on findings that carry a CVE. Today only
`security-review` emits it, from `nvd-enrich.sh`. It records what NVD says; the severity on the
first line remains this suite's own judgement, per `rubric.md`.
```

- [ ] **Step 5: Run the validator to verify it passes**

Run: `python3 tests/validate.py`
Expected: `OK    11 check group(s) passed, 0 warning(s)`

- [ ] **Step 6: Update `README.md` and `.gitignore`**

Add to `README.md` after the `review-tools.sh` section that ends near `:77`:

```markdown
### NVD enrichment

`security-review` annotates every CVE its scanners find with that CVE's CVSS vector, CWE,
publication date and NVD analysis status, using `nvd-enrich.sh`. The score is evidence in the
finding, not the finding's severity: reachability decides severity, per `references/rubric.md`.

It works with no configuration. An API key only raises the rate limit, from 5 requests per 30
seconds to 50, which the script turns into a per-run lookup cap of 8 keyless and 50 keyed.

Get a free key at https://nvd.nist.gov/developers/request-an-api-key, then:

```
mkdir -p ~/.config/claude-review-suite
printf 'NVD_API_KEY=your-key-here\n' > ~/.config/claude-review-suite/nvd.env
chmod 600 ~/.config/claude-review-suite/nvd.env
```

The file must be mode 600 or 400. Anything looser is refused rather than read, with the `chmod`
printed, because a credential the whole machine can read is a finding this suite would report in
your code. `NVD_API_KEY` in the environment takes precedence over the file, which is the easier
route in CI.

Responses cache under `~/.cache/claude-review-suite/nvd`, for 7 days normally and 24 hours while a
record is still awaiting NVD analysis. Clear it with `rm -rf ~/.cache/claude-review-suite/nvd`.

Check the setup with `./nvd-enrich.sh --check`, which reports `curl`, `jq`, key source, cache size
and network reachability, and never prints the key itself.
```

Add to `.gitignore` under the editor noise section:

```
# Defensive: the API key belongs in ~/.config/claude-review-suite, never in the repo
nvd.env
```

- [ ] **Step 7: Run the full suite**

Run: `bash tests/run.sh`
Expected: every gate passes or skips; no `FAIL` lines. Specifically `PASS  nvd-enrich.sh behaves`, `PASS  shellcheck on this repo's own scripts`, and the validator reporting 11 check groups.

- [ ] **Step 8: Verify against the live API, once, by hand**

Every test so far used a shimmed `curl`. Confirm the real thing works before calling this done:

```bash
printf 'CVE-2021-44228\n' | ./nvd-enrich.sh
```

Expected: a row with provenance `live`, score `10.0`, and vector beginning `CVSS:3.1/`. Run it a second time and expect provenance `cache`. If you have not set up a key yet, this still works keyless.

- [ ] **Step 9: Commit**

```bash
git add skills/security-review/SKILL.md references/procedure.md tests/validate.py README.md .gitignore
git commit -m "feat: wire NVD enrichment into security-review with an enforced calibration rule"
```

---

## Done When

- `bash tests/run.sh` reports no `FAIL` lines.
- `python3 tests/validate.py` reports 11 check groups passing.
- `printf 'CVE-2021-44228\n' | ./nvd-enrich.sh` returns a `live` row against the real API, and a `cache` row on the second run.
- Deleting the "evidence, never severity" paragraph from `skills/security-review/SKILL.md` makes the validator fail. Verify this by deleting it, running the validator, and restoring it.
