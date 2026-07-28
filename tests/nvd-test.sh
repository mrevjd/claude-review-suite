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

# --- network sentinel. cmd_check() gains a real network probe in this task, so from here on any
# curl invocation anywhere in this suite that is not explicitly routed through the shim above must
# still be unable to reach the real binary -- a test that forgets to put $BOX/bin ahead of it on
# PATH is exactly the bug this file already shipped once (Task 3, main()'s live fetch). Prepending
# this directory to the baseline PATH makes the omission harmless by construction: unshimmed calls
# resolve here instead of to the real curl, and never touch the network either way. The "network
# sentinel was never invoked" check at the end of this file turns a silent miss into a failure.
mkdir -p "$BOX/sentinel"
cat >"$BOX/sentinel/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >>"$SENTINEL_HITS"
exit 1
SHIM
chmod +x "$BOX/sentinel/curl"
export SENTINEL_HITS="$BOX/sentinel-hits"
: >"$SENTINEL_HITS"
export PATH="$BOX/sentinel:$PATH"

# Every test below that needs a genuinely live fetch (to check provenance, curl's argv, or a
# fetch_cve-internal mktemp call) must start from a cache with nothing in it for the CVE it uses.
# An earlier task tried tracking this by hand with per-call-site `rm -f` on one known cache file
# and still missed a case a test block later, because the invariant lived at each call site instead
# of in one place. Wiping the whole cache directory removes the need to reason about which earlier
# test last touched which CVE.
fresh_cache() { rm -rf "$XDG_CACHE_HOME/claude-review-suite/nvd"; }

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

# The second and third lines are the same CVE ID in two different cases, neither of which is
# already-canonical CVE-2021-44228. If uppercasing were skipped, both would fail CVE_RE (which
# requires an uppercase "CVE-" prefix) and get dropped instead of deduped, changing the output --
# a redundant already-uppercase duplicate here would let a broken uppercase step pass unnoticed.
#
# curl is shimmed (PATH) with no NVD_TEST_BODY, so the shim leaves the response empty and every
# row comes back "unavailable" -- this test is about the accept path (uppercase/dedup/order/drop),
# not about fetched content, and it must never reach the real network to prove that. A pre-existing
# cache hit for CVE-2021-44228 would print real cached data here instead of "unavailable", so this
# starts from a cold cache rather than relying on being the first test to touch it.
# NVD_MAX_LOOKUPS=1 (added by Task 5): two unique CVEs survive dedup here, and without a cap the
# second would be spaced out by the keyless SPACING=6 sleep -- unrelated to what this test checks
# and it would still assert the same "unavailable" row either way, since the cap path and the
# empty-body-parse-failure path both print the identical dashed row.
fresh_cache
out=$(printf 'not-a-cve\ncve-2021-44228\nCve-2021-44228\nCVE-2020-8203\n' \
  | PATH="$BOX/bin:$PATH" NVD_MAX_LOOKUPS=1 bash "$SCRIPT" 2>/dev/null)
rc=$?
expected=$(printf 'CVE-2021-44228\t-\t-\t-\t-\t-\t-\tunavailable\nCVE-2020-8203\t-\t-\t-\t-\t-\t-\tunavailable')
if [[ "$out" == "$expected" && $rc -eq 0 ]]; then
  ok "accept path: uppercased, deduped, order preserved, exit 0"
else
  bad "accept path" "exit $rc, got '$out'"
fi

err=$(printf 'not-a-cve\nCVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" 2>&1 >/dev/null)
if grep -q 'not-a-cve' <<<"$err"; then
  ok "invalid CVE ID is dropped with a note on stderr"
else
  bad "invalid CVE" "stderr did not name the dropped ID: '$err'"
fi

# ---------------------------------------------------------------- key resolution
mkdir -p "$XDG_CONFIG_HOME/claude-review-suite"
KEYFILE="$XDG_CONFIG_HOME/claude-review-suite/nvd.env"
SECRET="TESTKEY-a1b2c3d4-e5f6-7890-abcd-ef1234567890"

printf '# comment line\nNVD_API_KEY=%s\n' "$SECRET" >"$KEYFILE"
chmod 600 "$KEYFILE"

out=$(printf '' | PATH="$BOX/bin:$PATH" bash "$SCRIPT" --check 2>&1)
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
if [[ $(wc -l <<<"$out") -eq 5 ]]; then
  ok "--check prints exactly five lines with a readable key file (2>&1)"
else
  bad "--check line count, key present (nvd.env)" "got $(wc -l <<<"$out")"
fi

out=$(printf '' | PATH="$BOX/bin:$PATH" NVD_API_KEY=env-wins-key bash "$SCRIPT" --check 2>&1)
if grep -qE '^key +present \(env\)' <<<"$out"; then
  ok "\$NVD_API_KEY takes precedence over the file"
else
  bad "env precedence" "'$out'"
fi
if [[ $(wc -l <<<"$out") -eq 5 ]]; then
  ok "--check prints exactly five lines with \$NVD_API_KEY set (2>&1)"
else
  bad "--check line count, key present (env)" "got $(wc -l <<<"$out")"
fi

# resolve_key's permission-refusal branch warns on stderr (nvd-enrich.sh:69-76). Every pre-existing
# invocation in this file merges stderr with 2>&1, the same convention the brief's own --check test
# uses, so a stray warn() here is not hypothetical: it is the only way any caller in this codebase
# observes --check's output. cmd_check must silence resolve_key's stderr on this path specifically,
# so the "exactly five lines" contract holds under 2>&1 even when the key file is refused, not just
# in states where resolve_key has nothing to warn about.
chmod 644 "$KEYFILE"
out=$(printf '' | PATH="$BOX/bin:$PATH" bash "$SCRIPT" --check 2>&1)
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
if [[ $(wc -l <<<"$out") -eq 5 ]]; then
  ok "--check prints exactly five lines on a refused key, not six with resolve_key's warning (2>&1)"
else
  bad "--check line count, key refused" "got $(wc -l <<<"$out") lines: '$out'"
fi
chmod 600 "$KEYFILE"

# A key file with no matching NVD_API_KEY= line (empty, or comments only) must resolve to the
# normal keyless path, not crash. grep -m1 exits 1 when nothing matches; under pipefail that
# used to kill the whole script via set -e before resolve_key() ever reached its own "no key"
# return, so this asserts the exit code explicitly, not just the printed text.
printf '# comment only, no key here\n' >"$KEYFILE"
chmod 600 "$KEYFILE"
out=$(printf '' | PATH="$BOX/bin:$PATH" bash "$SCRIPT" --check 2>&1)
rc=$?
if [[ $rc -eq 0 ]] && grep -qE '^key +absent' <<<"$out"; then
  ok "comment-only 0600 nvd.env is keyless, not a crash"
else
  bad "comment-only key file" "exit $rc, '$out'"
fi
if [[ $(wc -l <<<"$out") -eq 5 ]]; then
  ok "--check prints exactly five lines with a comment-only key file (2>&1)"
else
  bad "--check line count, comment-only key file" "got $(wc -l <<<"$out")"
fi

: >"$KEYFILE"
chmod 600 "$KEYFILE"
out=$(printf '' | PATH="$BOX/bin:$PATH" bash "$SCRIPT" --check 2>&1)
rc=$?
if [[ $rc -eq 0 ]] && grep -qE '^key +absent' <<<"$out"; then
  ok "zero-byte 0600 nvd.env is keyless, not a crash"
else
  bad "zero-byte key file" "exit $rc, '$out'"
fi
if [[ $(wc -l <<<"$out") -eq 5 ]]; then
  ok "--check prints exactly five lines with a zero-byte key file (2>&1)"
else
  bad "--check line count, zero-byte key file" "got $(wc -l <<<"$out")"
fi

# Shadow stat with a script that always fails, standing in for a stat that supports neither the
# GNU (-c) nor the BSD (-f) form. file_mode() must yield an empty mode that the permission case
# statement's default branch refuses, not a set -e crash before that branch ever runs.
mkdir -p "$BOX/nostat"
cat >"$BOX/nostat/stat" <<'SHIM'
#!/bin/sh
exit 1
SHIM
chmod +x "$BOX/nostat/stat"

printf 'NVD_API_KEY=%s\n' "$SECRET" >"$KEYFILE"
chmod 600 "$KEYFILE"
out=$(printf '' | PATH="$BOX/nostat:$BOX/bin:$PATH" bash "$SCRIPT" --check 2>&1)
rc=$?
if [[ $rc -eq 0 ]] && grep -qE '^key +refused' <<<"$out"; then
  ok "stat unusable on both forms refuses instead of crashing"
else
  bad "file_mode fallback" "exit $rc, '$out'"
fi
if [[ $(wc -l <<<"$out") -eq 5 ]]; then
  ok "--check prints exactly five lines when stat is unusable and the key is refused (2>&1)"
else
  bad "--check line count, stat-fallback refusal" "got $(wc -l <<<"$out") lines: '$out'"
fi
chmod 600 "$KEYFILE"

# Five-line coverage across --check's states: key present (env, nvd.env), key refused (via a bad
# permission bit above, and again via an unusable stat), and key absent (comment-only, zero-byte)
# are all asserted above. Cache state needs no dedicated assertion anywhere in this file: cmd_check
# reports the cache with exactly one printf, unconditionally, so a missing directory, an empty one,
# and a populated one all still produce that same single line -- just with different text inside it
# -- and no cache state can add or remove a line. Network-unreachable has no dedicated assertion
# either, for the same shape of reason: cmd_check's curl probe redirects both stdout and stderr to
# /dev/null regardless of whether the request succeeds or fails, so there is no code path on that
# branch that could add or drop a line the way resolve_key's warn() did before it was silenced.

# This section is the only producer of a real key file in this suite -- every later test that
# wants a keyed run passes NVD_API_KEY inline instead, which overrides the file regardless of its
# contents. Nothing downstream has a legitimate reason to see this key, so the section that dirtied
# it cleans up after itself here, structurally, rather than relying on whichever section happens to
# run last to remember to do it. That "last section remembers" shape is exactly what went wrong
# with the cache before fresh_cache() existed: an append-only file where every block runs after the
# one before it, so cleanup-at-first-use-downstream silently stops covering new tests inserted in
# between. rm here instead of a fresh_cache()-style pull helper, because unlike the cache -- where
# different tests legitimately want a hit or a miss -- no test in this file wants a leftover key.
rm -f "$KEYFILE"

# ---------------------------------------------------------------- fetch and parse
# The "invalid CVE ID" test above already populated the cache for CVE-2021-44228 by fetching it
# with scored.json. Each test below needs a real, uncached fetch to prove what it claims (a live
# parse, a key that never reaches curl's argv, a mktemp failure inside fetch_cve), so each starts
# from fresh_cache() -- otherwise a leftover cache hit would skip fetch_cve entirely and let a
# broken fetch path pass unnoticed.

# jq normalizes JSON numbers to their shortest round-trip decimal form: a whole-number double such
# as 10.0 always prints as "10", never "10.0", in every jq version (this is not the jq 1.7 literal-
# number-preservation feature, which only applies to values that cannot round-trip through a
# double). scored.json's baseScore is CVE-2021-44228's real, published CVSS score, so "10" here is
# the correct output for that value, not a bug in parse_response.
fresh_cache
expected=$(printf 'CVE-2021-44228\t10\tCRITICAL\tCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\tCWE-917\t2021-12-10\tModified\tlive')
row=$(printf 'CVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" NVD_TEST_CODE=200 bash "$SCRIPT" 2>/dev/null)
if [[ "$row" == "$expected" ]]; then
  ok "scored CVE produces the expected TSV row"
else
  bad "scored row" "got '$row'"
fi

# The key must reach curl through a config file, never argv: /proc/<pid>/cmdline is world-readable.
# The "scored row" test just above leaves a fresh cache entry behind; cleared again here so this
# run also goes through fetch_cve rather than short-circuiting on a cache hit before curl even runs.
fresh_cache
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
# This PATH replaces the baseline outright (no ":$PATH" suffix) rather than extending it, so the
# sentinel prepended onto that baseline earlier in this file drops out here too -- the one place in
# this suite where the "every invocation is covered by construction" property doesn't hold on its
# own. It is harmless today only because jq is checked before curl in main(), so the script exits
# before curl would ever run, and because the curl symlink above already points at the real shim
# rather than nothing. Appending the sentinel here removes the reliance on both of those staying
# true: jq is still genuinely absent (the sentinel directory has no jq in it either), so this
# assertion's own condition is untouched, but a future edit that reorders main()'s checks or drops
# the curl symlink now fails the "sentinel never invoked" check instead of quietly falling through
# to the real network.
out=$(printf 'CVE-2021-44228\n' | PATH="$BOX/nojq:$BOX/sentinel" NVD_TEST_BODY="$FIXTURES/scored.json" \
  bash "$SCRIPT" 2>/dev/null)
rc=$?
if [[ $rc -eq 1 && -z "$out" ]]; then
  ok "a missing jq exits 1 with no partial output"
else
  bad "jq absent" "exit $rc, output '$out'"
fi

# A key config file that fails to build must warn, not silently send the request keyless. The
# shim below fails mktemp only when its argv names the cfg allocation specifically (nvd-enrich.sh
# tags every mktemp call with a distinguishing template: nvd-body, nvd-hdrs, nvd-cfg), not by
# counting which call in-process this is. A count breaks the moment a call is added, removed, or
# reordered anywhere in the script -- or, for cfg specifically, the moment a keyed run retries and
# calls fetch_cve (and so mktemp) a second time -- silently retargeting the fault onto whichever
# allocation now happens to sit at that ordinal position instead of the one this test names.
REAL_MKTEMP="$(command -v mktemp)"
mkdir -p "$BOX/failcfg"
cat >"$BOX/failcfg/mktemp" <<SHIM
#!/bin/sh
case "\$*" in
  *nvd-cfg*)
    echo "mktemp: no space left on device" >&2
    exit 1
    ;;
esac
exec "$REAL_MKTEMP" "\$@"
SHIM
chmod +x "$BOX/failcfg/mktemp"
# The "key on argv" test above left a fresh cache entry behind too; without clearing it, this run
# would hit the cache, never call fetch_cve or its cfg mktemp, and this test would pass for free.
fresh_cache
err=$(printf 'CVE-2021-44228\n' | PATH="$BOX/failcfg:$BOX/bin:$PATH" NVD_API_KEY="$SECRET" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" 2>&1 >/dev/null)
if grep -q 'could not create the key config file' <<<"$err"; then
  ok "a failed key-config mktemp warns instead of silently going keyless"
else
  bad "cfg mktemp fallback" "stderr: '$err'"
fi

# ---------------------------------------------------------------- cache
# The "cfg mktemp fallback" test above left its own fresh cache entry for CVE-2021-44228 behind, so
# without this the first invocation below would already be a cache hit and never prove the "then a
# cache hit" half of this test's name -- it needs to start genuinely cold so the first invocation is
# a real, populating fetch (first_calls -eq 1) and only the second is served from disk.
fresh_cache
: >"$CALLS"
printf 'CVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" >/dev/null 2>&1
first_calls=$(wc -l <"$CALLS")
row=$(printf 'CVE-2021-44228\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" 2>/dev/null)
second_calls=$(wc -l <"$CALLS")
if [[ "$row" == *$'\t'cache ]] && [[ "$first_calls" -eq 1 ]] && [[ "$first_calls" -eq "$second_calls" ]]; then
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

# Metric preference: cvssMetricV31 must win over cvssMetricV40 when both are present. scored.json
# only ever carries one metric type, so nothing before this could catch the chain being reordered
# (e.g. v4.0 checked before v3.1); this fixture carries both, with deliberately different scores.
row=$(printf 'CVE-2026-22222\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/prefers-v31-over-v40.json" bash "$SCRIPT" 2>/dev/null)
expected=$(printf 'CVE-2026-22222\t9.8\tCRITICAL\tCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\t-\t2026-01-15\tAnalyzed\tlive')
if [[ "$row" == "$expected" ]]; then
  ok "cvssMetricV31 is preferred over cvssMetricV40 when both are present"
else
  bad "metric preference" "got '$row'"
fi

# CVSS v2 puts baseSeverity on the metric object, not inside cvssData, so parse_response falls
# back to $mm.baseSeverity. This is the only fixture exercising that fallback.
row=$(printf 'CVE-2026-33333\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/only-cvssv2-metric.json" bash "$SCRIPT" 2>/dev/null)
if [[ "$row" == *$'\t'MEDIUM$'\t'* ]]; then
  ok "a CVSS v2-only record reads baseSeverity from the metric object, not cvssData"
else
  bad "cvssMetricV2 severity fallback" "got '$row'"
fi

# ---------------------------------------------------------------- unresolvable input
# Keyless from here on: the key-resolution section above now cleans up its own $KEYFILE when it
# finishes, so every test below runs in genuine keyless mode without needing to know that history.
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
SECONDS=0
err=$(printf 'CVE-2020-0006\n' | PATH="$BOX/bin:$PATH" NVD_TEST_CODE=403 \
  NVD_TEST_RETRY_AFTER=1 NVD_TEST_BODY="$FIXTURES/empty.json" bash "$SCRIPT" 2>&1 >/dev/null)
elapsed=$SECONDS
# Call count and the "rate" text on stderr are both still true if the code ignored Retry-After and
# fell through to its hardcoded 10s/30s default -- only the elapsed time tells the two apart. The
# bound is well above the 1s this run should take and well below the 10s/30s default, so it is
# tight enough to catch a regression to the hardcoded value without making a correct run flaky.
if [[ $(wc -l <"$CALLS") -eq 2 ]] && grep -qi 'rate' <<<"$err" && [[ "$elapsed" -lt 4 ]]; then
  ok "a 403 is retried once, honouring Retry-After, then reported"
else
  bad "rate-limit retry" "$(wc -l <"$CALLS") call(s), ${elapsed}s elapsed, stderr '$err'"
fi

# Retry-After may legally be an HTTP-date instead of delta-seconds (RFC 7231); tr -dc would
# otherwise concatenate every digit in the date into a sleep of hundreds of billions of seconds.
# Proving the fallback fires by actually waiting out either the correct ~10-30s default or, on a
# regression, the near-eternal one would make this test slow at best and hang the suite at worst,
# so sleep itself is shimmed to record its argument instead of actually sleeping -- this asserts on
# the exact value the retry logic decided to use, deterministically and immediately.
cat >"$BOX/bin/sleep" <<'SHIM'
#!/bin/sh
printf '%s\n' "$1" >>"$SLEEPS"
exit 0
SHIM
chmod +x "$BOX/bin/sleep"
export SLEEPS="$BOX/sleeps"
: >"$SLEEPS"

: >"$CALLS"
printf 'CVE-2020-0007\n' | PATH="$BOX/bin:$PATH" NVD_TEST_CODE=403 \
  NVD_TEST_RETRY_AFTER='Wed, 21 Oct 2015 07:28:00 GMT' NVD_TEST_BODY="$FIXTURES/empty.json" \
  bash "$SCRIPT" >/dev/null 2>&1
backoff_used=$(cat "$SLEEPS")
if [[ "$backoff_used" =~ ^[0-9]{1,4}$ ]]; then
  ok "an HTTP-date-form Retry-After falls back to the sane default, not a concatenated near-eternal sleep"
else
  bad "Retry-After date form" "computed backoff was '$backoff_used'"
fi

# ---------------------------------------------------------------- rate-limit stop
# Every shim from here on lives in its own directory prepended ahead of $BOX/bin rather than
# overwriting $BOX/bin/curl. Overwriting it would silently change the curl every *later* test in this
# append-only file sees, which is the same "whichever section ran last decides" coupling that
# fresh_cache() and the key-file cleanup above exist to remove.
#
# A retry that is rate-limited too means the run is over NVD's allowance, so the remaining CVEs are
# short-circuited. Before that existed, a sustained 403 retried every CVE independently: a 3-CVE batch
# at NVD_MAX_LOOKUPS=2 made four requests and slept 30, 6, 30 against an API that had already said
# back off, printing nothing until the end.
mkdir -p "$BOX/bin403"
cat >"$BOX/bin403/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >>"$CALLS"
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *)  shift ;;
  esac
done
[ -n "$out" ] && : >"$out"
printf '403'
exit 0
SHIM
chmod +x "$BOX/bin403/curl"

# Deliberately left at the keyless default cap of 8 rather than the NVD_MAX_LOOKUPS=2 the defect was
# first reported under. At a cap of 2 the cap itself bounds the run to two requests, so the run-ending
# short-circuit and its absence are indistinguishable and this assertion cannot fail. Above the cap,
# the two diverge sharply: stopping is 2 requests and 1 sleep, while retrying each CVE independently
# is 6 requests and 5 sleeps (three backoffs plus two spacing waits).
fresh_cache
: >"$CALLS"
: >"$SLEEPS"
out=$(printf 'CVE-2020-0101\nCVE-2020-0102\nCVE-2020-0103\n' \
  | PATH="$BOX/bin403:$BOX/bin:$PATH" bash "$SCRIPT" 2>"$BOX/err-403")
# All three rows are still emitted, because one input CVE means one output row on every path.
if [[ $(wc -l <"$CALLS") -eq 2 ]] && [[ $(wc -l <"$SLEEPS") -eq 1 ]] \
  && [[ $(wc -l <<<"$out") -eq 3 ]] \
  && grep -q 'remaining CVEs will not be requested' "$BOX/err-403"; then
  ok "a retry that is rate-limited too marks the remainder unavailable instead of retrying each CVE"
else
  bad "rate-limit stop" "$(wc -l <"$CALLS") request(s), $(wc -l <"$SLEEPS") sleep(s), \
$(wc -l <<<"$out") row(s), stderr '$(cat "$BOX/err-403")'"
fi

# The other half of the same change, and the half the assertion above cannot see: a retry spends
# budget like any other request. The shim below 403s the first request and answers every later one, so
# the retry *succeeds* and the run-ending short-circuit never fires -- the only thing left deciding the
# outcome is whether the retry was charged. Charged: CVE-2020-0171 finds the cap of 2 already spent and
# comes back unavailable, for two requests total. Uncharged (the old behaviour, counting CVEs): it gets
# a third request and a live row, which is how a retrying run made roughly twice the documented cap.
jq '.vulnerabilities[0].cve.id = "CVE-2020-0171"' "$FIXTURES/scored.json" >"$BOX/rec-0171.json"
mkdir -p "$BOX/bin403once"
cat >"$BOX/bin403once/curl" <<SHIM
#!/bin/sh
printf '%s\n' "\$*" >>"\$CALLS"
out=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    *)  shift ;;
  esac
done
[ -n "\$out" ] && : >"\$out"
if [ "\$(wc -l <"\$CALLS")" -eq 1 ]; then
  printf '403'
  exit 0
fi
[ -n "\$out" ] && cp "$BOX/rec-0171.json" "\$out"
printf '200'
exit 0
SHIM
chmod +x "$BOX/bin403once/curl"

fresh_cache
: >"$CALLS"
: >"$SLEEPS"
rows=$(printf 'CVE-2020-0170\nCVE-2020-0171\n' | PATH="$BOX/bin403once:$BOX/bin:$PATH" \
  NVD_MAX_LOOKUPS=2 bash "$SCRIPT" 2>/dev/null)
if [[ $(wc -l <"$CALLS") -eq 2 ]] && [[ "$(sed -n 2p <<<"$rows")" == *$'\t'unavailable ]]; then
  ok "a retry is charged against the request cap, so a retrying run cannot exceed the documented cap"
else
  bad "retry is charged" "$(wc -l <"$CALLS") request(s), rows '$rows'"
fi

# A 429 whose body dies mid-transfer: curl writes the status through -w *and* exits non-zero, so
# nvd-enrich.sh's own `|| printf '000'` appends to what curl already printed and the capture is
# "429000". That equalled none of the values tested downstream, so the retry the spec mandates never
# fired on exactly the truncated response most likely to be carrying a rate limit.
mkdir -p "$BOX/bintrunc"
cat >"$BOX/bintrunc/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >>"$CALLS"
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *)  shift ;;
  esac
done
[ -n "$out" ] && : >"$out"
printf '429000'
exit 18
SHIM
chmod +x "$BOX/bintrunc/curl"

fresh_cache
: >"$CALLS"
printf 'CVE-2020-0160\n' | PATH="$BOX/bintrunc:$BOX/bin:$PATH" bash "$SCRIPT" >/dev/null 2>&1
if [[ $(wc -l <"$CALLS") -eq 2 ]]; then
  ok "a 429 whose transfer broke mid-body is still read as a 429 and retried"
else
  bad "truncated status code" "$(wc -l <"$CALLS") request(s), expected 2"
fi

# ---------------------------------------------------------------- unresolved diagnostics
# skills/security-review/SKILL.md tells the agent to name NVD enrichment in "## Checks skipped" "with
# the reason the script reported on stderr", listing an unreachable network among the reasons. A curl
# that cannot reach the network used to produce dashed rows and a completely empty stderr, so that
# instruction could not be followed as written.
mkdir -p "$BOX/bindead"
cat >"$BOX/bindead/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >>"$CALLS"
exit 6
SHIM
chmod +x "$BOX/bindead/curl"

fresh_cache
: >"$CALLS"
err=$(printf 'CVE-2020-0111\nCVE-2020-0112\n' | PATH="$BOX/bindead:$BOX/bin:$PATH" \
  bash "$SCRIPT" 2>&1 >/dev/null)
if grep -q '2 CVE(s) could not be enriched' <<<"$err" && grep -q 'no response from NVD' <<<"$err"; then
  ok "a network failure reports a count and a reason on stderr, not silence"
else
  bad "unresolved diagnostic" "stderr: '$err'"
fi

# ---------------------------------------------------------------- cache past the cap
# The cap bounds *network* work, and reading a file already on disk is not network work, so a stale
# entry must still be served once the budget is spent. Discarding it printed a dashed row for a CVE
# the script had an answer for on disk, in the exact scenario the cache exists for: a large repository
# reviewed more than once. NVD_MAX_LOOKUPS=0 is the sharpest form of the test, because it also asserts
# that serving the stale row costs no request at all.
STALE_CACHE="$XDG_CACHE_HOME/claude-review-suite/nvd"
fresh_cache
mkdir -p "$STALE_CACHE"
# scored.json names CVE-2021-44228, and parse_response now refuses a record that does not name the CVE
# it was asked about. Rewriting the id keeps this test about the stale fallback rather than about that
# guard, which has its own assertions below.
jq '.vulnerabilities[0].cve.id = "CVE-2020-0121"' "$FIXTURES/scored.json" \
  >"$STALE_CACHE/CVE-2020-0121.json"
touch -d '30 days ago' "$STALE_CACHE/CVE-2020-0121.json" 2>/dev/null \
  || touch -t 202606010000 "$STALE_CACHE/CVE-2020-0121.json"
: >"$CALLS"
rows=$(printf 'CVE-2020-0120\nCVE-2020-0121\n' | PATH="$BOX/bin:$PATH" NVD_MAX_LOOKUPS=0 \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" 2>/dev/null)
if [[ "$(sed -n 2p <<<"$rows")" == *$'\t'cache-stale ]] \
  && [[ "$(sed -n 1p <<<"$rows")" == *$'\t'unavailable ]] \
  && [[ ! -s "$CALLS" ]]; then
  ok "a stale cache entry is served past the request cap rather than discarded for a dashed row"
else
  bad "stale past the cap" "rows '$rows', $(wc -l <"$CALLS") request(s)"
fi

# ---------------------------------------------------------------- response identity
# $body is one file reused for every CVE in the batch. A curl that returns 200 without writing it --
# a transfer that died before the first body byte -- used to make the next CVE emit the *previous*
# CVE's complete row, identical in every column including a `live` provenance, and write that record
# to its cache file for seven days. The requested CVE vanished from the output entirely.
jq '.vulnerabilities[0].cve.id = "CVE-2020-0130"' "$FIXTURES/scored.json" >"$BOX/rec-0130.json"
mkdir -p "$BOX/binonce"
cat >"$BOX/binonce/curl" <<SHIM
#!/bin/sh
printf '%s\n' "\$*" >>"\$CALLS"
out=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    *)  shift ;;
  esac
done
if [ "\$(wc -l <"\$CALLS")" -eq 1 ] && [ -n "\$out" ]; then
  cp "$BOX/rec-0130.json" "\$out"
fi
printf '200'
exit 0
SHIM
chmod +x "$BOX/binonce/curl"

fresh_cache
: >"$CALLS"
rows=$(printf 'CVE-2020-0130\nCVE-2020-0131\n' | PATH="$BOX/binonce:$BOX/bin:$PATH" \
  bash "$SCRIPT" 2>/dev/null)
if [[ "$(sed -n 2p <<<"$rows")" == "CVE-2020-0131"$'\t-\t-\t-\t-\t-\t-\t'unavailable ]] \
  && [[ ! -f "$STALE_CACHE/CVE-2020-0131.json" ]]; then
  ok "a 200 that writes no body cannot emit or cache the previous CVE's record"
else
  bad "body reuse" "rows '$rows', cache entry for 0131 \
$([[ -f "$STALE_CACHE/CVE-2020-0131.json" ]] && echo written || echo absent)"
fi

# $HDRS is reused across the batch exactly as $body is, and its reuse *is* independently observable,
# because nothing cross-checks a header file against the CVE it came from the way parse_response now
# checks the record's id. The shim below rate-limits the first CVE with a Retry-After of 1, answers its
# retry, then rate-limits the second CVE with a response carrying no headers at all. The second CVE's
# backoff must be the keyless default of 30, not the 1 second left behind in the file by the first.
mkdir -p "$BOX/binhdrs"
cat >"$BOX/binhdrs/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >>"$CALLS"
dump=""
while [ $# -gt 0 ]; do
  case "$1" in
    -D) dump="$2"; shift 2 ;;
    *)  shift ;;
  esac
done
case "$(wc -l <"$CALLS")" in
  1) [ -n "$dump" ] && printf 'HTTP/2 403\r\nRetry-After: 1\r\n\r\n' >"$dump"
     printf '403' ;;
  3) printf '403' ;;
  *) printf '200' ;;
esac
exit 0
SHIM
chmod +x "$BOX/binhdrs/curl"

fresh_cache
: >"$CALLS"
: >"$SLEEPS"
printf 'CVE-2020-0180\nCVE-2020-0181\n' | PATH="$BOX/binhdrs:$BOX/bin:$PATH" \
  bash "$SCRIPT" >/dev/null 2>&1
# In order: the first CVE's Retry-After of 1, the 6s keyless spacing before the second CVE, then the
# second CVE's backoff. A leaked header file makes that third value 1.
if [[ $(wc -l <"$SLEEPS") -eq 3 ]] && [[ "$(sed -n 3p "$SLEEPS")" == "30" ]]; then
  ok "a response carrying no Retry-After cannot inherit the previous CVE's header file"
else
  bad "header file reuse" "sleeps were '$(tr '\n' ' ' <"$SLEEPS")', expected '1 6 30'"
fi

# The other half of the same invariant, and the one that does not depend on any external binary
# behaving well: the response body is not trusted to say which CVE it describes. scored.json names
# CVE-2021-44228, so asking for anything else must produce no row from it and no cache entry.
fresh_cache
: >"$CALLS"
row=$(printf 'CVE-2020-0140\n' | PATH="$BOX/bin:$PATH" \
  NVD_TEST_BODY="$FIXTURES/scored.json" bash "$SCRIPT" 2>/dev/null)
if [[ "$row" == "CVE-2020-0140"$'\t-\t-\t-\t-\t-\t-\t'unavailable ]] \
  && [[ ! -f "$STALE_CACHE/CVE-2020-0140.json" ]]; then
  ok "a record naming a different CVE than the one requested is refused, not emitted or cached"
else
  bad "response identity" "row '$row', cache entry for 0140 \
$([[ -f "$STALE_CACHE/CVE-2020-0140.json" ]] && echo written || echo absent)"
fi

# ---------------------------------------------------------------- NVD_MAX_LOOKUPS validation
# A non-numeric value did not degrade gracefully, it removed the cap: `[ "$n" -ge abc ]` printed
# "integer expression expected" once per CVE and evaluated false every time, so a typo in the one
# setting standing between a 200-CVE repository and a twenty minute review made it unbounded.
fresh_cache
err=$(printf 'CVE-2020-0150\n' | PATH="$BOX/bin:$PATH" NVD_MAX_LOOKUPS=abc \
  NVD_TEST_BODY="$FIXTURES/empty.json" bash "$SCRIPT" 2>&1 >/dev/null)
if grep -q "NVD_MAX_LOOKUPS='abc'" <<<"$err" && grep -q 'default cap of 8' <<<"$err" \
  && ! grep -q 'integer expression expected' <<<"$err"; then
  ok "a non-numeric NVD_MAX_LOOKUPS warns and keeps the default cap instead of disabling it"
else
  bad "NVD_MAX_LOOKUPS validation" "stderr: '$err'"
fi

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

# An absent curl reported as an unreachable network made two lines of the same five-line report
# contradict each other, and sent the reader looking for a firewall over a missing binary.
#
# Like the "missing jq" test above, this PATH replaces the baseline outright rather than extending it,
# so the sentinel prepended earlier drops out with it. That is unavoidable and harmless here for a
# stronger reason than in the jq case: the whole premise of the test is that no curl binary of any
# kind is reachable on this PATH, sentinel or real, so there is no request for a leak to escape
# through. If a curl ever did appear on it, the assertion below would fail rather than go quiet.
mkdir -p "$BOX/nocurl"
for b in bash sh grep sed tr cut cat mktemp stat date find wc rm cp touch jq; do
  p="$(command -v "$b" 2>/dev/null)" && ln -sf "$p" "$BOX/nocurl/$b"
done
out=$(PATH="$BOX/nocurl" bash "$SCRIPT" --check 2>&1 </dev/null)
if grep -qE '^curl +absent' <<<"$out" && grep -qE '^network +unknown \(curl absent\)' <<<"$out" \
  && [[ $(wc -l <<<"$out") -eq 5 ]]; then
  ok "--check reports an unknown network, not an unreachable one, when curl is absent"
else
  bad "--check network line with curl absent" "'$out'"
fi

# A trailing argument is a usage error, not something to ignore. `--check junk` silently dropping
# "junk" hides a typo in the one command whose entire job is reporting the truth, and exit 2 is what
# the unknown-option path already does.
out=$(PATH="$BOX/bin:$PATH" bash "$SCRIPT" --check junk 2>&1 </dev/null)
rc=$?
if [[ $rc -eq 2 ]] && ! grep -qE '^curl +' <<<"$out"; then
  ok "--check with a trailing argument exits 2 instead of ignoring it"
else
  bad "--check trailing argument" "exit $rc, output '$out'"
fi

# ---------------------------------------------------------------- network sentinel
# Checked last, after every test above has run, so it catches a leak from anywhere in this file --
# not just the six --check call sites this task found unshimmed -- rather than only the ones this
# section happens to know about.
if [[ -s "$SENTINEL_HITS" ]]; then
  bad "no test reaches the real network" "sentinel curl was invoked: $(cat "$SENTINEL_HITS")"
else
  ok "no test in this suite reaches the real network (sentinel curl was never invoked)"
fi

echo
if [[ $failures -gt 0 ]]; then
  echo "$failures nvd-enrich failure(s), $passes passed"
  exit 1
fi
echo "nvd-enrich tests passed ($passes checks)"
