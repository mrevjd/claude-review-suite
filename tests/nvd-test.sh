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

# A key file with no matching NVD_API_KEY= line (empty, or comments only) must resolve to the
# normal keyless path, not crash. grep -m1 exits 1 when nothing matches; under pipefail that
# used to kill the whole script via set -e before resolve_key() ever reached its own "no key"
# return, so this asserts the exit code explicitly, not just the printed text.
printf '# comment only, no key here\n' >"$KEYFILE"
chmod 600 "$KEYFILE"
out=$(printf '' | bash "$SCRIPT" --check 2>&1)
rc=$?
if [[ $rc -eq 0 ]] && grep -qE '^key +absent' <<<"$out"; then
  ok "comment-only 0600 nvd.env is keyless, not a crash"
else
  bad "comment-only key file" "exit $rc, '$out'"
fi

: >"$KEYFILE"
chmod 600 "$KEYFILE"
out=$(printf '' | bash "$SCRIPT" --check 2>&1)
rc=$?
if [[ $rc -eq 0 ]] && grep -qE '^key +absent' <<<"$out"; then
  ok "zero-byte 0600 nvd.env is keyless, not a crash"
else
  bad "zero-byte key file" "exit $rc, '$out'"
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
out=$(printf '' | PATH="$BOX/nostat:$PATH" bash "$SCRIPT" --check 2>&1)
rc=$?
if [[ $rc -eq 0 ]] && grep -qE '^key +refused' <<<"$out"; then
  ok "stat unusable on both forms refuses instead of crashing"
else
  bad "file_mode fallback" "exit $rc, '$out'"
fi
chmod 600 "$KEYFILE"

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
out=$(printf 'CVE-2021-44228\n' | PATH="$BOX/nojq" NVD_TEST_BODY="$FIXTURES/scored.json" \
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

echo
if [[ $failures -gt 0 ]]; then
  echo "$failures nvd-enrich failure(s), $passes passed"
  exit 1
fi
echo "nvd-enrich tests passed ($passes checks)"
