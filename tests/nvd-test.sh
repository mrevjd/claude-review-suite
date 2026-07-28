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

# The second and third lines are the same CVE ID in two different cases, neither of which is
# already-canonical CVE-2021-44228. If uppercasing were skipped, both would fail CVE_RE (which
# requires an uppercase "CVE-" prefix) and get dropped instead of deduped, changing the output --
# a redundant already-uppercase duplicate here would let a broken uppercase step pass unnoticed.
out=$(printf 'not-a-cve\ncve-2021-44228\nCve-2021-44228\nCVE-2020-8203\n' \
  | bash "$SCRIPT" 2>/dev/null)
rc=$?
expected=$(printf 'CVE-2021-44228\nCVE-2020-8203')
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

echo
if [[ $failures -gt 0 ]]; then
  echo "$failures nvd-enrich failure(s), $passes passed"
  exit 1
fi
echo "nvd-enrich tests passed ($passes checks)"
