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
