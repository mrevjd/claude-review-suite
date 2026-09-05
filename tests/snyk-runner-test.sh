#!/usr/bin/env bash
# Tests the exit-code contract of `review-tools.sh snyk`. No network and no real snyk: a fake snyk
# is shimmed onto PATH ahead of the real one, the same technique tests/nvd-test.sh uses for curl.
#
# The contract is the whole point of the subcommand. Its output already says which scans ran, but a
# caller that gates on the exit code cannot read prose, and this suite's founding rule is that a
# check which did not run is never reported as a pass. The case that matters most is the partial
# run: one scan clean, one skipped. That shipped as exit 0 -- indistinguishable from a complete
# clean scan -- and it was the default outcome on any account without Snyk Code enabled, because
# `snyk code test` is refused there while `snyk test` succeeds.
#
# Run with: bash tests/snyk-runner-test.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/review-tools.sh"

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
mkdir -p "$BOX/bin" "$BOX/scan"

# --- fake snyk. Each behaviour is driven by an environment variable, so a case declares the shape
# of the run rather than the bytes of the output:
#   FAKE_AUTH=0|1     what `snyk whoami` exits
#   FAKE_TEST=<n>     what `snyk test` exits
#   FAKE_CODE=<n>     what `snyk code test` exits
#   FAKE_CODE_BODY    text `snyk code test` prints, so the SNYK-CODE-0005 branch can be reached
cat >"$BOX/bin/snyk" <<'SHIM'
#!/bin/sh
case "$1" in
  whoami)    [ "${FAKE_AUTH:-0}" -eq 0 ] && { echo "fake-user"; exit 0; }; echo "not authed" >&2; exit 2 ;;
  --version) echo "0.0.0-fake"; exit 0 ;;
  code)      printf '%s\n' "${FAKE_CODE_BODY:-fake code output}"; exit "${FAKE_CODE:-0}" ;;
  test)      echo "fake test output"; exit "${FAKE_TEST:-0}" ;;
esac
echo "unexpected argv: $*" >&2
exit 90
SHIM
chmod +x "$BOX/bin/snyk"

# A PATH with no snyk at all, for the ABSENT case. Built from the real PATH minus any directory
# holding a snyk, so the case cannot pass merely because the harness guessed the install dir wrong.
NO_SNYK_PATH=""
IFS=':' read -r -a path_parts <<<"$PATH"
for part in "${path_parts[@]}"; do
  [ -z "$part" ] && continue
  [ -x "$part/snyk" ] && continue
  NO_SNYK_PATH="${NO_SNYK_PATH:+$NO_SNYK_PATH:}$part"
done

# expect <exit> <label> [VAR=VAL ...] -- run the subcommand with the fake on PATH and check the code.
#
# The fake's PATH goes first so a case can override it with one of its own: `env` applies
# assignments left to right, so the last one wins. Written the other way round, the ABSENT case
# silently kept the fake on PATH, both scans ran clean, and it asserted 2 against a 0.
expect() {
  local want="$1" label="$2"
  shift 2
  local got
  env PATH="$BOX/bin:$PATH" "$@" "$SCRIPT" snyk "$BOX/scan" >/dev/null 2>&1
  got=$?
  if [ "$got" -eq "$want" ]; then
    ok "$label (exit $got)"
  else
    bad "$label" "expected exit $want, got $got"
  fi
}

echo "snyk runner exit-code contract"

expect 2 "snyk absent: both scans SKIP, never a pass" PATH="$NO_SNYK_PATH"

expect 2 "snyk present but unauthenticated: both scans SKIP" FAKE_AUTH=1

expect 0 "both scans ran clean" FAKE_TEST=0 FAKE_CODE=0

expect 1 "dependency findings" FAKE_TEST=1 FAKE_CODE=0

expect 1 "source findings" FAKE_TEST=0 FAKE_CODE=1

expect 1 "findings outrank a skipped scan" FAKE_TEST=1 FAKE_CODE=2

expect 2 "neither scan ran" FAKE_TEST=3 FAKE_CODE=2

# The regression. A clean dependency scan beside a skipped source scan is not a clean run, and the
# exit code has to say so on its own: the caller reading it cannot see the SKIP line above it.
expect 3 "one scan clean, one skipped: incomplete, not clean" \
  FAKE_TEST=0 FAKE_CODE=2 FAKE_CODE_BODY="ERROR Snyk Code is not enabled (SNYK-CODE-0005)"

expect 3 "one scan clean, one with no supported project" FAKE_TEST=0 FAKE_CODE=3

# The fake refuses any argv the script is not expected to send, exiting 90. A 90 anywhere above
# would surface as a wrong exit code, but only if some case happened to route it; assert it directly
# so a future argv change cannot pass by accident.
env FAKE_AUTH=0 PATH="$BOX/bin:$PATH" "$SCRIPT" snyk "$BOX/scan" >"$BOX/out" 2>&1
if grep -q 'unexpected argv' "$BOX/out"; then
  bad "the script sends only the argv the fake expects" "$(grep 'unexpected argv' "$BOX/out" | head -n1)"
else
  ok "the script sends only the argv the fake expects"
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "FAILURES PRESENT ($failures failed, $passes passed)"
  exit 1
fi
echo "snyk runner tests passed ($passes checks)"
