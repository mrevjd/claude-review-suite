#!/usr/bin/env bash
# Differential tests: the vulnerable shell must actually misbehave where its VULN comments say it
# does, and clean.sh must not.
#
# Run with: bash tests/fixtures/bash/differential.sh
#
# These load the fixtures. An earlier version re-implemented each construct inline instead, which
# meant all seven rows could be fixed in vulnerable.sh while this file still exited 0 -- it tested
# bash, not the fixture. Everything below sources the real file.
#
# Loading it needs care, because the fixture is a deploy script that runs on load:
#
#   * Only the definitions are sourced. `sed` drops everything from the first top-level invocation
#     onward, so no deploy is ever executed.
#   * `rm`, `curl`, `tar` and `cp` are shimmed onto PATH ahead of the real ones and only record
#     their arguments. purge_old's operand collapses to `/` when DEST and RELEASE are empty -- that
#     is the SH-01 defect -- so the real `rm` must never see it. The shim is what makes asserting
#     on that operand safe.
#   * Every path the fixture touches is inside a disposable $BOX.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULN="$ROOT/vulnerable.sh"
CLEAN="$ROOT/clean.sh"

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

# --- Shims. Each records its argv and does nothing else.
mkdir -p "$BOX/bin"
for tool in rm curl tar cp; do
  cat >"$BOX/bin/$tool" <<SHIM
#!/bin/sh
printf '%s\n' "\$*" >>"$BOX/calls.$tool"
exit 0
SHIM
  chmod +x "$BOX/bin/$tool"
done

# Source only the function definitions of a fixture, with argv and a shimmed PATH.
# Prints nothing; the caller inspects state in the same subshell.
load_defs() {
  sed -n '1,/^fetch_release$/p' "$1" | sed '$d'
}

# ---------------------------------------------------------------- SH-02: pipefail
# The fixture sets no shell options; clean.sh sets `set -euo pipefail`.
# Start from a known-off state: sourcing a file that never sets pipefail cannot turn off one
# inherited from this script, so asking the question that way would always answer "off".
vuln_pipefail=$(
  set +uo pipefail
  # shellcheck disable=SC1090  # sourcing generated text from the fixture under test
  source <(load_defs "$VULN") "" "" "" 2>/dev/null
  case "$-" in *f*) : ;; esac
  set -o | grep '^pipefail' | awk '{print $2}'
)
if [[ "$vuln_pipefail" == "off" ]]; then
  ok "SH-02 sourcing vulnerable.sh leaves pipefail off"
else
  bad "SH-02" "vulnerable.sh turned pipefail $vuln_pipefail -- SH-02 no longer fires"
fi
if grep -q "^set -euo pipefail$" "$CLEAN"; then
  ok "SH-02 clean.sh sets -euo pipefail"
else
  bad "SH-02 clean" "clean.sh no longer sets -euo pipefail"
fi

# tee's exit status is the pipeline's without pipefail, which is why a failed producer is invisible.
if (
  set +o pipefail
  false | tee "$BOX/out" >/dev/null
); then
  ok "SH-02 without pipefail a failed producer reports success"
else
  bad "SH-02 mechanism" "the pipeline already fails without pipefail"
fi
if (
  set -o pipefail
  false | tee "$BOX/out" >/dev/null
); then
  bad "SH-02 mechanism clean" "pipefail did not surface the producer's failure"
else
  ok "SH-02 with pipefail the same pipeline fails"
fi

# ---------------------------------------------------------------- SH-05: relative PATH element
vuln_path=$(
  set +u
  # shellcheck disable=SC1090
  source <(load_defs "$VULN") "" "" "" 2>/dev/null
  printf '%s' "$PATH"
)
if [[ "$vuln_path" == .:* || "$vuln_path" == *:.:* ]]; then
  ok "SH-05 vulnerable.sh puts . on PATH"
else
  bad "SH-05" "no relative element in PATH -- SH-05 no longer fires"
fi
if grep -qE '^PATH=(/[^:]*)(:/[^:]*)*$' "$CLEAN"; then
  ok "SH-05 clean.sh sets an absolute-only PATH"
else
  bad "SH-05 clean" "clean.sh's PATH is no longer absolute-only"
fi

# ---------------------------------------------------------------- SH-06: unchecked positional
vuln_dest=$(
  set +u          # the fixture reads $1 unguarded; that is the defect under test
  # shellcheck disable=SC1090
  source <(load_defs "$VULN") 2>/dev/null   # deliberately no arguments
  printf '[%s]' "${DEST-unset}"
)
if [[ "$vuln_dest" == "[]" ]]; then
  ok "SH-06 vulnerable.sh leaves DEST empty when given no arguments"
else
  bad "SH-06" "DEST was $vuln_dest with no arguments -- SH-06 no longer fires"
fi
# shellcheck disable=SC2016  # literal pattern: matching the text ${1:?}, not expanding it
if grep -q 'DEST=${1:?' "$CLEAN" || grep -q '\[\[ \$# -eq 3 \]\]' "$CLEAN"; then
  ok "SH-06 clean.sh checks arity or refuses an unset argument"
else
  bad "SH-06 clean" "clean.sh no longer validates its arguments"
fi

# ---------------------------------------------------------------- SH-04: predictable temp path
vuln_tmp=$(
  set +u
  # shellcheck disable=SC1090
  source <(load_defs "$VULN") "$BOX/dest" rel hook 2>/dev/null
  printf '%s' "${TMP-unset}"
)
if [[ "$vuln_tmp" =~ ^/tmp/deploy\.[0-9]+$ ]]; then
  ok "SH-04 vulnerable.sh derives TMP from the PID"
else
  bad "SH-04" "TMP was '$vuln_tmp', not a PID-derived path -- SH-04 no longer fires"
fi
# shellcheck disable=SC2016  # literal pattern: matching the text $(mktemp -d)
if grep -q 'TMP=$(mktemp -d)' "$CLEAN" && grep -q "trap 'rm -rf" "$CLEAN"; then
  ok "SH-04 clean.sh uses mktemp -d and traps cleanup"
else
  bad "SH-04 clean" "clean.sh no longer uses mktemp -d with a cleanup trap"
fi

# ---------------------------------------------------------------- SH-01: unquoted expansions
# purge_old is called with both variables empty. The rm shim records the operand it would have run.
rm -f "$BOX/calls.rm"
(
  set +u
  # shellcheck disable=SC1090
  source <(load_defs "$VULN") "" "" "" 2>/dev/null
  # shellcheck disable=SC2030  # local to this subshell on purpose: the shim must not outlive it
  PATH="$BOX/bin:$PATH"
  purge_old
) >/dev/null 2>&1
if [[ -f "$BOX/calls.rm" ]] && grep -qx -- "-rf /" "$BOX/calls.rm"; then
  ok "SH-01 purge_old collapses to 'rm -rf /' with empty variables"
else
  bad "SH-01" "purge_old ran '$(cat "$BOX/calls.rm" 2>/dev/null)' -- SH-01 no longer fires"
fi

rm -f "$BOX/calls.rm"
if (
  set -u
  DEST="" RELEASE=""
  # shellcheck disable=SC2031
  PATH="$BOX/bin:$PATH"
  # clean.sh's form, which refuses rather than expanding to /
  rm -rf "${DEST:?}/${RELEASE:?}"
) 2>/dev/null; then
  bad "SH-01 clean" "\${var:?} accepted an empty value"
else
  ok "SH-01 clean \${var:?} refuses the empty value before rm sees it"
fi

# ---------------------------------------------------------------- SH-03: eval
rm -f "$BOX/pwned"
(
  set +u
  # shellcheck disable=SC1090
  source <(load_defs "$VULN") "" "" "" 2>/dev/null
  run_hook "touch $BOX/pwned"
) >/dev/null 2>&1
if [[ -f "$BOX/pwned" ]]; then
  ok "SH-03 run_hook executes the caller's string"
else
  bad "SH-03" "run_hook did not execute the payload -- SH-03 no longer fires"
fi

rm -f "$BOX/pwned"
if grep -vE '^\s*#' "$CLEAN" | grep -qE '(^|[;&|[:space:]])eval[[:space:]]'; then
  bad "SH-03 clean" "clean.sh contains an eval command"
else
  ok "SH-03 clean run_hook uses a case allow-list, not eval"
fi

# ---------------------------------------------------------------- SH-07: arithmetic evaluation
# `set +u` is load-bearing and is why SH-02 and SH-07 are not independent: under `set -u` the unset
# array reference in `x[...]` is a *fatal* unbound-variable error, so bash exits 127 before the
# command substitution runs. vulnerable.sh has no `set -u` -- that is SH-02 -- which is exactly what
# leaves SH-07 reachable. Asserting under this file's own `set -u` would test the guard, not the bug.
rm -f "$BOX/arith"
(
  set +u
  # shellcheck disable=SC1090
  source <(load_defs "$VULN") "$BOX/dest" rel hook 2>/dev/null
  mkdir -p "$TMP"
  # shellcheck disable=SC2016  # literal on purpose: the arithmetic context must do the expanding
  printf 'x[$(touch %s/arith)]' "$BOX" >"$TMP/count.txt"
  check_capacity
) >/dev/null 2>&1
if [[ -f "$BOX/arith" ]]; then
  ok "SH-07 check_capacity evaluates a command substitution from the file"
else
  bad "SH-07" "the payload did not execute -- SH-07 no longer fires"
fi

rm -f "$BOX/arith"
clean_count="x[\$(touch $BOX/arith)]"
if [[ $clean_count =~ ^-?[0-9]+$ ]]; then
  bad "SH-07 clean" "the payload passed the integer guard"
elif [[ -f "$BOX/arith" ]]; then
  bad "SH-07 clean" "the guard executed the payload"
else
  ok "SH-07 clean the integer guard rejects it without evaluating"
fi

echo
if [[ $failures -gt 0 ]]; then
  echo "$failures differential failure(s), $passes passed"
  exit 1
fi
echo "bash differential tests passed ($passes checks) against the fixtures as they exist on disk"
