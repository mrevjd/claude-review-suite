#!/usr/bin/env bash
# Runs the structural validator, then any real linter that happens to be installed against the
# fixtures.
#
# Two disciplines this script inherits from the suite it tests:
#
#   1. An absent tool is a SKIP, never a pass and never a failure. So is a check with no fixtures
#      to run against -- an empty run reporting PASS is the silent gap this suite exists to prevent.
#   2. "The tool found problems" is not "the check failed". A diagnostic linter is expected to be
#      silent on a clean fixture and to complain about a vulnerable one; a vulnerable fixture the
#      linter has nothing to say about is a broken fixture, so that case fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

skipped=()
failed=0

have() { command -v "$1" >/dev/null 2>&1; }

skip() { skipped+=("$1 -- $2"); }

# gate <label> <tool> <fixture-count> <cmd...> -- the command must succeed.
gate() {
  local label="$1" tool="$2" count="$3"
  shift 3
  if ! have "$tool"; then
    skip "$label" "$tool not installed"
    return
  fi
  if [[ "$count" -eq 0 ]]; then
    skip "$label" "no fixtures present"
    return
  fi
  printf '\n--- %s (%d fixture(s)) ---\n' "$label" "$count"
  if "$@"; then
    echo "PASS  $label"
  else
    echo "FAIL  $label"
    failed=1
  fi
}

# expect_flagged <label> <tool> <fixture-count> <cmd...> -- the command must FAIL, because the
# fixture is deliberately defective and the tool is supposed to notice.
expect_flagged() {
  local label="$1" tool="$2" count="$3"
  shift 3
  if ! have "$tool"; then
    skip "$label" "$tool not installed"
    return
  fi
  if [[ "$count" -eq 0 ]]; then
    skip "$label" "no fixtures present"
    return
  fi
  printf '\n--- %s (%d fixture(s)) ---\n' "$label" "$count"
  if "$@" >/dev/null 2>&1; then
    echo "FAIL  $label -- tool reported nothing on a deliberately defective fixture"
    failed=1
  else
    echo "PASS  $label (tool flagged it, as intended)"
  fi
}

echo "=== structural validator ==="
python3 tests/validate.py || failed=1

shopt -s nullglob
go_fixtures=(tests/fixtures/go/*.go)
sh_all=(tests/fixtures/bash/*.sh)
sh_clean=(tests/fixtures/bash/clean*.sh)
sh_vuln=(tests/fixtures/bash/vulnerable*.sh)
php_fixtures=(tests/fixtures/php/*.php)
py_fixtures=(tests/fixtures/general/*.py tests/fixtures/security/*.py)
ts_fixtures=(tests/fixtures/vue-ts/*.ts)
shopt -u nullglob

# --- Syntax gates: every fixture must parse. A vulnerable fixture has to be vulnerable, not broken.

gate "gofmt parses Go fixtures" gofmt "${#go_fixtures[@]}" \
  bash -c 'for f in "$@"; do gofmt -e "$f" >/dev/null || exit 1; done' _ "${go_fixtures[@]}"

gate "bash -n parses Bash fixtures" bash "${#sh_all[@]}" \
  bash -c 'for f in "$@"; do bash -n "$f" || exit 1; done' _ "${sh_all[@]}"

# php -l takes one file at a time.
gate "php -l on PHP fixtures" php "${#php_fixtures[@]}" \
  bash -c 'for f in "$@"; do php -l "$f" || exit 1; done' _ "${php_fixtures[@]}"

gate "py_compile on Python fixtures" python3 "${#py_fixtures[@]}" \
  python3 -m py_compile "${py_fixtures[@]}"

# node 22+ strips types, so --check is a real parse gate for TypeScript. It cannot parse .vue.
gate "node --check on TS fixtures" node "${#ts_fixtures[@]}" \
  bash -c 'for f in "$@"; do node --check "$f" || exit 1; done' _ "${ts_fixtures[@]}"

# --- Diagnostic gates: silent on clean, noisy on vulnerable.

gate "shellcheck is silent on clean Bash fixtures" shellcheck "${#sh_clean[@]}" \
  shellcheck -S style "${sh_clean[@]}"

expect_flagged "shellcheck flags vulnerable Bash fixtures" shellcheck "${#sh_vuln[@]}" \
  shellcheck -S style "${sh_vuln[@]}"

# -i 2 matches this repo's shell style; shfmt's default is tabs, and gating on a tool's default
# rather than the project's chosen style would report a style disagreement as a defect.
gate "shfmt formatting on clean Bash fixtures" shfmt "${#sh_clean[@]}" \
  shfmt -i 2 -ci -d "${sh_clean[@]}"

if [[ ${#skipped[@]} -gt 0 ]]; then
  echo
  echo "=== checks skipped ==="
  for entry in "${skipped[@]}"; do
    echo "SKIP  $entry"
  done
fi

echo
if [[ $failed -eq 0 ]]; then
  echo "ALL RUNNABLE CHECKS PASSED (${#skipped[@]} skipped)"
else
  echo "FAILURES PRESENT"
fi
exit "$failed"
