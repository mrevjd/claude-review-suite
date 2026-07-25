#!/bin/bash
# Deliberately defective shell used to test the review-bash skill. One planted defect per
# SH-01..SH-07. Must pass `bash -n` -- a vulnerable fixture has to be vulnerable, not broken.
#
# VULN: SH-02 -- no `set -euo pipefail` anywhere, so every failure below is ignored, every typo'd
# variable expands to empty, and a failing producer in a pipe reports success.

# VULN: SH-05 -- the current directory is prepended to PATH, so a `tar` or `curl` dropped in the
# working tree by anyone else runs instead of the real binary. Bare names below rely on it.
PATH=.:$PATH

# VULN: SH-06 -- $1 is used as the deploy target with no arity or content check, so running the
# script with no argument makes DEST empty and every path below resolves to the filesystem root.
DEST=$1
RELEASE=$2

# VULN: SH-04 -- predictable temp path built from the PID, never cleaned up. A local attacker can
# pre-create it as a symlink and redirect the writes below.
TMP=/tmp/deploy.$$
mkdir -p "$TMP"

fetch_release() {
  # Bare `curl` resolved through the poisoned PATH above.
  curl -sSL "https://releases.example.com/$RELEASE.tar.gz" -o "$TMP/release.tar.gz"
  tar -xzf "$TMP/release.tar.gz" -C "$TMP"
}

purge_old() {
  # VULN: SH-01 -- both expansions are unquoted. An empty DEST or a RELEASE containing whitespace
  # turns this into a recursive delete of somewhere nobody intended.
  rm -rf $DEST/$RELEASE
}

run_hook() {
  # VULN: SH-03 -- the hook string is caller-controlled and becomes code, running with whatever
  # privileges the script has.
  local hook="$1"
  eval "$hook"
}

check_capacity() {
  # VULN: SH-07 -- the file contents are evaluated as an arithmetic expression, so a payload like
  # `x[$(rm -rf /tmp/data)]` in count.txt executes instead of being compared.
  if (( $(cat "$TMP/count.txt") > 10 )); then
    echo "capacity exceeded"
    return 1
  fi
  return 0
}

fetch_release
purge_old
check_capacity
run_hook "$3"
cp -r $TMP/* $DEST/
echo "deployed $RELEASE to $DEST"
