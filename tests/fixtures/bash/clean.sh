#!/usr/bin/env bash
# CLEAN-FIXTURE -- the same seven situations as vulnerable.sh, written correctly.
# A review of this file must produce no Critical and no High findings.

# SH-02: fail on error, on unset variable, and on a failing producer in a pipeline.
set -euo pipefail

# SH-05: explicit PATH with no relative or empty element, and every external binary resolved once
# up front so a missing dependency fails loudly instead of silently picking something else.
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required binary not found: $1" >&2
    exit 1
  }
}
require curl
require tar

usage() {
  echo "usage: ${0##*/} <dest-dir> <release-id> <hook-name>" >&2
  exit 2
}

# SH-06: arity checked, then content validated -- DEST must be an existing directory and RELEASE
# must match a known-safe shape, so neither can be empty or contain a traversal.
[[ $# -eq 3 ]] || usage
DEST=${1:?dest-dir required}
RELEASE=${2:?release-id required}
HOOK=${3:?hook-name required}

[[ -d $DEST ]] || {
  echo "dest-dir is not a directory: $DEST" >&2
  exit 1
}
[[ $RELEASE =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "release-id has an unexpected shape: $RELEASE" >&2
  exit 1
}

# SH-04: unpredictable temp directory, removed on every exit path including a signal.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch_release() {
  # SH-02: pipefail makes a failed curl here abort the script via -e, instead of tee's exit status
  # (always 0 on a successful write) masking it.
  curl -sSL "https://releases.example.com/${RELEASE}.tar.gz" | tee "$TMP/release.tar.gz" >/dev/null
  tar -xzf "$TMP/release.tar.gz" -C "$TMP"
}

purge_old() {
  # SH-01: every expansion quoted, and the target is known non-empty from the validation above.
  rm -rf "${DEST:?}/${RELEASE:?}"
}

run_hook() {
  # SH-03: no eval. The caller picks from a fixed set of behaviours; anything else is refused.
  case "$1" in
    migrate) "$TMP/bin/migrate" --confirm ;;
    warm-cache) "$TMP/bin/warm-cache" ;;
    none) : ;;
    *)
      echo "unknown hook: $1" >&2
      exit 1
      ;;
  esac
}

check_capacity() {
  local count
  count=$(<"$TMP/count.txt")
  # SH-07: the value is proven to be an integer before any arithmetic context sees it.
  [[ $count =~ ^-?[0-9]+$ ]] || {
    echo "count.txt is not an integer: $count" >&2
    exit 1
  }
  if ((count > 10)); then
    echo "capacity exceeded" >&2
    return 1
  fi
  return 0
}

fetch_release
purge_old
check_capacity
run_hook "$HOOK"
cp -r "$TMP"/* "$DEST"/
echo "deployed $RELEASE to $DEST"
