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

# shellcheck disable=SC2034  # consumed by fetch_cve(), added in task 2
API="https://services.nvd.nist.gov/rest/json/cves/2.0"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/claude-review-suite"
# shellcheck disable=SC2034  # consumed by cache_path(), added in task 3
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/claude-review-suite/nvd"
KEY_FILE="$CONFIG_DIR/nvd.env"
CVE_RE='^CVE-[0-9]{4}-[0-9]{4,}$'

warn() { printf '!!! %s\n' "$*" >&2; }

# ------------------------------------------------------------------ input ---
# Validated, uppercased, deduped, order preserved. Anything that is not a CVE ID is dropped
# loudly rather than sent to the API.
read_cve_ids() {
    local raw upper seen=""
    while read -r raw; do
        [ -n "$raw" ] || continue
        upper="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]')"
        if ! printf '%s' "$upper" | grep -qE "$CVE_RE"; then
            warn "dropped, not a CVE ID: $raw"
            continue
        fi
        case " $seen " in *" $upper "*) continue ;; esac
        seen="$seen $upper"
        printf '%s\n' "$upper"
    done
}

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
    mode="$(file_mode "$KEY_FILE")"
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

    API_KEY="$(grep -m1 '^NVD_API_KEY=' "$KEY_FILE" 2>/dev/null | cut -d= -f2-)"
    # Strip surrounding quotes, stray whitespace and a CRLF carriage return.
    API_KEY="$(printf '%s' "$API_KEY" | tr -d '\r' | sed -e 's/^[[:space:]]*//' \
        -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
    [ -n "$API_KEY" ] && KEY_SOURCE="nvd.env"
    return 0
}

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

# ----------------------------------------------------------------- dispatch ---
main() {
    case "${1:-}" in
        --check) cmd_check; exit 0 ;;
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
