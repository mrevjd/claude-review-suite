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
# shellcheck disable=SC2034  # consumed by resolve_key(), added in task 2
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

# ----------------------------------------------------------------- dispatch ---
main() {
    case "${1:-}" in
        --check) printf 'not implemented\n'; exit 0 ;;
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
