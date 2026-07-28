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

API="https://services.nvd.nist.gov/rest/json/cves/2.0"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/claude-review-suite"
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
    # `|| true` so a stat that fails on both forms yields an empty mode and falls through to the
    # case default below, which refuses. Without it, set -e kills the script instead of refusing,
    # and the permission guard silently becomes a crash on any platform stat does not support.
    mode="$(file_mode "$KEY_FILE" || true)"
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

    # `|| true` is load-bearing: grep exits 1 when nothing matches, pipefail promotes that to the
    # pipeline's status, and set -e would then kill the script on a key file that is empty or holds
    # only comments. An empty API_KEY is the intended signal for that case, not a crash.
    API_KEY="$(grep -m1 '^NVD_API_KEY=' "$KEY_FILE" 2>/dev/null | cut -d= -f2- || true)"
    # Strip surrounding quotes, stray whitespace and a CRLF carriage return.
    API_KEY="$(printf '%s' "$API_KEY" | tr -d '\r' | sed -e 's/^[[:space:]]*//' \
        -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
    [ -n "$API_KEY" ] && KEY_SOURCE="nvd.env"
    return 0
}

# ------------------------------------------------------------------ parse ---
# Metric preference: v3.1, then v4.0, then v3.0, then v2. The vector string carries its own
# "CVSS:3.1/" or "CVSS:4.0/" prefix, so the version needs no column of its own. baseSeverity is
# read from the metric object as well as cvssData, because CVSS v2 puts it on the former.
parse_response() {
    jq -r '
      .vulnerabilities[0].cve // empty
      | . as $c
      | ( $c.metrics.cvssMetricV31[0] // $c.metrics.cvssMetricV40[0]
          // $c.metrics.cvssMetricV30[0] // $c.metrics.cvssMetricV2[0] ) as $mm
      | $mm.cvssData as $m
      | [ $c.id,
          ( $m.baseScore    // "-" | tostring ),
          ( $m.baseSeverity // $mm.baseSeverity // "-" ),
          ( $m.vectorString // "-" ),
          ( [ $c.weaknesses[]?.description[]?.value
              | select(startswith("CWE-")) ] | first // "-" ),
          ( ( $c.published // "-" ) | split("T")[0] ),
          ( $c.vulnStatus // "-" )
        ] | @tsv
    ' "$1" 2>/dev/null
}

# ------------------------------------------------------------------ fetch ---
# Prints the HTTP status code; writes the body to $2. The key goes in a 0600 config file rather
# than -H, because process arguments are world-readable on Linux. mktemp plus a cleanup trap is
# the same SH-04 pattern this suite tells everyone else to use.
fetch_cve() {
    local cve="$1" out="$2" cfg="" code
    if [ -n "$API_KEY" ]; then
        # `|| true` so a mktemp failure (e.g. no space left, unwritable TMPDIR) leaves cfg empty
        # and falls through to a keyless request below instead of a set -e crash: losing the key
        # for one fetch is recoverable, dying mid-batch is not.
        cfg="$(mktemp "${TMPDIR:-/tmp}/nvd-cfg.XXXXXX" || true)"
        if [ -n "$cfg" ]; then
            chmod 600 "$cfg"
            # `|| { ...; cfg=""; }` so a write failure (disk fills between mktemp and here) falls
            # back to the same keyless path as a failed mktemp, instead of a set -e crash that
            # would bypass the warning below. rm -f clears the now-useless temp file immediately,
            # since an empty cfg means the trap at the bottom of this function will not.
            printf 'header = "apiKey: %s"\n' "$API_KEY" >"$cfg" || {
                rm -f "$cfg"
                cfg=""
            }
        fi
        # A silent downgrade to keyless is worse than the crash this guards against: the caller
        # configured a key expecting the rate limit that comes with it, so losing it without a
        # word would look like a healthy run with no visible sign the key was ever dropped.
        if [ -z "$cfg" ]; then
            warn "could not create the key config file, sending $cve without your API key"
        fi
    fi
    code="$(curl -sS --max-time 20 ${cfg:+--config "$cfg"} \
        -o "$out" -D "$HDRS" -w '%{http_code}' "$API?cveId=$cve" 2>/dev/null || printf '000')"
    [ -n "$cfg" ] && rm -f "$cfg"
    printf '%s' "$code"
}

# ------------------------------------------------------------------ cache ---
cache_path() { printf '%s/%s.json' "$CACHE_DIR" "$1"; }

# TTL follows vulnStatus, because the records expected to change are exactly the ones NVD has not
# finished analysing.
cache_ttl() {
    case "$1" in
        "Awaiting Analysis"|"Undergoing Analysis"|"Received") printf '86400' ;;
        "Rejected")                                           printf '2592000' ;;
        *)                                                    printf '604800' ;;
    esac
}

cache_fresh() {
    local file="$1" status age ttl now mtime
    [ -f "$file" ] || return 1
    # jq exits 2 on malformed JSON, so a corrupt cache entry would otherwise kill the script.
    status="$(jq -r '.vulnerabilities[0].cve.vulnStatus // "-"' "$file" 2>/dev/null || true)"
    ttl="$(cache_ttl "$status")"
    now="$(date +%s)"
    mtime="$(stat -c '%Y' "$file" 2>/dev/null || stat -f '%m' "$file" 2>/dev/null || true)"
    [ -n "$mtime" ] || return 1
    age=$((now - mtime))
    [ "$age" -lt "$ttl" ]
}

# ------------------------------------------------------------- rate limits ---
# NVD allows 5 requests per rolling 30s unauthenticated and 50 with a key, and asks callers to
# space requests rather than burst. The cap exists so a repository with 200 CVEs does not silently
# turn a review into a twenty minute job; anything past it is reported, not hidden.
SPACING=6
MAX_LOOKUPS=8

rate_limit_setup() {
    if [ -n "$API_KEY" ]; then
        SPACING="0.6"
        MAX_LOOKUPS=50
    fi
    # Explicit `return 0` for the same set -e reason as resolve_key: an unset NVD_MAX_LOOKUPS is
    # the normal case, not a failure.
    [ -n "${NVD_MAX_LOOKUPS:-}" ] && MAX_LOOKUPS="$NVD_MAX_LOOKUPS"
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

    resolve_key
    rate_limit_setup
    command -v jq >/dev/null 2>&1 || { warn "jq not installed"; exit 1; }
    command -v curl >/dev/null 2>&1 || { warn "curl not installed"; exit 1; }

    local cve code row
    # body and HDRS are globals, not locals. The EXIT trap fires after main has returned, so a
    # function local would already be out of scope and the trap would expand it to the empty
    # string, leaking the temp file.
    #
    # `|| true` so a mktemp failure reports cleanly through warn()/exit 1 instead of a set -e
    # crash that leaks mktemp's own stderr text without going through this script's error path.
    #
    # Every mktemp call in this script (this one, HDRS below, and cfg in fetch_cve) uses a full
    # path template with a distinguishing prefix rather than a bare `mktemp`. A test that needs to
    # fail one specific allocation can then match the shimmed mktemp's argv by name (e.g. `*nvd-cfg*`)
    # instead of counting which ordinal call it is -- a count breaks the moment a call is added,
    # removed, or reordered anywhere in the script, silently retargeting the fault at whatever now
    # sits in that slot.
    body="$(mktemp "${TMPDIR:-/tmp}/nvd-body.XXXXXX" || true)"
    if [ -z "$body" ]; then
        warn "could not create a temp file"
        exit 1
    fi
    HDRS="$(mktemp "${TMPDIR:-/tmp}/nvd-hdrs.XXXXXX" || true)"
    if [ -z "$HDRS" ]; then
        warn "could not create a temp file"
        exit 1
    fi
    trap 'rm -f "$body" "$HDRS"' EXIT

    # The cache is an optimisation: this script's own header promises exit 1 only when it "could
    # not run at all", and an unwritable cache directory is not that -- every CVE is still fetchable,
    # just not cacheable. `|| true` on both lines means a read-only parent or similar leaves
    # $CACHE_DIR missing or unwritable rather than aborting here via set -e; cache_fresh then finds
    # no file for every CVE and the loop below already tolerates that as "not fresh". One warning
    # covers the whole run, since every row would otherwise silently refetch with no visible sign.
    mkdir -p "$CACHE_DIR" 2>/dev/null || true
    chmod 700 "$CACHE_DIR" 2>/dev/null || true
    [ -d "$CACHE_DIR" ] && [ -w "$CACHE_DIR" ] || \
        warn "cache directory $CACHE_DIR is unusable, every CVE will be refetched"

    local lookups=0 capped=0
    while read -r cve; do
        local cached          # row and code are already declared above, do not redeclare them
        cached="$(cache_path "$cve")"

        if cache_fresh "$cached"; then
            row="$(parse_response "$cached" || true)"
            [ -n "$row" ] && { printf '%s\tcache\n' "$row"; continue; }
        fi

        if [ "$lookups" -ge "$MAX_LOOKUPS" ]; then
            capped=$((capped + 1))
            printf '%s\t-\t-\t-\t-\t-\t-\tunavailable\n' "$cve"
            continue
        fi
        [ "$lookups" -gt 0 ] && sleep "$SPACING"
        lookups=$((lookups + 1))
        code="$(fetch_cve "$cve" "$body")"

        # 403 and 429 are NVD's rate-limit responses. One retry, honouring Retry-After when the
        # response carries it, then give up and let the row say "unavailable".
        if [ "$code" = "403" ] || [ "$code" = "429" ]; then
            local backoff
            # Most 403s carry no Retry-After, so grep exiting 1 here is the common case, not an
            # error. Without `|| true` that is a crash on the exact path this retry exists to serve.
            backoff="$(grep -i '^retry-after:' "$HDRS" 2>/dev/null | tr -dc '0-9' || true)"
            # Retry-After may legally be an HTTP-date instead of a delta-seconds integer (RFC
            # 7231). tr -dc '0-9' would concatenate every digit in a date into a number in the
            # hundreds of billions, and sleeping that "successfully" is worse than crashing: the
            # tool just hangs with no output and no diagnostic until someone kills it. Anything
            # that isn't a short run of digits is rejected back to empty, which falls through to
            # the sane hardcoded default below; four digits comfortably covers any real NVD value
            # while still capping a legitimate-but-absurd header under three hours.
            [[ "$backoff" =~ ^[0-9]{1,4}$ ]] || backoff=""
            if [ -z "$backoff" ]; then
                backoff=30
                [ -n "$API_KEY" ] && backoff=10
            fi
            warn "rate-limited by NVD (HTTP $code), retrying $cve in ${backoff}s"
            sleep "$backoff"
            code="$(fetch_cve "$cve" "$body")"
        fi

        row=""
        [ "$code" = "200" ] && row="$(parse_response "$body" || true)"

        if [ -n "$row" ]; then
            # The row was already fetched and parsed successfully; only the cache write can still
            # fail (e.g. a full disk). `|| true` keeps that failure from aborting the script via
            # set -e here, which would otherwise discard this row and every remaining CVE in the
            # batch over a cache miss, not a fetch failure.
            cp "$body" "$cached" 2>/dev/null || true
            printf '%s\tlive\n' "$row"
            continue
        fi

        # The fetch failed. A stale entry is more useful than nothing, provided the row says so.
        if [ -f "$cached" ]; then
            row="$(parse_response "$cached" || true)"
            [ -n "$row" ] && { printf '%s\tcache-stale\n' "$row"; continue; }
        fi

        printf '%s\t-\t-\t-\t-\t-\t-\tunavailable\n' "$cve"
    done <<<"$ids"

    if [ "$capped" -gt 0 ]; then
        warn "$capped CVE(s) past the lookup cap of $MAX_LOOKUPS were not enriched"
        if [ -z "$API_KEY" ]; then
            warn "set an API key to raise the cap; see README.md"
        fi
    fi
}

main "$@"
