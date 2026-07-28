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
# Two `set -e` mechanisms get conflated constantly, so which one a guard below is buying is stated
# at the guard. (1) A plain `var="$(cmd)"` takes cmd's exit status, so a failing cmd aborts the
# *calling* shell. That one is real and is why assignments carry `|| true`. (2) errexit does not
# reach inside a `$( )`: `inherit_errexit` is off and never set here, so a failure partway through a
# function invoked as `code="$(fetch_cve ...)"` aborts nothing, and neither does one inside a
# function invoked as an `if` condition. Guards on those paths are defence in depth against a future
# bare call, not the thing keeping the script alive today.

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
#
# $2 is the CVE this row is supposed to be about, and the record is dropped unless it matches. The
# response body is not trusted to say which CVE it describes: $body is reused for every CVE in the
# batch, so any path that leaves it holding the previous response would otherwise emit that CVE's
# complete row under a `live` provenance and write it to this CVE's cache file. Real curl truncates
# -o and so does fetch_cve now, but "the file must already be right" is a weaker invariant than
# "the record has to name the CVE we asked for". A mismatch produces no row here, which the caller
# already handles as a failed lookup.
parse_response() {
    jq -r --arg want "$2" '
      .vulnerabilities[0].cve // empty
      | . as $c
      | select($c.id == $want)
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
        # `|| true` is defence in depth here, not what saves this path: this function only ever runs
        # inside a `$( )`, where errexit does not apply, so a failed mktemp would leave cfg empty and
        # fall through to the keyless request below regardless. It is kept so the fallback does not
        # silently depend on the caller's invocation form, which a refactor to a bare call would
        # change without touching this line.
        cfg="$(mktemp "${TMPDIR:-/tmp}/nvd-cfg.XXXXXX" || true)"
        if [ -n "$cfg" ]; then
            chmod 600 "$cfg"
            # This handler is load-bearing for a reason that has nothing to do with set -e: without
            # `cfg=""`, a write that failed partway (disk fills between mktemp and here) leaves cfg
            # naming a file with no apiKey header in it. curl is then handed --config pointing at
            # that file and sends the request keyless anyway, while `[ -z "$cfg" ]` below reads
            # false and the warning never fires. Clearing cfg routes the failure onto the same
            # warned keyless path as a failed mktemp. rm -f clears the now-useless temp file
            # immediately, since an empty cfg means the trap at the bottom of this function will not.
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
    # $out and $HDRS are one pair of files reused for every CVE in the batch. curl truncates both
    # itself, but only once it gets far enough to open them, so a transfer that dies before the first
    # byte can leave the previous CVE's response sitting there. Truncating here makes "nothing was
    # written" mean an empty file rather than the last CVE's, so a stale body can never be read as
    # this CVE's answer.
    : >"$out"
    : >"$HDRS"
    code="$(curl -sS --max-time 20 ${cfg:+--config "$cfg"} \
        -o "$out" -D "$HDRS" -w '%{http_code}' "$API?cveId=$cve" 2>/dev/null || printf '000')"
    [ -n "$cfg" ] && rm -f "$cfg"
    # `code` is not reliably three digits. curl writes %{http_code} at the end of the transfer, so a
    # response whose status arrived and whose body then broke yields the status *and* a non-zero exit,
    # and the `|| printf '000'` above appends to whatever curl already printed: a 429 that closes
    # mid-body comes out as "429000". Left alone that equals none of the values tested downstream, so
    # the rate-limit retry the spec mandates never fired on exactly the truncated response most likely
    # to carry a 429.
    #
    # -o sends the body to a file and -sS sends errors to stderr, so curl's stdout is only ever the
    # -w string. That makes the leading three digits curl's real answer, and they are kept. Anything
    # else, including an empty capture, collapses to "000", the same "no usable answer" signal as a
    # curl that never spoke at all, so nothing downstream compares against a string of unknown shape.
    if [[ "$code" =~ ^([0-9]{3})[0-9]*$ ]]; then
        code="${BASH_REMATCH[1]}"
    else
        code="000"
    fi
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
    # jq exits 2 on a corrupt cache entry, which is routine rather than exceptional. `|| true` is
    # defence in depth against a future bare call, not what keeps this alive: cache_fresh is only
    # ever invoked as an `if` condition, and errexit is suppressed for the whole of a function called
    # that way. What actually handles the corrupt entry is the empty `status` falling through to
    # cache_ttl's default branch, and then parse_response declining to produce a row from it.
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
#
# The cap counts *requests*, not CVEs. Counting CVEs let a run that retried rate-limited lookups make
# roughly twice the "8 keyless, 50 keyed" figure the README documents, against an API that had
# already said back off. A retry spends budget like any other request.
SPACING=6
MAX_LOOKUPS=8

rate_limit_setup() {
    if [ -n "$API_KEY" ]; then
        SPACING="0.6"
        MAX_LOOKUPS=50
    fi
    if [ -n "${NVD_MAX_LOOKUPS:-}" ]; then
        # An unvalidated value does not degrade gracefully, it removes the cap: `[ "$n" -ge abc ]`
        # prints "integer expression expected" once per CVE and evaluates false every time, so a
        # typo in the one setting that bounds a 200-CVE repository silently makes it unbounded.
        # Leading zeros are rejected too, because `[ -ge ]` reads them as decimal while `$(( ))`
        # reads them as octal, and a cap that means two different numbers is not a cap.
        if [[ "$NVD_MAX_LOOKUPS" =~ ^(0|[1-9][0-9]*)$ ]]; then
            MAX_LOOKUPS="$NVD_MAX_LOOKUPS"
        else
            warn "NVD_MAX_LOOKUPS='$NVD_MAX_LOOKUPS' is not a non-negative integer, keeping the default cap of $MAX_LOOKUPS"
        fi
    fi
    # Explicit `return 0` for the same set -e reason as resolve_key, which is real for both: they are
    # called bare from main, so a function-final failed test does abort the script.
    return 0
}

cmd_check() {
    # resolve_key's permission-refusal branch warns on stderr, which every caller of --check in this
    # codebase merges into stdout (2>&1, the only convention this file uses). Left unguarded, a
    # refused key file would make --check print six lines instead of the five its own contract
    # promises. The chmod hint is not lost: the "key refused" line below already carries both the
    # diagnosis and the remedy, so this only silences the duplicate.
    resolve_key 2>/dev/null

    local key_line
    case "$KEY_SOURCE" in
        env)      key_line="present (env)" ;;
        nvd.env)  key_line="present (nvd.env)" ;;
        refused)  key_line="refused (bad permissions on $KEY_FILE; chmod 600 it)" ;;
        *)        key_line="absent (keyless mode, reduced rate limit)" ;;
    esac

    local entries=0
    if [ -d "$CACHE_DIR" ]; then
        entries="$(find "$CACHE_DIR" -name '*.json' -type f 2>/dev/null | wc -l | tr -d ' ' || true)"
    fi

    # Probed once and reused. The network line below and the curl line at the bottom both need the
    # answer, and forking `command -v` twice for it invited them to disagree.
    local have_curl=absent have_jq=absent
    command -v curl >/dev/null 2>&1 && have_curl=present
    command -v jq >/dev/null 2>&1 && have_jq=present

    # A five second ceiling, so probing from an offline machine costs five seconds rather than
    # hanging the review that called it. `-I` makes this a HEAD: the old form fetched a whole CVE
    # record and threw it away, immediately before the run started fetching for real with no spacing
    # between the two, so a reachability probe was quietly spending a lookup's worth of NVD's rolling
    # allowance. Reachable/unreachable is decided by curl's exit status rather than the status code,
    # so a server that answers HEAD with 405 still reads as reachable, which is the honest answer.
    #
    # "unreachable" is only claimed when a request was actually attempted and failed. Reporting an
    # absent curl as an unreachable network made two lines of the same five-line report contradict
    # each other, and sent the reader looking for a firewall over a missing binary.
    local net="unknown (curl absent)"
    if [ "$have_curl" = present ]; then
        net="unreachable"
        curl -sS --max-time 5 -I -o /dev/null "$API?cveId=CVE-2021-44228" \
            >/dev/null 2>&1 && net="services.nvd.nist.gov reachable"
    fi

    printf '%-8s %s\n' curl    "$have_curl"
    printf '%-8s %s\n' jq      "$have_jq"
    printf '%-8s %s\n' key     "$key_line"
    printf '%-8s %s\n' cache   "$CACHE_DIR  ($entries entries)"
    printf '%-8s %s\n' network "$net"
}

# --------------------------------------------------------------- run state ---
# enrich_one() both reads and writes these, so they are file-level globals rather than main() locals.
# Bash's dynamic scoping would let main-locals work, but the coupling is worth declaring where it can
# be seen instead of inferred from reading two functions together. They must not be updated inside a
# `$( )`: a subshell's increment is discarded, which is why the request counter is bumped by
# enrich_one at the call site rather than inside a fetch wrapper.
REQUESTS=0        # NVD requests made this run, retries included. This is what MAX_LOOKUPS caps.
CAPPED=0          # CVEs left unenriched because the request budget was already spent
UNRESOLVED=0      # CVEs left unenriched for any other reason
UNRESOLVED_WHY="" # the distinct reasons behind UNRESOLVED, in first-seen order
RATE_LIMITED=0    # a retry was rate-limited too, so remaining CVEs are not requested at all

emit_unavailable() { printf '%s\t-\t-\t-\t-\t-\t-\tunavailable\n' "$1"; }

# Prints the stale cache row for $1 if there is a usable one, and says whether it did.
#
# Reached from three places: a failed fetch, the request cap, and the rate-limit stop. The last two
# matter and used to be missing. Both exist to bound *network* work, and reading a file already on
# disk is not network work, so discarding a cached answer at the cap cost the caller real information
# for nothing. It is also the exact case the cache was built for: a large repository reviewed twice.
emit_stale() {
    local cached row
    cached="$(cache_path "$1")"
    [ -f "$cached" ] || return 1
    row="$(parse_response "$cached" "$1" || true)"
    [ -n "$row" ] || return 1
    printf '%s\tcache-stale\n' "$row"
    return 0
}

# Records one CVE that got a dashed row, with why. Reasons are deduped in first-seen order, so a
# 40-CVE batch that failed the same way produces one clause and not forty. The same `case` membership
# idiom as read_cve_ids' dedupe.
note_unresolved() {
    UNRESOLVED=$((UNRESOLVED + 1))
    case "; $UNRESOLVED_WHY" in
        *"; $1;"*) return 0 ;;
    esac
    UNRESOLVED_WHY="$UNRESOLVED_WHY$1; "
}

# Why a fetch produced no row, in words. skills/security-review/SKILL.md requires the report to name
# NVD enrichment in "## Checks skipped" with the reason this script printed on stderr, so a failure
# that says nothing there makes that instruction impossible to follow. curl's own "000" and an HTTP
# status mean different things to whoever reads the report, so they get different text.
fetch_reason() {
    case "$1" in
        000)     printf 'no response from NVD (network unreachable, or curl failed)' ;;
        404)     printf 'not present in NVD (HTTP 404)' ;;
        403|429) printf 'rate-limited by NVD (HTTP %s)' "$1" ;;
        200)     printf 'NVD returned no usable record' ;;
        *)       printf 'HTTP %s from NVD' "$1" ;;
    esac
}

# The retry delay in seconds: Retry-After when the response carries a usable one, otherwise the
# spec's 10s keyed or 30s keyless default.
retry_backoff() {
    local backoff
    # Most 403s carry no Retry-After, so grep exiting 1 here is the common case rather than an error,
    # and `|| true` keeps the assignment's status from becoming this function's. An empty result is
    # the intended signal and falls through to the default below.
    backoff="$(grep -i '^retry-after:' "$HDRS" 2>/dev/null | tr -dc '0-9' || true)"
    # Retry-After may legally be an HTTP-date instead of a delta-seconds integer (RFC 7231). tr -dc
    # '0-9' would concatenate every digit in a date into a number in the hundreds of billions, and
    # sleeping that "successfully" is worse than crashing: the tool just hangs with no output and no
    # diagnostic until someone kills it. Anything that isn't a short run of digits is rejected back to
    # empty; four digits comfortably covers any real NVD value while still capping a
    # legitimate-but-absurd header under three hours.
    [[ "$backoff" =~ ^[0-9]{1,4}$ ]] || backoff=""
    if [ -z "$backoff" ]; then
        backoff=30
        [ -n "$API_KEY" ] && backoff=10
    fi
    printf '%s' "$backoff"
}

# ------------------------------------------------------------------ enrich ---
# One CVE in, exactly one row out, on every path. That invariant is the whole contract: a caller
# handed a shorter list than it sent has no way to tell which CVE went missing, which is the failure
# mode references/procedure.md exists to prevent.
#
# This is a function and not main()'s loop body because eight decisions live in it (cache freshness,
# the rate-limit stop, the request budget, spacing, the fetch, the retry, the cache write, the stale
# fallback) and a 40-line loop body was where four separate defects had been hiding.
enrich_one() {
    local cve="$1" cached row code
    cached="$(cache_path "$cve")"

    if cache_fresh "$cached"; then
        row="$(parse_response "$cached" "$cve" || true)"
        if [ -n "$row" ]; then
            printf '%s\tcache\n' "$row"
            return 0
        fi
    fi

    # Everything past here needs the network, and two run-level states forbid it. Both fall back to a
    # stale entry first, for the reason given on emit_stale.
    if [ "$RATE_LIMITED" -eq 1 ]; then
        if emit_stale "$cve"; then
            return 0
        fi
        note_unresolved "NVD rate-limited this run, so later CVEs were not requested"
        emit_unavailable "$cve"
        return 0
    fi

    if [ "$REQUESTS" -ge "$MAX_LOOKUPS" ]; then
        if emit_stale "$cve"; then
            return 0
        fi
        CAPPED=$((CAPPED + 1))
        emit_unavailable "$cve"
        return 0
    fi

    if [ "$REQUESTS" -gt 0 ]; then
        sleep "$SPACING"
    fi
    REQUESTS=$((REQUESTS + 1))
    code="$(fetch_cve "$cve" "$body")"

    # 403 and 429 are NVD's rate-limit responses. One retry, honouring Retry-After when the response
    # carries it. A retry that is rate-limited *too* means the run is over its allowance, so every
    # remaining CVE is short-circuited rather than each paying the same backoff again: at keyless
    # defaults a sustained 403 over a 3-CVE batch was 66 seconds of sleeping and four requests
    # against an API that had already said back off, with no output at all until the end. The spec
    # calls for exactly this ("then marks all remaining CVEs unavailable"); it just did not exist.
    if [ "$code" = "403" ] || [ "$code" = "429" ]; then
        local backoff
        backoff="$(retry_backoff)"
        # The retry is a request and is charged for like one, so it is skipped when the budget is
        # already spent rather than quietly overrunning it.
        if [ "$REQUESTS" -lt "$MAX_LOOKUPS" ]; then
            warn "rate-limited by NVD (HTTP $code), retrying $cve in ${backoff}s"
            sleep "$backoff"
            REQUESTS=$((REQUESTS + 1))
            code="$(fetch_cve "$cve" "$body")"
        fi
        if [ "$code" = "403" ] || [ "$code" = "429" ]; then
            RATE_LIMITED=1
            warn "NVD is still rate-limiting (HTTP $code); the remaining CVEs will not be requested"
        fi
    fi

    row=""
    [ "$code" = "200" ] && row="$(parse_response "$body" "$cve" || true)"

    if [ -n "$row" ]; then
        # The row is already fetched and parsed; only the cache write can still fail (a full disk,
        # say). `|| true` matters here because this runs in the calling shell where errexit is live:
        # without it, a failed cp would discard this row and every remaining CVE in the batch over a
        # cache miss rather than a fetch failure.
        cp "$body" "$cached" 2>/dev/null || true
        printf '%s\tlive\n' "$row"
        return 0
    fi

    # The fetch failed, or returned nothing usable. A stale entry beats nothing, provided the row
    # says so.
    if emit_stale "$cve"; then
        return 0
    fi
    note_unresolved "$(fetch_reason "$code")"
    emit_unavailable "$cve"
    return 0
}

# ----------------------------------------------------------------- dispatch ---
main() {
    case "${1:-}" in
        --check)
            # A trailing argument is a usage error, not something to ignore: `--check junk` silently
            # dropping "junk" would hide a typo in the one command whose job is reporting the truth.
            if [ "$#" -gt 1 ]; then
                warn "unknown option: $2"
                exit 2
            fi
            cmd_check
            exit 0
            ;;
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

    local cve
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

    while read -r cve; do
        enrich_one "$cve"
    done <<<"$ids"

    if [ "$CAPPED" -gt 0 ]; then
        warn "$CAPPED CVE(s) were not enriched: this run's cap of $MAX_LOOKUPS NVD requests was reached"
        if [ -z "$API_KEY" ]; then
            warn "set an API key to raise the cap; see README.md"
        fi
    fi
    # Without this, a run where every lookup failed printed nothing but dashed rows on stdout and a
    # completely empty stderr, and the skill's instruction to name the reason in "## Checks skipped"
    # had no reason available to name.
    if [ "$UNRESOLVED" -gt 0 ]; then
        warn "$UNRESOLVED CVE(s) could not be enriched: ${UNRESOLVED_WHY%; }"
    fi
}

main "$@"
