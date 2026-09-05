#!/usr/bin/env bash
# review-tools.sh: manage tooling for the code & security review skill suite.
#
#   ./review-tools.sh probe   [dir]   capability report (default)
#   ./review-tools.sh install [dir]   install anything missing, globally
#   ./review-tools.sh tsv     [dir]   machine-readable probe, for the skills
#   ./review-tools.sh snyk    [dir]   run the snyk scans alone, without a review pass
#                                     exit 0 both scans clean, 1 findings, 2 neither scan ran,
#                                            3 incomplete: what ran was clean, a scan was skipped
#
# Resolution: global first, project-local fallback.
#   REVIEW_TOOL_PREFER=local  reverses it
#   PREFIX=/opt/bin           where binaries land (default /usr/local/bin)
#
# Upstream binaries are preferred over distro packages throughout; the distro
# package manager is used only for curl/tar/unzip, where staleness is harmless.
set -uo pipefail

PREFIX="${PREFIX:-/usr/local/bin}"
PREFER="${REVIEW_TOOL_PREFER:-global}"
SUDO=""
[ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

TOOLS=(
    go staticcheck gosec govulncheck errcheck
    shellcheck shfmt
    bun tsc eslint knip
    php composer phpstan
    semgrep gitleaks trivy snyk
    git curl jq yq
)

# ---------------------------------------------------------------- helpers ---
have() { command -v "$1" >/dev/null 2>&1; }
say()  { printf '==> %s\n' "$*"; }
warn() { printf '!!! %s\n' "$*" >&2; }
skip() { printf '    %s present, skipping\n' "$1"; }

arch_vars() {
    case "$(uname -m)" in
        x86_64|amd64)  ARCH_GNU=x86_64;  ARCH_GO=amd64; ARCH_ALT=x64 ;;
        aarch64|arm64) ARCH_GNU=aarch64; ARCH_GO=arm64; ARCH_ALT=arm64 ;;
        *) warn "unsupported arch $(uname -m)"; exit 1 ;;
    esac
}

pkg_install() {
    if   have apt-get; then $SUDO apt-get install -y "$@"   # apt-get: stable CLI for scripts
    elif have dnf;     then $SUDO dnf install -y "$@"
    elif have pacman;  then $SUDO pacman -S --noconfirm "$@"
    elif have zypper;  then $SUDO zypper install -y "$@"
    elif have apk;     then $SUDO apk add "$@"
    else warn "no known package manager; install manually: $*"; return 1
    fi
}

# Every other tool here is a capability the moment it is on PATH. snyk is not: it needs an
# authenticated session, and an unauthenticated one fails with the same non-zero exit a real finding
# uses. Reporting it PRESENT when it cannot run is the "looks complete, is not" result this suite
# exists to refuse, so the probe asks the second question too.
#
# `whoami` answers in a username. `config get api` would answer the same question by printing the
# token on stdout, which is a credential leak performed by the tool that inspects for credential
# leaks; do not swap it in.
auth_ok() {
    local bin="$1" path="$2"
    case "$bin" in
        snyk) "$path" whoami --experimental >/dev/null 2>&1 ;;
        *) return 0 ;;
    esac
}

# ------------------------------------------------------------- resolution ---
resolve_global() { command -v "$1" 2>/dev/null; }

resolve_local() {
    local bin="$1" d
    for d in "$ROOT/node_modules/.bin" "$ROOT/vendor/bin"; do
        [ -x "$d/$bin" ] && { printf '%s\n' "$d/$bin"; return 0; }
    done
    return 1
}

# Go-built binaries embed their module version; recovers real versions even
# when a tool has no version flag, or was built without release ldflags.
go_mod_version() {
    have go || return 0
    go version -m "$1" 2>/dev/null | awk '$1=="mod"{print $3; exit}'
}

version_of() {
    local path="$1" bin v=""
    bin="$(basename "$path")"
    case "$bin" in
        go)          v="$(go version 2>/dev/null)" ;;
        shellcheck)  v="$("$path" --version 2>/dev/null | grep -i '^version:' | head -n1)" ;;
        govulncheck) v="$("$path" -version 2>/dev/null | grep -oE 'govulncheck@[^ ]+' | head -n1)" ;;
        *)           v="$("$path" --version 2>&1 | head -n1)" ;;
    esac
    v="$(printf '%s' "$v" | tr -d '\r')"

    # Reject usage/error text and anything with no digit in it, then fall back
    # to the embedded module version rather than reporting stderr as a version.
    if [ -z "$v" ] \
       || ! printf '%s' "$v" | grep -q '[0-9]' \
       || printf '%s' "$v" | grep -qiE 'not defined|unknown flag|usage:|^error'; then
        v="$(go_mod_version "$path")"
    fi

    printf '%s' "${v:-unknown}" | cut -c1-60
}

# tool -> "STATUS<TAB>SCOPE<TAB>PATH<TAB>VERSION"
probe_one() {
    local bin="$1" path="" scope=""
    if [ "$PREFER" = "local" ]; then
        if path="$(resolve_local "$bin")";  then scope=local
        elif path="$(resolve_global "$bin")"; then scope=global; fi
    else
        if path="$(resolve_global "$bin")"; then scope=global
        elif path="$(resolve_local "$bin")";  then scope=local; fi
    fi
    if [ -z "$path" ]; then
        printf 'ABSENT\t-\t-\t-'
    elif ! auth_ok "$bin" "$path"; then
        printf 'NOAUTH\t%s\t%s\t%s' "$scope" "$path" "$(version_of "$path")"
    else
        printf 'PRESENT\t%s\t%s\t%s' "$scope" "$path" "$(version_of "$path")"
    fi
}

cmd_tsv() {
    local t
    for t in "${TOOLS[@]}"; do printf '%s\t%s\n' "$t" "$(probe_one "$t")"; done
}

cmd_probe() {
    local t line status scope version absent=0 noauth=0
    printf '%-14s %-8s %-7s %s\n' TOOL STATUS SCOPE VERSION
    printf '%-14s %-8s %-7s %s\n' -------------- -------- ------- -------
    for t in "${TOOLS[@]}"; do
        line="$(probe_one "$t")"
        status="$(printf '%s' "$line" | cut -f1)"
        scope="$(printf  '%s' "$line" | cut -f2)"
        version="$(printf '%s' "$line" | cut -f4)"
        printf '%-14s %-8s %-7s %s\n' "$t" "$status" "$scope" "$version"
        case "$status" in
            ABSENT) absent=$((absent + 1)) ;;
            NOAUTH) noauth=$((noauth + 1)) ;;
        esac
    done
    # Two counts, two remedies: installing a binary will not authenticate it, and one summary line
    # covering both would send the reader to the wrong fix.
    printf '\n%d of %d absent' "$absent" "${#TOOLS[@]}"
    [ "$noauth" -gt 0 ] && printf ', %d present but unauthenticated' "$noauth"
    printf '.'
    [ "$absent" -gt 0 ] && printf '  Run: %s install' "$0"
    [ "$noauth" -gt 0 ] && printf '  Then: snyk auth'
    printf '\n'
}

# ---------------------------------------------------------------- install ---
# gh_install <bin> <owner/repo> <asset-regex> [path-inside-archive]
gh_install() {
    local bin="$1" repo="$2" pattern="$3" inner="${4:-}"
    have "$bin" && { skip "$bin"; return 0; }

    local json url name tmp src
    json="$(curl -sfL "https://api.github.com/repos/$repo/releases/latest")" \
        || { warn "$bin: release lookup failed for $repo"; return 1; }

    url="$(printf '%s' "$json" | grep -oE '"browser_download_url": *"[^"]+"' \
          | cut -d'"' -f4 | grep -E "$pattern" | head -n1)" || true

    if [ -z "$url" ]; then
        warn "$bin: no asset matched /$pattern/. Available assets:"
        printf '%s' "$json" | grep -oE '"browser_download_url": *"[^"]+"' \
            | cut -d'"' -f4 | sed 's/^/      /' >&2 || true
        warn "$bin: adjust the pattern in this script and re-run."
        return 1
    fi

    name="$(basename "$url")"
    tmp="$(mktemp -d)"
    say "installing $bin from $name"
    curl -sfL "$url" -o "$tmp/$name" || { warn "$bin: download failed"; rm -rf "$tmp"; return 1; }

    case "$name" in
        *.tar.gz|*.tgz) tar -xzf "$tmp/$name" -C "$tmp" ;;
        *.tar.xz)       tar -xJf "$tmp/$name" -C "$tmp" ;;
        *.zip)          have unzip || pkg_install unzip; unzip -qo "$tmp/$name" -d "$tmp" ;;
        *)              mv "$tmp/$name" "$tmp/$bin" ;;   # bare binary or .phar
    esac

    if [ -n "$inner" ] && [ -f "$tmp/$inner" ]; then
        src="$tmp/$inner"
    else
        src="$(find "$tmp" -type f -name "$bin" | head -n1)"
        [ -z "$src" ] && src="$(find "$tmp" -type f -name "${bin}*" \
            ! -name '*.tar*' ! -name '*.zip' ! -name '*.txt' ! -name '*.md' | head -n1)"
    fi
    [ -z "${src:-}" ] && { warn "$bin: no binary found inside $name"; rm -rf "$tmp"; return 1; }

    $SUDO install -m 0755 "$src" "$PREFIX/$bin" && say "$bin -> $PREFIX/$bin"
    rm -rf "$tmp"
}

path_warn() {
    local dir="$1" label="$2"
    [ -z "$dir" ] && return 0
    case ":$PATH:" in
        *":$dir:"*) ;;
        *) warn "$label ($dir) is not on PATH: add it to your shell rc" ;;
    esac
}

cmd_install() {
    arch_vars
    have curl || pkg_install curl
    have tar  || pkg_install tar

    # Prompt for sudo once, upfront, rather than mid-run between downloads.
    if [ -n "$SUDO" ]; then
        say "binaries install to $PREFIX, caching sudo credentials"
        $SUDO -v || { warn "sudo needed to write $PREFIX; set PREFIX=\$HOME/.local/bin to avoid it"; exit 1; }
    fi

    # --- upstream binaries -------------------------------------------------
    # Patterns verified against live releases 2026-07-25: shellcheck v0.11.0,
    # shfmt v3.13.1, gitleaks 8.30.1 (note: labels x86-64 as x64), yq amd64.
    # A miss prints the real asset list rather than failing silently, and
    # never aborts the rest of the run.
    gh_install shellcheck koalaman/shellcheck "linux\.${ARCH_GNU}\.tar\.xz$"             || true
    gh_install shfmt      mvdan/sh            "linux_${ARCH_GO}$"                        || true
    gh_install gitleaks   gitleaks/gitleaks   "linux_(${ARCH_ALT}|${ARCH_GO})\.tar\.gz$" || true
    gh_install yq         mikefarah/yq        "yq_linux_${ARCH_GO}$"                     || true
    gh_install jq         jqlang/jq           "linux-(${ARCH_GO}|${ARCH_GNU})$"          || true

    # phpstan ships an official phar; self-contained, needs php on PATH to run
    if have php; then
        gh_install phpstan phpstan/phpstan "phpstan\.phar$" || true
    else
        warn "php absent: skipping phpstan"
    fi

    # --- Go analysers ------------------------------------------------------
    # Install via a scratch GOBIN, then place in PREFIX so these land alongside
    # every other tool. Avoids depending on GOPATH/bin being on PATH.
    if have go; then
        local pair bin mod gotmp
        gotmp="$(mktemp -d)"
        for pair in \
            "staticcheck:honnef.co/go/tools/cmd/staticcheck@latest" \
            "gosec:github.com/securego/gosec/v2/cmd/gosec@latest" \
            "govulncheck:golang.org/x/vuln/cmd/govulncheck@latest" \
            "errcheck:github.com/kisielk/errcheck@latest"
        do
            bin="${pair%%:*}"; mod="${pair#*:}"
            if have "$bin"; then skip "$bin"; continue; fi
            say "building $bin"
            if GOBIN="$gotmp" go install "$mod" && [ -x "$gotmp/$bin" ]; then
                $SUDO install -m 0755 "$gotmp/$bin" "$PREFIX/$bin" && say "$bin -> $PREFIX/$bin"
            else
                warn "$bin: build failed"
            fi
        done
        rm -rf "$gotmp"
    else
        warn "go absent: skipping staticcheck/gosec/govulncheck/errcheck."
        warn "Distro Go is usually stale; get current from https://go.dev/dl/"
    fi

    # --- JS/TS: no upstream binaries exist, bun global shims are the closest -
    if have bun; then
        local jspair
        for jspair in "tsc:typescript" "eslint:eslint" "knip:knip"; do
            bin="${jspair%%:*}"; mod="${jspair##*:}"
            if have "$bin"; then skip "$bin"; else
                say "installing $bin globally via bun ($mod)"
                bun add -g "$mod"
            fi
        done
        path_warn "$(bun pm bin -g 2>/dev/null || true)" "bun global bin dir"
    else
        warn "bun absent: skipping tsc/eslint/knip"
    fi

    # --- security scanners -------------------------------------------------
    if have semgrep; then skip semgrep; else
        say "installing semgrep via pipx"
        have pipx || python3 -m pip install --user --break-system-packages pipx
        pipx install semgrep
    fi

    # snyk ships one static binary per arch. Asset names verified against the live v1.1307.0
    # release on 2026-09-05. Authentication is deliberately not attempted: `snyk auth` opens a
    # browser and writes a credential to the user's home directory, which is their decision.
    local snyk_asset="snyk-linux$"
    [ "$ARCH_GO" = arm64 ] && snyk_asset="snyk-linux-arm64$"
    gh_install snyk snyk/cli "$snyk_asset" || true

    if have trivy; then skip trivy; else
        # Unpinned deliberately: upstream prunes old releases, so pins rot.
        say "installing trivy from upstream script"
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | $SUDO sh -s -- -b "$PREFIX"
    fi

    # --- composer (optional now phpstan is a phar) -------------------------
    if ! have php; then
        warn "php absent: skipping composer"
    elif have composer; then
        skip composer
    else
        say "installing composer from getcomposer.org"
        curl -sSfL https://getcomposer.org/installer -o /tmp/composer-setup.php
        php /tmp/composer-setup.php --install-dir=/tmp --filename=composer
        $SUDO install -m 0755 /tmp/composer "$PREFIX/composer"
        rm -f /tmp/composer-setup.php /tmp/composer
    fi

    printf '\n'; say "install pass complete, re-probing:"; printf '\n'
    cmd_probe

    # A NOAUTH row is not something this script can clear, and saying so beats leaving the reader to
    # re-run install and watch nothing change.
    if have snyk && ! auth_ok snyk "$(resolve_global snyk)"; then
        printf '\n'; warn "snyk is installed but not authenticated. Run 'snyk auth' when you want it"
        warn "to run: it opens a browser, so this script will not do it for you."
    fi
}

# ------------------------------------------------------------------- snyk ---
# The two snyk scans on their own, for when the scan is wanted without paying for a full review
# pass. This reports: it installs nothing, authenticates nothing, and fixes nothing.
#
# snyk_scan reads SNYK_BIN and updates `ran` and `found`, both declared by its caller. Exit codes are
# verified against CLI 1.1307.0: 0 clean, 1 findings, 3 no supported project, 2 everything that went
# wrong. 2 has to be read rather than counted, because a licensing refusal arrives with the same
# code a genuine crash does, and those are opposite claims.
snyk_scan() {
    local label="$1"
    shift
    local out rc first

    printf '\n--- %s ---\n' "$label"
    out="$("$SNYK_BIN" "$@" 2>&1)"
    rc=$?
    first="$(printf '%s\n' "$out" | grep -vE '^[[:space:]]*$' | head -n1 | cut -c1-100)"

    case "$rc" in
        0) printf '%s\n' "$out"; say "$label: RAN, nothing found"; ran=$((ran + 1)) ;;
        1) printf '%s\n' "$out"; say "$label: RAN, findings above"; ran=$((ran + 1)); found=1 ;;
        3) warn "$label: SKIP, no supported project in scope (exit 3)" ;;
        *)
            if printf '%s' "$out" | grep -q 'SNYK-CODE-0005'; then
                warn "$label: SKIP, Snyk Code is not enabled for this organisation (exit $rc)."
                warn "  Not a crash and not a clean scan. Enable Snyk Code in the org's settings."
            else
                warn "$label: SKIP, exit $rc: $first"
            fi
            ;;
    esac
}

cmd_snyk() {
    local line status path ran=0 found=0

    line="$(probe_one snyk)"
    status="$(printf '%s' "$line" | cut -f1)"
    path="$(printf '%s' "$line" | cut -f3)"

    case "$status" in
        ABSENT)
            warn "snyk not installed: both scans SKIP. Install it with: bun add -g snyk"
            return 2
            ;;
        NOAUTH)
            warn "snyk installed but not authenticated: both scans SKIP. Authenticate with: snyk auth"
            return 2
            ;;
    esac

    SNYK_BIN="$path"
    say "snyk $(version_of "$path") ($path), scanning $ROOT"
    say "'snyk test' sends the dependency graph only; 'snyk code test' uploads source to Snyk"

    snyk_scan "snyk test (dependencies)" test --severity-threshold=low "$ROOT"
    snyk_scan "snyk code test (source)" code test --severity-threshold=low "$ROOT"

    printf '\n'
    if [ "$ran" -eq 0 ]; then
        warn "neither scan ran. This is not a clean result."
        return 2
    fi
    [ "$found" -eq 1 ] && return 1
    if [ "$ran" -lt 2 ]; then
        # Exit 0 here would be indistinguishable from a complete clean scan, and on an account
        # without Snyk Code enabled this is the usual outcome rather than an edge case. The SKIP
        # line above says so in words; a caller gating on the exit code cannot read words, which is
        # the whole reason this suite refuses to let a check that did not run look like a pass.
        warn "$ran of 2 scans ran and found nothing. Incomplete, not clean: see the SKIP above."
        return 3
    fi
    say "both scans ran, nothing found."
    return 0
}

# --------------------------------------------------------------- dispatch ---
usage() { awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; }

CMD="${1:-probe}"
ROOT="${2:-.}"
case "$CMD" in
    probe)   cmd_probe ;;
    tsv)     cmd_tsv ;;
    snyk)    cmd_snyk ;;
    install) cmd_install ;;
    -h|--help|help) usage ;;
    *) warn "unknown command: $CMD"; usage >&2; exit 2 ;;
esac
