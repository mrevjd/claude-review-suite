# claude-review-suite

Six Claude Code skills that review code for correctness and security, emit a human-readable report,
and emit a machine-consumable prompt block a downstream coding agent can act on — with mandatory
re-verification, so a stale finding is never blindly applied.

The suite reports. It does not auto-fix.

## Install

```
/plugin marketplace add mrevjd/claude-review-suite
/plugin install claude-review-suite@claude-review-suite
```

Optionally install the analysers the skills probe for — see [Toolchain](#toolchain):

```bash
./review-tools.sh probe      # what's present
./review-tools.sh install    # install what isn't
```

## Skills

| Skill | Triggers on | Carries |
|---|---|---|
| `code-review` | "review this", "look over this PR", "before I merge", "any bugs in this" | General checklist `GEN-01`…`GEN-07`; detects languages and delegates |
| `security-review` | "security review", "audit this", "check for vulns", "is this exploitable" | Threat checklist `SEC-01`…`SEC-07`; `semgrep`, `gitleaks`, `trivy` |
| `review-go` | `.go` files, "review this Go service" | `GO-01`…`GO-07`; `go vet`, `staticcheck`, `gosec`, `govulncheck`, `errcheck` |
| `review-bash` | `.sh`/`.bash` files, a shell shebang, "review this script" | `SH-01`…`SH-07`; `shellcheck`, `shfmt` |
| `review-vue-ts` | `.vue`/`.ts`/`.tsx` files, "review this component" | `VT-01`…`VT-07`; `tsc --noEmit`, `eslint`, `bun audit`, `knip` |
| `review-php` | `.php` files, "audit this endpoint" | `PHP-01`…`PHP-06`; `php -l`, `phpstan`, `composer audit` |

The two entry-point skills detect the languages in the diff or tree and run every language skill that
applies, merging all findings into one severity-ordered list. Each language skill also works
standalone. Languages outside the four — Python, Perl, Ruby, SQL, config — fall through to the
general or threat checklist, and the report says so rather than passing over them in silence.

## Hybrid tooling

Guidance is the baseline; tools sharpen it. Every skill probes with `command -v` before it runs
anything, and every check that did not run is named in a `## Checks skipped` table with a reason and
an install hint. **A tool that crashed is a skipped check, never a clean result** — "gosec found
nothing" and "gosec did not run" are opposite claims, and conflating them is the most dangerous thing
a review can do.

Nothing needs to be installed for a review to complete.

## Toolchain

`review-tools.sh` manages the binaries the skills probe for. It is a convenience, not a dependency —
every skill degrades to its checklist when a tool is absent.

```bash
./review-tools.sh probe      # capability report: status, scope, version   (default)
./review-tools.sh install    # install everything missing
./review-tools.sh tsv        # same probe, tab-separated, for a skill to consume
```

`probe` prints a table and exits with a count of what is missing:

```
TOOL           STATUS   SCOPE   VERSION
staticcheck    PRESENT  global  staticcheck 2026.1 (v0.7.0)
gitleaks       PRESENT  global  gitleaks version 8.30.1
...
0 of 21 absent.
```

**Resolution order** is global first, then project-local (`node_modules/.bin`, `vendor/bin`) — so a
globally installed `eslint` wins over a vendored one. Set `REVIEW_TOOL_PREFER=local` to reverse that,
which is what you want when a project pins a specific analyser version. An optional second argument
sets the directory those project-local paths resolve against: `./review-tools.sh probe ../some-app`.

**`install` writes outside the repository.** Binaries land in `/usr/local/bin`, which needs sudo; set
`PREFIX=$HOME/.local/bin` to install without it. Upstream release binaries are preferred over distro
packages throughout — the distro package manager is used only for `curl`, `tar` and `unzip`, where
staleness is harmless. Anything already on `PATH` is skipped, so re-running is safe.

Versions are read from each binary rather than assumed, falling back to the embedded Go module
version for tools whose `--version` flag is missing or prints usage text. A tool whose version cannot
be determined reports `unknown` rather than being silently reported as fine.

### NVD enrichment

`security-review` annotates every CVE its scanners find with that CVE's CVSS base score, NVD
severity label, CVSS vector, CWE, publication date and NVD analysis status, using `nvd-enrich.sh`.
The score is evidence in the finding, not the finding's severity: reachability decides severity, per
`references/rubric.md`.

It works with no configuration. An API key only raises the rate limit, from 5 requests per 30
seconds to 50, which the script turns into a per-run budget of 8 NVD requests keyless and 50 keyed.
A retry counts against that budget like any other request. `NVD_MAX_LOOKUPS` overrides it: set it
higher for a repository with more CVEs than the cap, or `NVD_MAX_LOOKUPS=0` to answer entirely from
the cache and make no requests at all. A non-numeric value is refused with a warning and the default
is kept, because a cap that silently disappears is worse than one that is too low.

Get a free key at https://nvd.nist.gov/developers/request-an-api-key, then:

```
mkdir -p ~/.config/claude-review-suite
printf 'NVD_API_KEY=your-key-here\n' > ~/.config/claude-review-suite/nvd.env
chmod 600 ~/.config/claude-review-suite/nvd.env
```

The file must be mode 600 or 400. Anything looser is refused rather than read, with the `chmod`
printed, because a credential the whole machine can read is a finding this suite would report in
your code. `NVD_API_KEY` in the environment takes precedence over the file, which is the easier
route in CI.

**If you set `XDG_CONFIG_HOME`, that path is not `~/.config`.** The key file is read from
`${XDG_CONFIG_HOME:-$HOME/.config}/claude-review-suite/nvd.env`, so substitute your own value into
the commands above or the script will never see the file you just created. The cache honours
`XDG_CACHE_HOME` the same way.

Responses cache under `${XDG_CACHE_HOME:-$HOME/.cache}/claude-review-suite/nvd`, keyed off NVD's
analysis status: 7 days for a record NVD has analysed, 24 hours while one is still awaiting
analysis, undergoing analysis, or newly received, and 30 days for a rejected CVE, which will not
change again. Clear it with `rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/claude-review-suite/nvd"`.

Check the setup with `./nvd-enrich.sh --check`, which reports `curl`, `jq`, key source, the cache
path with a count of cached entries, and network reachability, and never prints the key itself.

## Dual output

**1. A human report.** Findings grouped by severity, worst first, each with severity, confidence,
`file:line`, the checklist ID that caught it, what is wrong, why it matters, and a fix direction.
Then the skipped-checks table.

**2. An agent prompt block.** Fenced and copy-pasteable, carrying every severity from Critical to
Low. Four rules make its re-verification real:

- **Anchored by content.** Each finding carries a literal snippet from the cited location. The
  receiving agent relocates the code by matching it; line numbers are marked `~` as hints. A snippet
  that does not match means the finding is `SKIPPED-STALE` by definition.
- **Intent, never a diff.** Each entry states what must be true when the fix is done. A patch would
  get pasted without thought, which is the failure mode the block exists to prevent.
- **Self-contained findings.** The receiving agent has none of the review context, so each entry
  restates enough of the why to be judged alone.
- **A mandatory status table.** Every finding ID returns `FIXED`, `SKIPPED-STALE`, or
  `SKIPPED-DISAGREE` with a reason. Stale and disagree stay distinct: the first says the review aged,
  the second says it may have been wrong, and collapsing them loses the only feedback signal on
  review quality.

Validation commands in the block come from the same probe the review used, so it never tells an agent
to run a binary that is not installed. No findings means no block.

## Layout

```
.claude-plugin/     plugin.json, marketplace.json
references/         rubric.md (severity, confidence, finding format)
                    procedure.md (probe, detection, report skeleton, error handling)
                    agent-prompt.md (block template and fill rules)
skills/             one directory per skill, each a single SKILL.md
tests/              validate.py, run.sh, fixtures/, README.md
review-tools.sh     probe / install / tsv for the tools the skills use
nvd-enrich.sh       CVE IDs on stdin, one enriched TSV row out; see NVD enrichment above
```

All six skills reference the same three documents, which is what lets a Go finding and a Vue finding
merge into one coherent list.

## Testing

```bash
bash tests/run.sh    # structural validator + every installed linter, against the fixtures
```

Each skill has known-vulnerable and known-clean fixtures, with every planted defect annotated
`VULN: <checklist-id>`. The validator enforces that every checklist row has fixture coverage, that the
agent prompt block parses with usable anchors, and that skill descriptions cannot contend for
triggers. The criteria that need a live agent — severity accuracy, false-positive rate, trigger
behaviour — are a documented manual protocol in `tests/README.md`, deliberately not claimed as
automated.

## Name collision

Claude Code ships a built-in `/security-review` command. When both are available, invoke this one as
`claude-review-suite:security-review`.

## License

MIT.
