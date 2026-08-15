# CLAUDE.md

A Claude Code plugin: six review skills published through a marketplace. `README.md` covers what
each skill does. This file covers what you cannot see by reading the tree.

## Commands

```bash
python3 tests/validate.py   # structural validator alone, stdlib only, no network
bash tests/run.sh           # validator + every installed linter, against the fixtures
./review-tools.sh probe     # which analysers are present (default subcommand)
```

Both test entry points must pass before anything is called done.

## The invariant

**The suite reports. It does not auto-fix.** Every skill emits a human report plus a machine-readable
agent prompt block for a downstream agent to act on, with mandatory re-verification so a stale
finding is never blindly applied. A change that makes a skill edit code directly breaks the product.

## An absent tool is a SKIP

Never a pass, never a failure. This is the single discipline the whole suite exists to enforce, and
it is easy to erode by accident:

- "gosec found nothing" and "gosec did not run" are opposite claims. Conflating them is the most
  dangerous thing a review can do.
- **A tool that crashed is a skipped check, never a clean result.**
- A check with no fixtures to run against is also a SKIP. An empty run reporting PASS is the exact
  silent gap this repo is written to prevent.
- Every check that did not run must appear in the report's `## Checks skipped` table with a reason
  and an install hint. Nothing needs to be installed for a review to complete.

`review-tools.sh install` is a suggestion to surface to the user, never something to run for them.
This is machine-enforced: `check_installer_is_suggested_not_run` fails any skill that names
`review-tools.sh install` in a paragraph without a suggest-don't-run qualifier.

## Severity comes from reachability, not from CVSS

`rubric.md` makes reachability drive severity, so **a CVSS 9.8 in unreachable code is still Medium
here**. A CVSS score is evidence, never severity. Drop that rule and the reports quietly degrade
into a CVSS dump, which is why `check_nvd_enrichment` enforces it rather than a paragraph asking
nicely.

`nvd-enrich.sh` deliberately stays out of the `TOOLS` dict: `check_tool_probes` requires a literal
`command -v <binary>` line, and this script is invoked by relative path, never resolved on `PATH`.

## Contracts the validator enforces

Changing a skill or fixture means satisfying `tests/validate.py`. It has **12 check groups**, not
the five spelled out below. Read the group that failed before guessing at the rule.

- **Skill frontmatter** (`check_skill_frontmatter`): exactly `name` + `description`, under 1024
  chars, `name` matching the directory, description starting with "Use when" and in third person
  outside quoted trigger phrases, links to all three `references/` docs, a "Checks skipped"
  requirement, no dangling reference paths.
- **Fixtures** (`check_checklist_coverage`, `check_vuln_anchors`): every checklist row a skill
  declares is planted in one of that skill's `vulnerable*` fixtures, and every ID planted is
  declared by the owning skill. Each fixture directory needs at least one `clean*` file, marked
  `CLEAN-FIXTURE` and planting no IDs, or the false-positive side goes untested. Every `VULN: <ID>`
  carries either an `ANCHOR:` naming a construct that must still be present, or an `ANCHOR-ABSENT:`
  naming a guard whose absence is the defect. **The comment is not the defect**. Fixing a plant
  without removing its annotation fails here.
- **Delegation** (`check_delegation`): the two entry points delegate to all four language skills,
  say how findings merge, and use no `@skills/` or `@references/` link, because an `@` path
  force-loads that file into context.
- **Manifests** (`check_manifests`): `.claude-plugin/plugin.json` and `marketplace.json` must agree
  on name and version.

The other seven are worth knowing before you edit a skill, since each one fails on something easy
to do by accident: `check_changelog`, `check_references`, `check_agent_prompt_parses`,
`check_tool_probes` (every tool assigned to a skill must be named in its `SKILL.md`, and the first
one needs a literal `command -v <binary>` line), `check_trigger_distinctness` (entry points match
intent, language skills match language + intent, and descriptions must not contend),
`check_installer_is_suggested_not_run`, and `check_nvd_enrichment`.

## Checklist IDs

`GEN-01`…`07` (code-review), `SEC-01`…`07` (security-review), `GO-01`…`07`, `SH-01`…`07`,
`VT-01`…`07`, `PHP-01`…`06`. `security-review` cross-references IDs it does not own; those must
still exist in the owning skill.

## Releasing

A release is **three** edits, not two: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`
(these two must agree on name and version), and a `CHANGELOG.md` entry.

`check_changelog` gates all of it. The newest CHANGELOG entry must name the version the manifests
ship, every entry must be `## [x.y.z] - YYYY-MM-DD` in descending version order, and every entry
needs a matching link definition (and vice versa, so a renumbered version leaves no orphan).

## Accuracy is the product

This repo reviews other people's code for false confidence, so it cannot ship its own. A claim that
turns out to be false, or a test that cannot fail, gets fixed in the cycle it is found, whatever
severity it was rated. Do not defer it to a follow-up.
