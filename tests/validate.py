#!/usr/bin/env python3
"""Structural validator for claude-review-suite. Stdlib only."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ["code-review", "security-review", "review-go", "review-bash",
          "review-vue-ts", "review-php"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
CONFIDENCES = ["Confirmed", "Likely", "Speculative"]
STATUSES = ["FIXED", "SKIPPED-STALE", "SKIPPED-DISAGREE"]

failures = []
warnings = []


def fail(msg):
    failures.append(msg)


def warn(msg):
    warnings.append(msg)


def read(rel):
    path = ROOT / rel
    if not path.exists():
        fail(f"missing file: {rel}")
        return None
    return path.read_text(encoding="utf-8")


def load_json(rel):
    text = read(rel)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"{rel}: invalid JSON: {exc}")
        return None


def check_manifests():
    plugin = load_json(".claude-plugin/plugin.json")
    if plugin:
        for key in ("name", "description", "version", "author", "license"):
            if key not in plugin:
                fail(f"plugin.json: missing key {key!r}")
        if plugin.get("name") != "claude-review-suite":
            fail("plugin.json: name must be 'claude-review-suite'")
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(plugin.get("version", ""))):
            fail("plugin.json: version must be semver x.y.z")

    market = load_json(".claude-plugin/marketplace.json")
    if market and plugin:
        entries = market.get("plugins") or []
        if len(entries) != 1:
            fail("marketplace.json: expected exactly one plugin entry")
        else:
            entry = entries[0]
            if entry.get("name") != plugin.get("name"):
                fail("marketplace.json: plugin name disagrees with plugin.json")
            if entry.get("version") != plugin.get("version"):
                fail("marketplace.json: version disagrees with plugin.json")
            if entry.get("source") != "./":
                fail("marketplace.json: source must be './'")


def check_references():
    rubric = read("references/rubric.md")
    if rubric:
        for sev in SEVERITIES:
            if not re.search(rf"^\|?\s*\*?\*?{sev}\b", rubric, re.M):
                fail(f"rubric.md: severity {sev!r} not defined")
        for conf in CONFIDENCES:
            if conf not in rubric:
                fail(f"rubric.md: confidence {conf!r} not defined")
        for heading in ("## Severity", "## Confidence", "## Finding format",
                        "## One defect matching several checklist rows"):
            if heading not in rubric:
                fail(f"rubric.md: missing section {heading!r}")

    proc = read("references/procedure.md")
    if proc:
        if "command -v" not in proc:
            fail("procedure.md: capability probe pattern 'command -v' not documented")
        for heading in ("## Capability probe", "## Language detection",
                        "## Report skeleton", "## Error handling"):
            if heading not in proc:
                fail(f"procedure.md: missing section {heading!r}")
        for case in ("crash", "no findings", "Checks skipped"):
            if case.lower() not in proc.lower():
                fail(f"procedure.md: error handling does not cover {case!r}")

    prompt = read("references/agent-prompt.md")
    if prompt:
        for token in ("Anchor:", "Issue:", "Expect:", "~L"):
            if token not in prompt:
                fail(f"agent-prompt.md: template missing {token!r}")
        for status in STATUSES:
            if status not in prompt:
                fail(f"agent-prompt.md: status {status!r} not in the required table")
        if "all severities" not in prompt.lower():
            fail("agent-prompt.md: must state the block carries all severities")


ANCHOR_RE = re.compile(r"^\s*Anchor:\s+`(?P<anchor>.+)`\s*$")
ENTRY_RE = re.compile(
    r"^\[(?P<id>F\d+)\]\s+(?P<severity>\w+)\s+·\s+@(?P<path>[^,]+),\s+~(?P<lines>L[\d\-]+)\s*$")


def parse_block(text):
    """Parse an agent prompt block into findings. Malformed entries simply do not parse, which is
    what the caller asserts against."""
    findings, current = [], None
    for line in text.splitlines():
        entry = ENTRY_RE.match(line)
        if entry:
            if current:
                findings.append(current)
            current = dict(entry.groupdict())
            continue
        if current is None:
            continue
        anchor = ANCHOR_RE.match(line)
        if anchor:
            current["anchor"] = anchor.group("anchor")
        for field in ("Issue", "Expect"):
            m = re.match(rf"^\s*{field}:\s+(?P<v>\S.*)$", line)
            if m:
                current[field.lower()] = m.group("v").strip()
    if current:
        findings.append(current)
    return findings


def check_agent_prompt_parses():
    sample = read("tests/fixtures/agent-prompt/sample-block.md")
    if sample is None:
        return
    findings = parse_block(sample)
    if len(findings) < 2:
        fail("sample-block.md: expected at least two findings to parse")
    for f in findings:
        for field in ("anchor", "issue", "expect"):
            if not f.get(field):
                fail(f"sample-block.md: {f['id']} missing {field}")
        if f["severity"] not in SEVERITIES:
            fail(f"sample-block.md: {f['id']} severity {f['severity']!r} not in rubric")
        if f.get("anchor", "").strip() in ("", "..."):
            fail(f"sample-block.md: {f['id']} anchor is not a usable literal snippet")
    ids = [f["id"] for f in findings]
    if ids != sorted(ids, key=lambda s: int(s[1:])):
        fail("sample-block.md: finding IDs are not in ascending order")
    for status in STATUSES:
        if status not in sample:
            fail(f"sample-block.md: status table missing {status!r}")


ID_RE = re.compile(r"\b((?:GO|SH|VT|PHP|GEN|SEC)-\d\d)\b")

TOOLS = {
    "review-go": ["go vet", "staticcheck", "gosec", "govulncheck", "errcheck"],
    "review-bash": ["shellcheck", "shfmt"],
    "review-vue-ts": ["tsc --noEmit", "eslint", "bun audit", "knip"],
    "review-php": ["php -l", "phpstan", "composer audit"],
    "security-review": ["semgrep", "gitleaks", "trivy"],
}

# A skill *declares* only the IDs in its own prefix. Where a skill cites another skill's ID -- as
# security-review does when weighting the language rows -- that is a cross-reference, not a
# declaration, and it must not pull fixture-coverage duty onto the citing skill.
ID_PREFIX = {
    "code-review": "GEN",
    "security-review": "SEC",
    "review-go": "GO",
    "review-bash": "SH",
    "review-vue-ts": "VT",
    "review-php": "PHP",
}

FIXTURE_DIRS = {
    "review-go": "tests/fixtures/go",
    "review-bash": "tests/fixtures/bash",
    "review-vue-ts": "tests/fixtures/vue-ts",
    "review-php": "tests/fixtures/php",
    "code-review": "tests/fixtures/general",
    "security-review": "tests/fixtures/security",
}


def frontmatter(text):
    """Split YAML frontmatter from body. Only flat `key: value` pairs are supported."""
    if not text.startswith("---\n"):
        return None, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return None, text
    raw = text[4:end]
    data = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            data[key.strip()] = value.strip()
    data["__raw__"] = text[: end + 5]
    return data, text[end + 5:]


def check_skill_frontmatter():
    for name in SKILLS:
        rel = f"skills/{name}/SKILL.md"
        text = read(rel)
        if text is None:
            continue
        fm, body = frontmatter(text)
        if fm is None:
            fail(f"{rel}: no YAML frontmatter")
            continue
        keys = {k for k in fm if k != "__raw__"}
        if keys != {"name", "description"}:
            fail(f"{rel}: frontmatter keys must be exactly name+description, got {sorted(keys)}")
        if len(fm["__raw__"]) > 1024:
            fail(f"{rel}: frontmatter is {len(fm['__raw__'])} chars, limit 1024")
        if fm.get("name") != name:
            fail(f"{rel}: frontmatter name {fm.get('name')!r} != directory {name!r}")
        if not re.fullmatch(r"[A-Za-z0-9-]+", fm.get("name", "")):
            fail(f"{rel}: name may only contain letters, numbers, hyphens")
        desc = fm.get("description", "")
        if not desc.startswith("Use when"):
            fail(f"{rel}: description must start with 'Use when'")
        if len(desc) > 500:
            warn(f"{rel}: description is {len(desc)} chars (aim for <500)")
        # Third person applies to the skill's own prose, not to trigger phrasings it quotes --
        # "before I merge" is a user utterance and belongs in the description verbatim.
        prose = re.sub(r'"[^"]*"', "", desc).lower()
        for pronoun in (" i ", " i'", " we ", " you "):
            if pronoun in f" {prose} ":
                fail(f"{rel}: description must be third person (found {pronoun.strip()!r} "
                     f"outside a quoted trigger phrase)")
        # every skill emits the shared artifacts, so every skill must link the machinery
        for ref in ("../../references/rubric.md", "../../references/procedure.md",
                    "../../references/agent-prompt.md"):
            if ref not in body:
                fail(f"{rel}: body does not reference {ref}")
        if "Checks skipped" not in body:
            fail(f"{rel}: body must require a 'Checks skipped' section")
        for ref in re.findall(r"\.\./\.\./([A-Za-z0-9_./-]+\.md)", body):
            if not (ROOT / ref).exists():
                fail(f"{rel}: dangling reference ../../{ref}")


def check_tool_probes():
    for name, tools in TOOLS.items():
        text = read(f"skills/{name}/SKILL.md")
        if text is None:
            continue
        for tool in tools:
            if tool not in text:
                fail(f"skills/{name}/SKILL.md: tool probe {tool!r} not listed")
        binary = tools[0].split()[0]
        if f"command -v {binary}" not in text:
            fail(f"skills/{name}/SKILL.md: no 'command -v {binary}' probe line")


def check_checklist_coverage():
    """Every checklist ID a skill declares must be planted in that skill's vulnerable fixtures,
    and every ID planted in a fixture must be declared by a skill. Silent gaps are a defect."""
    declared, cited = {}, {}
    for name in SKILLS:
        text = read(f"skills/{name}/SKILL.md")
        if text is None:
            continue
        found = set(ID_RE.findall(text))
        prefix = ID_PREFIX[name] + "-"
        ids = {i for i in found if i.startswith(prefix)}
        if not ids:
            fail(f"skills/{name}/SKILL.md: declares no {prefix}nn checklist IDs")
        declared[name] = ids
        cited[name] = found - ids

    # A cross-reference to an ID no skill declares is a typo that would send a reader looking for a
    # checklist row that does not exist.
    every_id = set().union(*declared.values()) if declared else set()
    for name, refs in cited.items():
        for dangling in sorted(refs - every_id):
            fail(f"skills/{name}/SKILL.md: cites {dangling}, which no skill declares")

    for name, ids in declared.items():
        fixture_dir = ROOT / FIXTURE_DIRS[name]
        if not fixture_dir.is_dir():
            fail(f"missing fixture directory: {FIXTURE_DIRS[name]}")
            continue
        vulnerable, clean = {}, []
        for path in sorted(fixture_dir.iterdir()):
            if not path.is_file():
                continue
            body = path.read_text(encoding="utf-8")
            planted = set(re.findall(r"VULN:\s*((?:GO|SH|VT|PHP|GEN|SEC)-\d\d)", body))
            if path.name.startswith("vulnerable"):
                if not planted:
                    fail(f"{path.relative_to(ROOT)}: vulnerable fixture plants no 'VULN: <ID>'")
                vulnerable[path.name] = planted
            elif path.name.startswith("clean"):
                clean.append(path)
                if planted:
                    fail(f"{path.relative_to(ROOT)}: clean fixture must not plant VULN ids")
                if "CLEAN-FIXTURE" not in body:
                    fail(f"{path.relative_to(ROOT)}: clean fixture must be marked CLEAN-FIXTURE")
        if not clean:
            fail(f"{FIXTURE_DIRS[name]}: no clean fixture (false-positive check needs one)")
        covered = set().union(*vulnerable.values()) if vulnerable else set()
        for missing in sorted(ids - covered):
            fail(f"{name}: checklist {missing} has no fixture coverage")
        for stray in sorted(covered - ids):
            fail(f"{FIXTURE_DIRS[name]}: plants {stray}, which {name} does not declare")


VULN_RE = re.compile(r"VULN:\s*((?:GO|SH|VT|PHP|GEN|SEC)-\d\d)")
COMMENT_PREFIXES = {
    ".sh": ("#",),
    ".py": ("#",),
    ".go": ("//",),
    ".ts": ("//",),
    ".php": ("//", "#"),
    ".vue": ("//", "<!--"),
}
ANCHOR_RE_PRESENT = re.compile(r"(?<!-)\bANCHOR:\s*(?P<anchor>\S.*?)\s*$")
ANCHOR_RE_ABSENT = re.compile(r"\bANCHOR-ABSENT:\s*(?P<anchor>\S.*?)\s*$")


def check_vuln_anchors():
    """The comment is not the defect. Every `VULN: <ID>` must carry an anchor naming the defective
    construct, and that anchor must still hold against the code.

    Without this, `check_checklist_coverage` passes on a fixture whose defect has been quietly
    fixed -- the annotation survives the edit that removes the vulnerability, so coverage is
    asserted against a comment rather than against code. That is exactly the silent gap this suite
    tells reviewers to look for, and it lived in this validator until 2026-07-25.

    Two forms, because not every defect is a construct you can point at:

      ANCHOR:        <literal>   the defective construct; must still appear
      ANCHOR-ABSENT: <literal>   the guard whose absence *is* the defect; must not appear

    A planted omission -- no `set -euo pipefail`, no CSRF header, no bounds check -- has nothing to
    match, so anchoring it positively is impossible. ANCHOR-ABSENT inverts the assertion and fails
    the moment someone adds the missing guard without removing the annotation.

    Anchoring by content rather than line number is the same rule `references/agent-prompt.md`
    imposes on every finding the suite emits.

    The honest limit: an anchor catches a defect that was *removed or rewritten*, which is the
    realistic drift. It cannot catch a fix that leaves the anchored text in place and neutralises
    it elsewhere -- adding an early return above an anchored dereference, say. That residue is what
    the differential tests are for."""
    for name in SKILLS:
        fixture_dir = ROOT / FIXTURE_DIRS[name]
        if not fixture_dir.is_dir():
            continue
        for path in sorted(fixture_dir.glob("vulnerable*")):
            if not path.is_file():
                continue
            rel = path.relative_to(ROOT)
            lines = path.read_text(encoding="utf-8").splitlines()

            # An anchor literal would trivially match its own annotation, so the haystack is the
            # file with every anchor line removed.
            haystack = "\n".join(
                l for l in lines if "ANCHOR:" not in l and "ANCHOR-ABSENT:" not in l)

            # Absence is asserted against code only. A fixture that plants "no `set -euo pipefail`"
            # names the missing guard in its own prose -- that is the annotation doing its job, not
            # the guard being present, and matching against comments would fail every such row.
            prefixes = COMMENT_PREFIXES.get(path.suffix, ("#",))
            code_only = "\n".join(
                l for l in haystack.splitlines()
                if not l.strip().startswith(prefixes))

            for idx, line in enumerate(lines):
                vuln = VULN_RE.search(line)
                if not vuln:
                    continue
                vid = vuln.group(1)

                # The anchor follows the VULN block; scan forward past the rest of a wrapped
                # comment, stopping at the next VULN annotation.
                anchor, absent = None, False
                for ahead in lines[idx + 1:idx + 10]:
                    if VULN_RE.search(ahead):
                        break
                    gone = ANCHOR_RE_ABSENT.search(ahead)
                    if gone:
                        anchor, absent = gone.group("anchor"), True
                        break
                    found = ANCHOR_RE_PRESENT.search(ahead)
                    if found:
                        anchor = found.group("anchor")
                        break

                if anchor is None:
                    fail(f"{rel}: {vid} has no ANCHOR:/ANCHOR-ABSENT: line, so nothing proves the "
                         f"defect still exists -- fixing the code would leave this annotation "
                         f"passing")
                    continue
                if len(anchor) < 8:
                    fail(f"{rel}: {vid} anchor {anchor!r} is too short to be distinctive")
                    continue
                # An anchor that also appears in the clean counterpart is true of the *correct*
                # version, so it can never detect the defect being fixed. VT-05 shipped with
                # exactly that bug -- it anchored a `defineProps<...>` line byte-identical in
                # clean.vue, because its defect is the absence of validation rather than the
                # presence of any construct -- and a blind review caught it by applying the real
                # fix and watching this validator stay green.
                if not absent:
                    for clean_path in sorted(fixture_dir.glob("clean*")):
                        if not clean_path.is_file():
                            continue
                        clean_body = "\n".join(
                            l for l in clean_path.read_text(encoding="utf-8").splitlines()
                            if "ANCHOR" not in l)
                        if anchor in clean_body:
                            fail(f"{rel}: {vid} anchor {anchor!r} also appears in "
                                 f"{clean_path.name}, so it is true of the corrected code and "
                                 f"cannot detect this defect being fixed")

                if absent and anchor in code_only:
                    fail(f"{rel}: {vid} is annotated as a missing {anchor!r}, but that now appears "
                         f"in the file -- the guard was added and the annotation was not removed")
                elif not absent and anchor not in haystack:
                    fail(f"{rel}: {vid} anchor {anchor!r} no longer appears in the file -- the "
                         f"planted defect was changed or removed but its annotation was not")


LANGUAGE_SKILLS = ["review-go", "review-bash", "review-vue-ts", "review-php"]
LANGUAGE_TOKENS = {
    "review-go": [r"\bGo\b", r"\.go\b"],
    "review-bash": [r"\bshell\b", r"\.sh\b"],
    "review-vue-ts": [r"\bVue\b", r"\bTypeScript\b"],
    "review-php": [r"\bPHP\b"],
}


def check_delegation():
    for name in ("code-review", "security-review"):
        text = read(f"skills/{name}/SKILL.md")
        if text is None:
            continue
        _, body = frontmatter(text)
        for target in LANGUAGE_SKILLS:
            if target not in body:
                fail(f"skills/{name}/SKILL.md: does not delegate to {target}")
        if "@skills/" in body or "@references/" in body:
            fail(f"skills/{name}/SKILL.md: uses an @ path link (force-loads context)")
        if "merge" not in body.lower():
            fail(f"skills/{name}/SKILL.md: does not say how multi-language findings merge")


def check_trigger_distinctness():
    """Entry points match intent; language skills match language + intent. Descriptions must not
    contend."""
    descs = {}
    for name in SKILLS:
        text = read(f"skills/{name}/SKILL.md")
        if text is None:
            continue
        fm, _ = frontmatter(text)
        if fm:
            descs[name] = fm.get("description", "")

    for name, patterns in LANGUAGE_TOKENS.items():
        desc = descs.get(name, "")
        if not any(re.search(p, desc) for p in patterns):
            fail(f"{name}: description names no language token, so it cannot win on language")
        for entry in ("code-review", "security-review"):
            for pattern in patterns:
                if re.search(pattern, descs.get(entry, "")):
                    fail(f"{entry}: description contains language token {pattern!r} — "
                         f"contends with {name}")

    if not re.search(r"secur|vuln|audit|exploit", descs.get("security-review", ""), re.I):
        fail("security-review: description carries no security intent words")
    if re.search(r"\bvuln|\bexploit", descs.get("code-review", ""), re.I):
        fail("code-review: description carries security intent words — contends with "
             "security-review")


def check_installer_is_suggested_not_run():
    """review-tools.sh is the user's to run. Every skill must name it so a missing toolchain has a
    one-shot remedy in the report, and no skill may instruct itself to execute it."""
    if not (ROOT / "review-tools.sh").exists():
        fail("missing file: review-tools.sh")

    targets = [f"skills/{name}/SKILL.md" for name in SKILLS] + ["references/procedure.md"]
    for rel in targets:
        text = read(rel)
        if text is None:
            continue
        if "review-tools.sh" not in text:
            fail(f"{rel}: does not mention review-tools.sh, so a missing toolchain has no remedy")
            continue
        # The distinction that matters: suggesting the installer is the point, running it is not.
        # Scoped by paragraph, because the qualifier routinely lands on a following wrapped line.
        qualifier = re.compile(
            r"leave running it|suggest it|never run it|do not run|does not install|"
            r"user's decision|user's call|the user decides",
            re.I,
        )
        for para in re.split(r"\n\s*\n", text):
            if re.search(r"review-tools\.sh\s+install", para) and not qualifier.search(para):
                first = para.strip().splitlines()[0]
                fail(f"{rel}: names 'review-tools.sh install' without the suggest-don't-run "
                     f"qualifier in the same paragraph: {first[:70]!r}")


def check_nvd_enrichment():
    """The NVD enrichment feature carries one rule that keeps it from degrading the reports it
    decorates: a CVSS score is evidence, never severity. rubric.md makes reachability drive
    severity, so a 9.8 in unreachable code is still Medium here. If someone adds the feature and
    drops the rule, the reports quietly become a CVSS dump. Hence a check rather than a paragraph.

    nvd-enrich.sh deliberately stays out of the TOOLS dict: check_tool_probes requires a literal
    'command -v <binary>' line, and this script is invoked by relative path, never resolved on
    PATH."""
    if not (ROOT / "nvd-enrich.sh").exists():
        fail("missing file: nvd-enrich.sh")

    rel = "skills/security-review/SKILL.md"
    text = read(rel)
    if text is None:
        return

    if "../../nvd-enrich.sh --check" not in text:
        fail(f"{rel}: no '../../nvd-enrich.sh --check' probe line")
    # A bare "nvd-enrich.sh" also occurs in the probe line and in the Procedure list's "Enrich the
    # CVEs" step, both of which precede "## Threat checklist" too -- matching that substring alone
    # would pass with the table row deleted. The row form (`nvd-enrich.sh` inside pipe delimiters)
    # is what makes this a *table* citation rather than any other mention.
    if not re.search(r"\|\s*`nvd-enrich\.sh`\s*\|", text.split("## Threat checklist")[0]):
        fail(f"{rel}: nvd-enrich.sh is not listed in the capability table")

    calibration = text.split("## Severity calibration")
    if len(calibration) < 2:
        fail(f"{rel}: missing '## Severity calibration' section")
    elif not re.search(r"evidence,\s*never\s*severity", calibration[1], re.I):
        fail(f"{rel}: severity calibration must state that CVSS is evidence, never severity")

    # Scoped to the Output section, where this guidance belongs, rather than split on every heading
    # in the document: an unscoped split lets "nvd" from the probe line or the Procedure step pair
    # with the pre-existing, unrelated "## Checks skipped" mention in Capability probe (about
    # review-tools.sh) and pass without this guidance existing at all.
    output = text.split("## Output")
    if len(output) < 2:
        fail(f"{rel}: missing '## Output' section")
    elif not (re.search(r"\bnvd\b", output[1], re.I) and "skipped" in output[1].lower()):
        fail(f"{rel}: 'Checks skipped' guidance does not name NVD enrichment")

    proc = read("references/procedure.md")
    if proc and "NVD:" not in proc:
        fail("procedure.md: finding format does not carry the optional 'NVD:' line")


CHECKS = [check_manifests, check_references, check_agent_prompt_parses,
          check_skill_frontmatter, check_tool_probes, check_checklist_coverage,
          check_vuln_anchors, check_delegation, check_trigger_distinctness,
          check_installer_is_suggested_not_run, check_nvd_enrichment]


def main():
    for check in CHECKS:
        check()
    for msg in warnings:
        print(f"WARN  {msg}")
    for msg in failures:
        print(f"FAIL  {msg}")
    total = len(CHECKS)
    if failures:
        print(f"\n{len(failures)} failure(s) across {total} check group(s)")
        return 1
    print(f"OK    {total} check group(s) passed, {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
