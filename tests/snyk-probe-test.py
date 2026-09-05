#!/usr/bin/env python3
"""Proves check_snyk_probe can actually fail. Stdlib only.

snyk is the first tool in the suite that can be installed and still unusable, so it is the first one
whose probe has to ask two questions instead of one. The check that enforces that is only worth
having if it rejects each way the discipline can be dropped, and the only way to know it does is to
drop them one at a time and watch.

One case here is not about a rule failing but about a rule being scoped correctly: the skill is
allowed to *name* `snyk config get api` in prose, because writing down why it is the wrong probe is
what stops a later editor swapping it back in. It is only banned from the probe block. A file-wide
ban would have been simpler to write and would have deleted that note, so the scoping is deliberate
and gets a test of its own.

Each case copies the real tree to a temp dir, points validate.ROOT at the copy, mutates one thing,
and asserts on what lands in failures. Nothing here touches the working tree.
"""
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate as v  # noqa: E402

REAL_ROOT = Path(__file__).resolve().parent.parent
SKILL = "skills/security-review/SKILL.md"
passed = 0
failed = 0


def ok(label):
    global passed
    passed += 1
    print(f"  pass  {label}")


def bad(label, detail):
    global failed
    failed += 1
    print(f"  FAIL  {label} -- {detail}")


def run_case(label, mutate, expect_fail=None, expect_clean=False):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(REAL_ROOT / "skills", root / "skills")
        shutil.copy2(REAL_ROOT / "review-tools.sh", root / "review-tools.sh")
        mutate(root)

        original_root = v.ROOT
        v.ROOT = root
        v.failures.clear()
        v.warnings.clear()
        try:
            v.check_snyk_probe()
            fails = list(v.failures)
        finally:
            v.ROOT = original_root
            v.failures.clear()
            v.warnings.clear()

    if expect_clean:
        if fails:
            bad(label, f"expected clean, got {fails}")
        else:
            ok(label)
        return
    if any(expect_fail in f for f in fails):
        ok(label)
    else:
        bad(label, f"no failure containing {expect_fail!r}; got {fails}")


def edit(path, old, new):
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{path}: anchor {old!r} not present"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def skill(old, new):
    return lambda root: edit(root / SKILL, old, new)


def script(old, new):
    return lambda root: edit(root / "review-tools.sh", old, new)


print("snyk probe branch tests")

run_case("unmutated tree is clean",
         lambda root: None, expect_clean=True)

run_case("a probe block with no PATH check is rejected",
         skill("command -v snyk\n", ""),
         expect_fail="no 'command -v snyk' line")

# The auth line lives in the fenced block; the section also discusses `snyk whoami` in prose and
# again in the four-states table. Deleting only the executable line has to fail, or the rule is
# satisfied by commentary and the probe can quietly stop probing.
run_case("deleting the auth line but keeping the prose is rejected",
         skill("snyk whoami --experimental   # exit 0 = authenticated; prints a username, never the token\n", ""),
         expect_fail="never runs an auth check")

run_case("probing auth with the token-printing command is rejected",
         skill("command -v snyk\n", "command -v snyk\nsnyk config get api\n"),
         expect_fail="prints the token")

run_case("naming the token-printing command in prose stays clean",
         lambda root: None, expect_clean=True)

run_case("dropping the unauthenticated-is-a-skip statement is rejected",
         skill("**Installed but not authenticated is a skipped check**, never a pass and never a finding.",
               "**Installed but not authenticated is worth noticing.**"),
         expect_fail="never says on one line")

run_case("naming 'snyk auth' without the suggest-don't-run qualifier is rejected",
         skill("Both are the user's call:", "Both are needed:"),
         expect_fail="without the suggest-don't-run qualifier")

run_case("dropping snyk from the script's TOOLS list is rejected",
         script("semgrep gitleaks trivy snyk", "semgrep gitleaks trivy"),
         expect_fail="absent from TOOLS")

run_case("dropping the standalone dispatch case is rejected",
         script("    snyk)    cmd_snyk ;;\n", ""),
         expect_fail="no 'snyk)' dispatch case calling cmd_snyk")

# The premise of the "stays clean" case above: if the prose warning is ever deleted, that case stops
# testing the scoping and silently becomes a duplicate of the unmutated one.
text = (REAL_ROOT / SKILL).read_text(encoding="utf-8")
probe = v.section(text, "Capability probe")
blocks = "\n".join(re.findall(r"```(?:bash|sh)?\n(.*?)```", probe or "", re.S))
if "snyk config get api" in (probe or "") and "snyk config get api" not in blocks:
    ok("the prose warning exists, so the scoping case tests scoping")
else:
    bad("the prose warning exists, so the scoping case tests scoping",
        "the skill no longer names 'snyk config get api' outside its probe block")

print()
if failed:
    print(f"FAILURES PRESENT ({failed} failed, {passed} passed)")
    sys.exit(1)
print(f"snyk probe branch tests passed ({passed} checks)")
