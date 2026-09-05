#!/usr/bin/env python3
"""Proves check_skill_frontmatter's model/effort branches can actually fail. Stdlib only.

The branches this covers were verified once by hand, and that verification was silently worthless
the first time: the fixture was restored with `git checkout --`, which reverts to the index, so
three of the six cases ran against a file whose `model:` line had already been wiped. Every case
passed and none of them had tested anything.

That is the argument for this file. A check nobody has watched fail is a check nobody knows works,
and this repo's whole product is refusing to report an absent check as a clean one.

Each case copies the real skills tree to a temp dir, points validate.ROOT at the copy, mutates one
line, and asserts on what lands in failures/warnings. Nothing here touches the working tree.
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate as v  # noqa: E402

REAL_ROOT = Path(__file__).resolve().parent.parent
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


def run_case(label, mutate, expect_fail=None, expect_warn=None, expect_clean=False):
    """Copy the tree, apply `mutate(skills_dir)`, run the check against the copy.

    `mutate` receives the temp skills directory so a case can edit one skill or all six: pinning a
    single skill to a different model trips the agreement check as well as the value check, and a
    case that means to test only one of those has to move all six together.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(REAL_ROOT / "skills", root / "skills")
        # check_skill_frontmatter resolves ../../references/*.md against ROOT for its dangling-link
        # rule, so the copy needs them or every case fails for an unrelated reason.
        shutil.copytree(REAL_ROOT / "references", root / "references")
        mutate(root / "skills")

        original_root = v.ROOT
        v.ROOT = root
        v.failures.clear()
        v.warnings.clear()
        try:
            v.check_skill_frontmatter()
            fails = list(v.failures)
            warns = list(v.warnings)
        finally:
            v.ROOT = original_root
            v.failures.clear()
            v.warnings.clear()

    if expect_clean:
        if fails or warns:
            bad(label, f"expected clean, got failures={fails} warnings={warns}")
        else:
            ok(label)
        return
    if expect_fail is not None:
        if any(expect_fail in f for f in fails):
            ok(label)
        else:
            bad(label, f"no failure containing {expect_fail!r}; got {fails}")
        return
    if expect_warn is not None:
        if any(expect_warn in w for w in warns):
            ok(label)
        else:
            bad(label, f"no warning containing {expect_warn!r}; got {warns}")


def edit(path, old, new):
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{path}: anchor {old!r} not present"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def one(name, old, new):
    return lambda skills: edit(skills / name / "SKILL.md", old, new)


def every(old, new):
    def mutate(skills):
        for child in sorted(skills.iterdir()):
            edit(child / "SKILL.md", old, new)
    return mutate


print("frontmatter branch tests")

run_case("unmutated tree is clean",
         lambda skills: None, expect_clean=True)

run_case("unknown key is rejected",
         one("review-go", "effort: xhigh", "effort: xhigh\ncolor: blue"),
         expect_fail="unknown key(s)")

run_case("unrecognised model is rejected",
         every("model: opus", "model: gpt-4"),
         expect_fail="is not one of")

run_case("unrecognised effort is rejected",
         every("effort: xhigh", "effort: ultra"),
         expect_fail="positive integer")

run_case("effort 0 is rejected",
         every("effort: xhigh", "effort: 0"),
         expect_fail="positive integer")

run_case("effort with a leading zero is rejected",
         every("effort: xhigh", "effort: 007"),
         expect_fail="positive integer")

run_case("a positive integer effort is accepted",
         every("effort: xhigh", "effort: 3"),
         expect_clean=True)

run_case("a missing pin is rejected",
         one("review-go", "model: opus\n", ""),
         expect_fail="missing required key(s)")

run_case("pins that disagree are rejected",
         one("review-go", "model: opus", "model: sonnet"),
         expect_fail="disagree on model/effort pins")

# Legal, and deliberately not a failure: the pin works outside auto mode. All six move together so
# the agreement check stays quiet and the warning is the only thing under test.
run_case("a model auto mode discards warns rather than fails",
         every("model: opus", "model: haiku"),
         expect_warn="ignored while auto mode is on")

print()
if failed:
    print(f"FAILURES PRESENT ({failed} failed, {passed} passed)")
    sys.exit(1)
print(f"frontmatter branch tests passed ({passed} checks)")
