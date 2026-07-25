#!/usr/bin/env bash
# Criterion 3 -- trigger behaviour. Does each phrasing load the skill it should, and not the one it
# contends with?
#
# Each case runs in a genuinely fresh headless session (`claude -p`) with the plugin installed, so
# the routing decision is made by an agent that has not seen this repository. --allowed-tools Skill
# keeps each run to the routing decision rather than paying for a full review.
#
# Requires the plugin installed: claude plugin install claude-review-suite@claude-review-suite
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT_DIR:-$(mktemp -d)}"
cd "$ROOT" || exit 1

if ! command -v claude >/dev/null 2>&1; then
  echo "SKIP  claude CLI not on PATH -- criterion 3 cannot run" >&2
  exit 0
fi

if ! claude plugin list 2>/dev/null | grep -q 'claude-review-suite'; then
  echo "SKIP  plugin not installed -- run: claude plugin install claude-review-suite@claude-review-suite" >&2
  exit 0
fi

# id | prompt | must load | must not load (comma separated, may be empty)
CASES=(
  "t1|review tests/fixtures/general/vulnerable.py before I merge|code-review|security-review"
  "t2|look over tests/fixtures/general/vulnerable.py|code-review|"
  "t3|audit tests/fixtures/security/vulnerable.py for vulns|security-review|"
  "t4|is tests/fixtures/security/vulnerable.py exploitable?|security-review|code-review"
  "t5|review this Go service: tests/fixtures/go/vulnerable.go|review-go|review-php,review-vue-ts"
  "t6|check this deploy script is safe: tests/fixtures/bash/vulnerable.sh|review-bash|review-go"
  "t7|review this component: tests/fixtures/vue-ts/vulnerable.vue|review-vue-ts|review-php"
  "t8|audit this PHP endpoint: tests/fixtures/php/vulnerable.php|review-php|review-go"
)

echo "running ${#CASES[@]} cases in parallel, output in $OUT"
for entry in "${CASES[@]}"; do
  id="${entry%%|*}"
  rest="${entry#*|}"
  prompt="${rest%%|*}"
  timeout 300 claude -p "$prompt" \
    --output-format stream-json --verbose --allowed-tools Skill \
    >"$OUT/$id.jsonl" 2>&1 &
done
wait

OUT="$OUT" python3 - "${CASES[@]}" <<'PY'
import json, os, sys

out = os.environ["OUT"]
failures = 0

def skills_used(path):
    used = []
    if not os.path.exists(path):
        return None
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            content = (ev.get("message") or {}).get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use" \
                            and block.get("name") == "Skill":
                        skill = block.get("input", {}).get("skill")
                        if skill:
                            used.append(skill)
    return used

print(f"\n{'#':4} {'must load':16} {'fired':34} verdict")
print("-" * 78)
for entry in sys.argv[1:]:
    cid, prompt, must, mustnot = entry.split("|")
    contenders = [c for c in mustnot.split(",") if c]
    used = skills_used(os.path.join(out, f"{cid}.jsonl"))
    if used is None:
        print(f"{cid:4} {must:16} {'(no output)':34} NO DATA")
        failures += 1
        continue
    ours = [s.split(":")[-1] for s in used if s.startswith("claude-review-suite:")]
    fired = ",".join(ours) if ours else "(none)"
    problems = []
    if must not in ours:
        problems.append(f"{must} did not fire")
    hit = [c for c in contenders if c in ours]
    if hit:
        problems.append("contender fired: " + ",".join(hit))
    verdict = "FAIL" if problems else "PASS"
    if problems:
        failures += 1
    print(f"{cid:4} {must:16} {fired:34} {verdict}"
          + (f"  -- {'; '.join(problems)}" if problems else ""))

print()
print(f"{failures} failure(s)" if failures else "ALL TRIGGER CASES PASSED")
sys.exit(1 if failures else 0)
PY
