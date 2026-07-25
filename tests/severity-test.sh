#!/usr/bin/env bash
# Criterion 1 -- severity accuracy, run blind. tests/README.md's criterion-1 pass was run by the
# fixtures' own author, which only shows the checklists CAN find the defects, not that they lead an
# unprimed reviewer to them. This runs each vulnerable fixture through a genuinely fresh headless
# session (`claude -p`) -- same trick that closed criterion 3 -- and scores the resulting report
# against the fixture's planted VULN IDs.
#
# Requires the plugin installed: claude plugin install claude-review-suite@claude-review-suite
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT_DIR:-$(mktemp -d)}"
cd "$ROOT" || exit 1

if ! command -v claude >/dev/null 2>&1; then
  echo "SKIP  claude CLI not on PATH -- criterion 1 cannot run" >&2
  exit 0
fi

if ! claude plugin list 2>/dev/null | grep -q 'claude-review-suite'; then
  echo "SKIP  plugin not installed -- run: claude plugin install claude-review-suite@claude-review-suite" >&2
  exit 0
fi

# id | prompt | fixture(s) for VULN grep (space-separated)
CASES=(
  "go|review tests/fixtures/go/vulnerable.go before I merge|tests/fixtures/go/vulnerable.go"
  "bash|review tests/fixtures/bash/vulnerable.sh before I merge|tests/fixtures/bash/vulnerable.sh"
  "vuets|review tests/fixtures/vue-ts/vulnerable.vue and tests/fixtures/vue-ts/vulnerable.ts before I merge|tests/fixtures/vue-ts/vulnerable.vue tests/fixtures/vue-ts/vulnerable.ts"
  "php|review tests/fixtures/php/vulnerable.php before I merge|tests/fixtures/php/vulnerable.php"
  "general|review tests/fixtures/general/vulnerable.py before I merge|tests/fixtures/general/vulnerable.py"
  "security|audit tests/fixtures/security/vulnerable.py for vulns|tests/fixtures/security/vulnerable.py"
)

echo "running ${#CASES[@]} cases in parallel, reports in $OUT"
for entry in "${CASES[@]}"; do
  id="${entry%%|*}"
  rest="${entry#*|}"
  prompt="${rest%%|*}"
  timeout 600 claude -p "$prompt" \
    --output-format text --allowed-tools "Skill Read Grep Glob Bash" \
    >"$OUT/$id.md" 2>"$OUT/$id.err" &
done
wait

OUT="$OUT" python3 - "${CASES[@]}" <<'PY'
import os, re, sys

out = os.environ["OUT"]

# Design criterion 1's explicit "must not be under-scored" floor (tests/README.md).
MIN_HIGH = {
    "GO-04", "PHP-02", "PHP-03", "PHP-05", "VT-01", "VT-02", "VT-04",
    "SEC-01", "SEC-03", "SEC-04", "SEC-06",
}
SEV_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
FINDING_RE = re.compile(r"^\[F\d+\]")
ID_RE = re.compile(r"\b([A-Z]{2,4}-\d{2})\b")
SEV_RE = re.compile(r"\b(Critical|High|Medium|Low)\b")


def planted_ids(fixtures):
    ids = []
    for path in fixtures.split():
        with open(path) as fh:
            text = fh.read()
        ids.extend(sorted(set(re.findall(r"VULN:\s*([A-Z]{2,4}-\d{2})", text))))
    return sorted(set(ids))


def parse_report(path):
    """Return {id: severity} for every checklist ID that appears on a finding line,
    plus the raw text for a substring fallback (mentioned-but-not-a-finding-line)."""
    if not os.path.exists(path):
        return None, ""
    with open(path) as fh:
        text = fh.read()
    id_severity = {}
    for line in text.splitlines():
        if not FINDING_RE.match(line.strip()):
            continue
        sev_match = SEV_RE.search(line)
        if not sev_match:
            continue
        sev = sev_match.group(1)
        for id_match in ID_RE.findall(line):
            if id_match not in id_severity or SEV_RANK[sev] > SEV_RANK[id_severity[id_match]]:
                id_severity[id_match] = sev
    return id_severity, text


total_ids = 0
missing = 0
underscored = 0
no_data = 0

for entry in sys.argv[1:]:
    cid, prompt, fixtures = entry.split("|")
    report_path = os.path.join(out, f"{cid}.md")
    id_severity, text = parse_report(report_path)
    ids = planted_ids(fixtures)

    print(f"\n=== {cid} ({len(ids)} planted IDs) ===")
    if id_severity is None:
        print("  NO DATA -- no report file")
        no_data += len(ids)
        total_ids += len(ids)
        continue

    print(f"{'ID':8} {'status':26} severity")
    for vid in ids:
        total_ids += 1
        if vid in id_severity:
            sev = id_severity[vid]
            status = "finding line"
        elif vid in text:
            sev = "(unscored)"
            status = "mentioned, not a finding line"
        else:
            sev = "(absent)"
            status = "NOT FOUND"
            missing += 1
        floor = ""
        if vid in MIN_HIGH:
            if sev in ("Critical", "High"):
                floor = "OK"
            else:
                floor = "UNDER-SCORED"
                underscored += 1
        print(f"{vid:8} {status:26} {sev:10} {floor}")

print()
print(f"{total_ids} planted IDs across {len(sys.argv) - 1} cases")
print(f"{missing} not found anywhere in the report")
print(f"{underscored} under-scored against the design's explicit Critical/High floor")
print(f"{no_data} unscoreable (missing report file)")
print()
if missing or underscored or no_data:
    print("FAIL -- see table above")
    sys.exit(1)
print("ALL PLANTED IDS FOUND, NO FLOOR VIOLATIONS (mentions outside finding lines still need a human read)")
PY
