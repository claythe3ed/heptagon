#!/usr/bin/env bash
# tamper_tests.sh
# ===============
#
# Three attacks on a signed Heptagon incident log, with detection
# verification after each one. Exits non-zero if any attack is not
# detected.
#
# Usage:
#     bash tamper_tests.sh /tmp/medinet-s3-leak.jsonl
#
# The log must have been sealed before running. If it hasn't,
# `heptagon audit` will still catch attacks 1 and 2 (Ed25519 only)
# but will not report a Merkle mismatch.

set -u

LOG="${1:-/tmp/medinet-s3-leak.jsonl}"

if [[ ! -f "$LOG" ]]; then
    echo "ERROR: log not found: $LOG"
    echo "Run convert_to_heptagon.py first."
    exit 2
fi

BACKUP="${LOG}.clean"
cp "$LOG" "$BACKUP"

PASS=0
FAIL=0

check_detected() {
    local label="$1"
    local exit_code="$2"
    if [[ "$exit_code" -ne 0 ]]; then
        echo "  ✅ $label: detected (exit $exit_code)"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $label: NOT detected (exit 0)"
        FAIL=$((FAIL + 1))
    fi
}

echo "===== ATTACK 1: delete a record ====="
cp "$BACKUP" "$LOG"
sed -i '16d' "$LOG"
heptagon audit "$LOG" >/dev/null 2>&1
check_detected "deletion" $?

echo ""
echo "===== ATTACK 2: modify a signed decision ====="
cp "$BACKUP" "$LOG"
python3 - "$LOG" << 'PYEOF'
import json
import sys
path = sys.argv[1]
lines = open(path).read().splitlines()
for i, line in enumerate(lines):
    rec = json.loads(line)
    if rec["type"] == "decision":
        rec["data"]["rationale"] = "TAMPERED — notification postponed"
        lines[i] = json.dumps(rec)
        break
open(path, "w").write("\n".join(lines) + "\n")
PYEOF
heptagon audit "$LOG" >/dev/null 2>&1
check_detected "modification" $?

echo ""
echo "===== ATTACK 3: reorder two decisions ====="
cp "$BACKUP" "$LOG"
python3 - "$LOG" << 'PYEOF'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines()
lines[10], lines[11] = lines[11], lines[10]
open(path, "w").write("\n".join(lines) + "\n")
PYEOF
heptagon audit "$LOG" >/dev/null 2>&1
check_detected "reordering" $?

echo ""
cp "$BACKUP" "$LOG"
rm -f "$BACKUP"

echo "===== RESULT ====="
echo "Detected: $PASS / 3"
if [[ "$FAIL" -eq 0 ]]; then
    echo "All attacks detected."
    exit 0
else
    echo "$FAIL attack(s) not detected."
    exit 1
fi
