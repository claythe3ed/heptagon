# Expected Output

Reference output for the MediNet scenario. Your run will have
different UUIDs and signatures (each run generates a fresh Ed25519
keypair) but the same structure and detection behavior.

---

## 1. Convert

$ python examples/medinet/convert_to_heptagon.py
Keypair written to: /tmp/medinet-ir-key.json
Public key: <16 hex chars>...
Logged 3 hook events
Golden path has 25 steps
Logged 25 golden-path decisions

Log written to: /tmp/medinet-s3-leak.jsonl
Evidence: 15
Decisions: 25

Run:
heptagon audit /tmp/medinet-s3-leak.jsonl
heptagon seal /tmp/medinet-s3-leak.jsonl --sign-with /tmp/medinet-ir-key.json
heptagon audit /tmp/medinet-s3-leak.jsonl

---

## 2. Audit the clean log

$ heptagon audit /tmp/medinet-s3-leak.jsonl
Log: /tmp/medinet-s3-leak.jsonl
Evidence: 15
Decisions: 25

Ed25519 valid: 25

OK: True

Exit code: `0`

---

## 3. Seal

$ heptagon seal /tmp/medinet-s3-leak.jsonl --sign-with /tmp/medinet-ir-key.json
Seal written to: /tmp/medinet-s3-leak.jsonl.root
Log: medinet-s3-leak.jsonl
Records sealed: 40
Merkle root: <16 hex chars>...
Signature: ed25519 (64 bytes)

CUSTODY NOTE
The seal was written next to the log file. If an attacker
can delete or modify the log, they can delete or modify the
seal too. On its own, this seal detects accidental
corruption, not a determined attacker.

For deletion and reordering detection to hold, copy the
.root file somewhere outside this machine:

    A separate Git repository

    A timestamping service (OpenTimestamps or similar)

    Write-once storage (WORM filesystem)

    An email sent to an independent address

See docs/threat-model.md for the full boundary.

Exit code: `0`

---

## 4. Audit after sealing

$ heptagon audit /tmp/medinet-s3-leak.jsonl
Log: /tmp/medinet-s3-leak.jsonl
Evidence: 15
Decisions: 25

Ed25519 valid: 25

Seal: VERIFIED (sha256-merkle)
Seal sig: valid

OK: True

Exit code: `0`

---

## 5. Tamper tests

$ bash examples/medinet/tamper_tests.sh
===== ATTACK 1: delete a record =====
✅ deletion: detected (exit 1)

===== ATTACK 2: modify a signed decision =====
✅ modification: detected (exit 1)

===== ATTACK 3: reorder two decisions =====
✅ reordering: detected (exit 1)

===== RESULT =====
Detected: 3 / 3
All attacks detected.

Exit code: `0`

---

## Attack detection details

### Attack 1 — deletion

Log: /tmp/medinet-s3-leak.jsonl
Evidence: 15
Decisions: 24

Ed25519 valid: 24

Seal: MISMATCH
expected root: <hex>...
computed root: <different hex>...
expected count: 40
actual count: 39

OK: False

Ed25519 shows `valid: 24` because the remaining signatures are still
valid. Only the Merkle root and record count reveal that a record
was removed.

### Attack 2 — modification

Log: /tmp/medinet-s3-leak.jsonl
Evidence: 15
Decisions: 25

Ed25519 valid: 24
Invalid signatures (1):

    <uuid>

Seal: MISMATCH
expected root: <hex>...
computed root: <different hex>...
expected count: 40
actual count: 40

OK: False

Both layers detect it. Ed25519 names the modified decision ID.

### Attack 3 — reordering

Log: /tmp/medinet-s3-leak.jsonl
Evidence: 15
Decisions: 25

Ed25519 valid: 25 ← every signature is still valid

Seal: MISMATCH
expected root: <hex>...
computed root: <different hex>...
expected count: 40
actual count: 40

OK: False

This is the case that Ed25519 alone cannot catch. No record was
deleted. No record was modified. Only the order changed. The Merkle
root is the only layer that detects it.

---

## Summary

| Command | Exit code |
|---|---|
| `convert_to_heptagon.py` | 0 |
| `heptagon audit` (clean) | 0 |
| `heptagon seal` | 0 |
| `heptagon audit` (sealed) | 0 |
| `tamper_tests.sh` — deletion | 1 (expected) |
| `tamper_tests.sh` — modification | 1 (expected) |
| `tamper_tests.sh` — reordering | 1 (expected) |
| `tamper_tests.sh` — overall | 0 |

The final `0` in `tamper_tests.sh` means all three attacks were
detected. A nonzero exit from that script means an attack slipped
through.
