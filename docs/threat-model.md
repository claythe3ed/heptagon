# Threat Model

What Heptagon protects against, and — with equal weight — what it
does not. Every claim here is either implemented in code or marked
as out of scope.

## What Heptagon protects against

**Accidental omission.** A responder forgets to log a decision, or
logs one without evidence, or forgets to record what changed
downstream. The 7D gate flags it and names the record.

**Undetected modification of a signed record.** Once a decision is
signed with Ed25519, any change to its rationale, evidence
references, effect artifacts, or lineage fields invalidates the
signature. `heptagon audit` detects it and names the record.

**Unreachable escalation paths.** A CIRP may list a role in a
scenario's escalation order that cannot be reached through the
reporting DAG. The tabletop engine finds the gap.

**Incomplete plans.** A CIRP missing one of the five required teams,
missing a reporting edge, or missing a scenario fails a compliance
gate.

**Duplicate or out-of-order evidence.** Two pieces of evidence with
the same SHA-256 hash are flagged. Decisions that reference
evidence dated after the decision are flagged.

## What Heptagon does NOT protect against

**A compromised signing key.** If an attacker has the private key
file, they can produce valid signatures for forged records. The
keypair is stored on disk with `0600` permissions and is **not**
encrypted at rest. If this is a concern, wrap the file in your own
passphrase-based encryption before storing it.

**Record deletion or reordering.** Individual signatures verify per
record. If an attacker with write access to the log file removes a
signed record, or reorders records, every remaining signature stays
valid. `heptagon audit` currently reports `OK: True`. Merkle root
anchoring is planned for a future release to close this gap — see
the "Custody and anchoring" section below.

**A malicious insider with write access to the audit store.** If
they can delete records, they can hide activity. The signatures
prove that a record is unmodified since signing. They do not prove
that no record was removed. Append-only storage (write-once
filesystem, external log aggregator) is the mitigation, and it is
the operator's responsibility.

**A determined attacker with control of the audit machine.** If
they can modify the Python environment or the code, they can make
the audit say anything. Run audits on a trusted machine.

**Legal admissibility.** The signatures are cryptographically valid.
Admissibility in any particular jurisdiction depends on chain of
custody, evidentiary rules, and other factors outside the framework.

**Real-time detection.** Heptagon is not a SIEM or EDR. It reads
logs after the fact. It does not monitor live traffic.

**Threat intelligence.** Heptagon does not track adversaries,
malware families, or indicators of compromise.

## Threat model in one table

| Adversary                                          | Protected? |
|----------------------------------------------------|------------|
| Responder forgetting to log a decision             | Yes        |
| Responder editing a signed decision                | Yes        |
| Attacker with the signing key                      | No         |
| Attacker who deletes a record from the log         | No (see Merkle, below) |
| Attacker who reorders records in the log           | No (see Merkle, below) |
| Insider with write access to the audit store       | No         |
| Attacker with control of the audit machine         | No         |
| Legal admissibility disputes                       | Out of scope |

## Custody and anchoring

**A cryptographic integrity mechanism is only as strong as the
custody of its anchor.**

This principle governs what Heptagon can and cannot promise. A
signature stored next to the record it protects is meaningful only
if the record and the signature are stored where the attacker
cannot reach both. A hash of a log file stored on the same machine
as the log file is not a security control — it is a second copy
that an attacker removes along with the first.

Heptagon is designed around this principle:

- **Signed records** protect against modification *of the record*.
  They assume the log file itself is stored where the attacker
  cannot rewrite it wholesale.
- **Merkle root anchoring**, implemented in v1.1.0 as the
  `heptagon seal` command, protects against deletion and reordering
  of records *within a log file*. It only provides this protection
  if the root is anchored somewhere the attacker does not control.
  Options include:
  - A separate Git repository
  - A timestamping service (OpenTimestamps or similar)
  - A write-once storage medium (WORM filesystem)
  - A copy emailed to an independent address at log-seal time

  If the root is stored next to the log file, it is a convenience
  for detecting accidental corruption, not a security control.
  The `heptagon seal` command prints this exact note to stderr
  every time it runs, so no user confuses the two cases.

- **Log file custody** — ensuring the storage location itself is
  append-only or otherwise tamper-resistant — is the operator's
  responsibility. The framework provides the mechanism; the
  deployment provides the trust boundary.

This distinction is written here, in advance, so that no one
mistakes a component for a system. A Merkle root without an anchor
is not a security improvement over per-record signatures. It is
one hash replacing many, stored in the same place.

## Design principles

1. **Honest limits.** Every claim in this document is either
   implemented or marked as out of scope. Claims that cannot be
   tested do not appear.

2. **Assumes honest actors by default.** The framework catches
   accidental omission and post-hoc tampering of individual
   records. It is not designed against an adversary who controls
   the signing key or the audit store. Extending scope requires
   explicit design, not assumption.

3. **Standard cryptography only.** Ed25519 via PyNaCl. Merkle
   roots will use SHA-256. No custom primitives.

4. **The framework is a tool, not a guarantee.** It makes records
   verifiable. It does not make decisions wise, plans correct, or
   organizations compliant.

## What would change this document

Any of the following would require a new version of this threat
model, with the corresponding code changes, tests, and published
release notes:

- Adding Merkle root anchoring (released in v1.1.0, documented
  above)
- Adding encrypted signing keys (would close the "compromised key"
  gap for lost-or-stolen files, but not for a live compromised
  process)
- Adding hash-chain linking across separate log files
- Adding external notarization integration (OpenTimestamps, etc.)

Until a claim appears here with a version number next to it, it is
not part of the framework.

## Reporting security issues

If you find a vulnerability in Heptagon itself — the signing
implementation, the log parser, or the CLI — do not open a public
issue. Contact the maintainer at the address in `pyproject.toml`
and allow reasonable time for a fix before disclosure.

This document exists so that the boundaries are clear before a
report arrives. If the vulnerability is inside the boundaries
described above, it is a bug. If it is outside — for example, "you
can delete a log file" — it is a documented limit, not a
vulnerability.
