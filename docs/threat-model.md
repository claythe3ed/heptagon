# Threat Model

## What Heptagon protects against

**Accidental omission.** A responder forgets to log a decision, or
logs one without evidence, or forgets to record what changed
downstream. The 7D gate flags it.

**Undetected modification after the fact.** Once a decision is
signed with Ed25519, any change to its rationale, evidence
references, effect artifacts, or lineage fields invalidates the
signature. The `audit` command detects it and names the record.

**Unreachable escalation paths.** A CIRP may list a role in a
scenario's escalation order that cannot be reached through the
reporting chain. The tabletop engine finds the gap.

**Incomplete plans.** A CIRP missing one of the five teams, missing
a reporting edge, or missing a scenario fails a gate.

## What Heptagon does NOT protect against

**A compromised signing key.** If the attacker has the private key,
they can produce valid signatures for forged records. Protect the
key — it is stored on disk with 0600 permissions by default. It is
not encrypted at rest.

**A malicious insider with write access to the audit log.** If they
can delete records, they can hide activity. The signatures prove
that a record is unmodified *since signing* — they do not prove
that no record was removed. Append-only storage (write-once
filesystem, external log aggregator) is the mitigation.

**A determined attacker who controls the machine running Heptagon.**
If they can modify the code or the Python environment, they can
make the audit say anything. Run audits on a trusted machine.

**Legal admissibility.** The signatures are cryptographically valid,
but admissibility in any particular jurisdiction depends on chain
of custody, evidentiary rules, and other factors outside the
framework.

**Real-time detection.** Heptagon is not a SIEM or EDR. It reads
logs after the fact. It does not monitor live traffic.

**Threat intelligence.** Heptagon does not track adversaries,
malware families, or indicators of compromise.

## Threat model in one table

| Adversary                                    | Protected? |
|----------------------------------------------|------------|
| Responder forgetting to log a decision       | Yes        |
| Responder editing a signed decision          | Yes        |
| Attacker with the signing key                | No         |
| Insider with write access to the audit store | No         |
| Attacker with control of the audit machine   | No         |
| Legal admissibility disputes                 | Out of scope |

## Design principles

1. **Honest limits.** Every claim in this document is testable. If
   a claim cannot be tested, it does not belong here.

2. **Assumes honest actors.** The framework catches accidental
   omission and post-hoc tampering by an external party. It is not
   designed against an adversary who controls the signing key or
   the audit store.

3. **Cryptography is standard.** Ed25519 via PyNaCl. No custom
   crypto, no roll-your-own primitives.

4. **The framework is a tool.** It makes records verifiable. It does
   not make decisions wise, plans correct, or organizations
   compliant.
