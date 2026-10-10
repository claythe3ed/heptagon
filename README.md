# Heptagon

**Seven coordinates. Every incident. Verified.**

A symbolic, formal, and executable framework for cybersecurity
incident response planning and management.

## What it does

Heptagon treats every incident record as a seven-coordinate object.
An incident without a timestamp, rationale, effect, or lineage is
not a complete record — and an incomplete record cannot be certified
as truthful.

The framework:

1. **Declares** a Cyber Incident Response Plan in code
2. **Verifies** plan completeness against six compliance gates
3. **Simulates** scenario escalations through the reporting DAG
4. **Logs** incidents with tamper-evident evidence and decisions
5. **Audits** every record for 7D coordinate coverage
6. **Rejects** incomplete records with specific, actionable reasons

## The seven coordinates

| Coordinate | Name | Meaning |
|---|---|---|
| **B**  | Spacetime  | Timestamp + origin |
| **F5** | Intention  | Why the actor acted |
| **F6** | Effect     | What changed downstream |
| **F7** | Lineage    | Position in the reporting chain |

A complete record populates all seven. The `check_7d_completeness()`
gate enforces this on every logged evidence and decision.

## Install

    pip install heptagon7

The PyPI project is named **heptagon7** — the name `heptagon` was
already taken on PyPI. After installing, the Python import and the
CLI command are both `heptagon`:

    import heptagon          # library
    heptagon --help          # CLI

For local development:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e .

## Quick start

    python -m heptagon.cirp.model          # reference CIRP demo
    python -m heptagon.core.symbolic       # symbolic layer demo
    python -m heptagon.simulation.stuxnet_test  # historical validation
    python -m pytest tests/ -v             # full test suite

## The six compliance gates

`CIRPModel.verify_all()` runs:

1. `check_teams_complete`       — all 5 R-C-C-P-T roles present and complete
2. `check_reporting_chain`      — every reporter can reach an executive
3. `check_evidence_completeness`— unique hashes, no dangling refs, chronology valid
4. `check_no_hidden_thing`      — every source's slice reconciles with the global log
5. `check_break_glass_logged`   — every emergency override is marked AND evidenced
6. `check_7d_completeness`      — every record populates all seven coordinates

## Architecture

    heptagon/
      core/            Symbolic layer (bundle, sheaf, lineage, operators)
      cirp/            CIRP primitives + compliance checks + tabletop
      simulation/      Deterministic agent-based simulator
      audit/           (future) signature verification, reporting

## Honest limits

- **Assumes honest actors.** This tool catches accidental omission,
  not adversarial falsification. Signatures are content hashes, not
  PKI signatures. A v1 threat model will address the malicious case.
- **Does not replace human judgment.** It verifies that decisions are
  logged, not that they are wise.
- **Does not certify compliance.** It reports whether a plan is
  internally consistent, not whether it meets any specific regulation.
- **Not production-ready before v1.0.** The API may change.

## History

The framework's design traces to a symbolic model of comprehensive
presentation (al-'ard fi fada' al-shumul). The mathematics is a
language for meaning, not a claim about physics. See `docs/PHILOSOPHY.md`
(future) for the full derivation.

## License

MIT. See `LICENSE`.

## Status

**v0.1.0** — Audit-closed. All twelve originally identified issues
resolved or retracted. 58 tests passing.
