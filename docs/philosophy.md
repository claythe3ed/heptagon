# Philosophy — Seven Coordinates

An incident cannot be truthfully described in four dimensions.

Four dimensions — three of space, one of time — capture *where* and
*when*. They do not capture:

- **Why** the actor acted
- **What** propagated downstream
- **Where** the actor sits in the causal and reporting chain

A complete incident record exhibits all seven coordinates. A record
that omits any of them is partial — and a partial record is not a
truthful record.

## The seven coordinates

The record space is the fiber bundle `E = B × F5 × F6 × F7`:

| Coordinate | Name       | Captured by                              |
|------------|------------|------------------------------------------|
| B0–B3      | Spacetime  | `timestamp`, `actor`, `source`           |
| F5         | Intention  | `Decision.rationale`                     |
| F6         | Effect     | `Decision.effect_artifacts`              |
| F7         | Lineage    | `Decision.predecessor` + `successors`    |

Total dimension: 7.

## What enforces the philosophy

The `check_7d_completeness()` gate. Every logged evidence and every
logged decision is checked against the seven-coordinate schema. If
any coordinate is empty, the gate fails and reports which record and
which coordinate.

## Why the framework separates three things

Most incident-response models conflate:

1. **Individual responsibility** — what a specific actor chose
2. **Extended influence** — what effects propagated from that choice
3. **Total unveiling** — whether the full record can be reconstructed

Heptagon separates them mathematically:

- **Responsibility** is diagonal: each actor is accountable only for
  their own choices.
- **Influence** is non-diagonal: effects cross actor boundaries.
- **Unveiling** is a flabbiness condition: every local section must
  extend to the global record, or the record is incomplete.

## What the philosophy is not

It is not physics. It is not theology. The mathematics is a language
for meaning, not a claim about the unseen.

The philosophy is a **schema**: a specification of what a complete
record must contain. The framework either enforces that schema or
it does not. When it does, "complete" means something. When it does
not, "complete" is decoration.

Heptagon enforces the schema.
