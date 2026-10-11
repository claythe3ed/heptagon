# Architecture

## Module map

    heptagon/
      core/symbolic.py            Symbolic layer
        FiberBundle7D             7D record space
        MoralSheaf                flabbiness / injective recording
        Lineage                   DAG of reporting structure
        PresentationOperator      who sees what
        TestimonyOperator         per-component attestation
        MoralJacobians            responsibility vs. influence
        UnifiedEvaluation         faithfulness metrics
        IncidentResponsePipeline  orchestrator

      cirp/model.py               CIRP primitives + gates
        Team, Stakeholder, Scenario, Evidence, Decision
        CIRPModel                 executable plan
          verify_all()            runs the six gates
          run_tabletop()          escalation validation

      cirp/yaml_loader.py         plan loader + schema validation
      audit/signing.py            Ed25519 signer
      audit/log.py                JSONL incident-log reader/writer
      cli/main.py                 argparse-based CLI
      simulation/
        internal_simulator.py     numpy-only agent simulator
        stuxnet_test.py           historical validation

## Data flow

    cirp.yaml  ──► yaml_loader ──► CIRPModel
                                       │
                                       ▼
                             verify_all() (six gates)
                                       │
                                       ▼
                             run_tabletop() (escalation)
                                       │
                                       ▼
                    Incident log ──► audit (signatures + 7D)

## The six compliance gates

| Gate                          | Enforces                              |
|-------------------------------|---------------------------------------|
| check_teams_complete          | All 5 R-C-C-P-T roles present + whole |
| check_reporting_chain         | Every reporter can reach an executive |
| check_evidence_completeness   | Unique hashes, chronology, refs valid |
| check_no_hidden_thing         | Signatures valid + sheaf flabby       |
| check_break_glass_logged      | Every override is marked AND evidenced|
| check_7d_completeness         | Every record populates all 7 coords   |

## Signing

Two signature algorithms are supported:

- `ed25519`           — real cryptographic signature over a canonical
                        payload, verifiable against the declared
                        public key
- `sha256-truncated`  — 16 hex chars of SHA-256 (legacy). Non-empty
                        but unverifiable

Callers should pass a `Signer` to `Decision.new()`. Decisions created
without one carry the legacy signature and are flagged by
`check_no_hidden_thing` as `legacy_sha256_decisions`.

## Exit codes (CLI)

    0   success
    1   plan fails a compliance check, or log fails audit
    2   invalid input (bad file, unknown scenario, etc.)

## Dependencies

- `numpy`       — symbolic core
- `PyYAML`      — plan loading
- `jsonschema`  — schema validation
- `PyNaCl`      — Ed25519 signing

The core is numpy-only. Everything else is used only when needed.
