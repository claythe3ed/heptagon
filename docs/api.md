# API Reference

The Python API mirrors the CLI. All classes are importable from
`heptagon` directly.

---

## CIRP model

### `heptagon.cirp.model.CIRPModel`

The executable plan. Holds teams, stakeholders, scenarios, reporting
edges, evidence, and decisions.

    from heptagon.cirp.model import CIRPModel

    cirp = CIRPModel(name="my_cirp", version="1.0")

**Methods:**

| Method | Purpose |
|---|---|
| `add_team(team)` | Add one of the 5 R-C-C-P-T teams |
| `add_stakeholder(s)` | Add an internal or external stakeholder |
| `add_scenario(s)` | Add an applicable scenario |
| `add_reporting_edge(reporter, escalate_to)` | Add a DAG edge |
| `log_evidence(ev)` | Append a piece of evidence |
| `log_decision(d)` | Append a decision |
| `verify_all() -> dict` | Run all six compliance gates |
| `run_tabletop(name, rounds=20, seed=42) -> dict` | Simulate a scenario |

### `heptagon.cirp.model.Team`

    from heptagon.cirp.model import Team

    Team(
        role="response",                    # one of: response, cyber_mgmt,
                                            #         crisis_mgmt,
                                            #         product_owner, third_party
        members=["IR lead", "SOC analyst"],
        contact="+1-555-0101",
        backup="+1-555-0102",
        mandate="Fix the breach, rebuild systems.",
    )

### `heptagon.cirp.model.Evidence`

    from heptagon.cirp.model import Evidence

    ev = Evidence.from_bytes(
        source="soc-siem",
        custodian="Priya Raman",
        data=b"alert-payload",
        description="SIEM alert: mass file rename",
    )
    # ev.evidence_id — UUID
    # ev.timestamp   — UTC datetime
    # ev.sha256      — hex digest of data

### `heptagon.cirp.model.Decision`

    from heptagon.cirp.model import Decision

    d = Decision.new(
        actor="cyber_mgmt",
        rationale="isolate host-12",
        evidence_refs=[ev.evidence_id],
        effect_artifacts=[ev.evidence_id],   # F6
        predecessor="response",               # F7
        successors=["crisis_mgmt"],           # F7
        break_glass=False,
        signer=signer,                        # optional Ed25519 signer
    )

If `signer=None`, the decision carries a legacy SHA-256 content hash
which is non-empty but not cryptographically verifiable. New code
should pass a `Signer`.

---

## Ed25519 signing

### `heptagon.audit.signing.Signer`

    from heptagon.audit.signing import Signer

    signer = Signer.generate()                    # fresh keypair
    signer.save("key.json")                       # writes with 0600

    loaded = Signer.load("key.json")              # read back
    sig = loaded.sign(b"payload")                 # 64-byte signature

    ok = Signer.verify(
        loaded.public_key_bytes,
        b"payload",
        sig,
    )                                             # True

**Design notes:**

- The private key is stored as raw bytes, hex-encoded in JSON.
- Permissions are set to `0600` on save.
- The keypair is **not** encrypted at rest. If this is a concern,
  wrap the file in your own passphrase-based encryption before
  storing it.

---

## Incident log

### `heptagon.audit.log.IncidentLog`

    from heptagon.audit.log import IncidentLog, save_log, load_log

    log = IncidentLog()
    log.append_evidence(ev)
    log.append_decision(d)

    save_log(log, "incidents.jsonl")              # write
    reloaded = load_log("incidents.jsonl")        # read

The file format is JSONL: one JSON object per line, tagged
`{"type": "evidence"|"decision", "data": {...}}`. Order is preserved.

---

## Symbolic layer

The symbolic core lives in `heptagon.core.symbolic`. These classes
are used by the CIRP model but can also be used directly.

| Class | Purpose |
|---|---|
| `FiberBundle7D` | The seven-coordinate record space |
| `MoralSheaf` | Flabbiness condition, injective recording |
| `Lineage` | DAG of reporting structure with cycle detection |
| `PresentationOperator` | Who sees what during a review |
| `TestimonyOperator` | Per-component attestation |
| `MoralJacobians` | Responsibility (diagonal) vs influence (non-diagonal) |
| `UnifiedEvaluation` | Faithfulness and rank-deficiency metrics |
| `IncidentResponsePipeline` | Orchestrator for the above |

### `Lineage` example

    from heptagon.core.symbolic import Lineage

    lin = Lineage(
        labels=["soc", "ir_lead", "ciso", "ceo", "legal"],
        edges=[(0, 1), (1, 2), (2, 3), (2, 4)],
    )

    lin.is_ancestor(0, 4)     # True — soc reaches legal via the chain
    lin.ancestors_of(4)       # [0, 1, 2]
    lin.successors_of(2)      # [3, 4]
    lin.roots()               # [0]

Cycles raise `ValueError`. Self-loops raise `ValueError`. Out-of-bounds
indices raise `ValueError`.

---

## YAML plan loading

    from heptagon.cirp.yaml_loader import (
        load_cirp_from_yaml,
        load_cirp_from_yaml_string,
        build_cirp_from_dict,
        validate_plan_dict,
    )

    cirp = load_cirp_from_yaml("plan.yaml")

The schema is loaded via `importlib.resources` from
`heptagon.schemas`, so it is available regardless of install method
(source tree, editable install, wheel, zipped egg).

---

## Full example

    from heptagon.audit.log import IncidentLog, save_log
    from heptagon.audit.signing import Signer
    from heptagon.cirp.model import CIRPModel, Decision, Evidence, Team

    # Set up the plan
    cirp = CIRPModel(name="demo", version="1.0")
    for role in ("response", "cyber_mgmt", "crisis_mgmt",
                 "product_owner", "third_party"):
        cirp.add_team(Team(role, ["x"], "+1", "+2", "do the thing"))
    cirp.add_reporting_edge("response", "cyber_mgmt")
    cirp.add_reporting_edge("cyber_mgmt", "crisis_mgmt")

    # Log evidence and a signed decision
    signer = Signer.generate()
    log = IncidentLog()

    ev = Evidence.from_bytes("soc", "analyst", b"alert", "initial")
    log.append_evidence(ev)

    d = Decision.new(
        actor="cyber_mgmt",
        rationale="isolate host-12",
        evidence_refs=[ev.evidence_id],
        effect_artifacts=[ev.evidence_id],
        predecessor="response",
        successors=["crisis_mgmt"],
        signer=signer,
    )
    log.append_decision(d)

    save_log(log, "demo.jsonl")
