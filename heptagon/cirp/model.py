"""
cirp_model.py
=============

A CIRP-grounded wrapper around the symbolic incident_response model.

Maps CIRP concepts (teams, reporting chain, evidence, decisions,
scenarios) into the symbolic primitives (Lineage, MoralSheaf,
TestimonyOperator, MoralJacobians, UnifiedEvaluation).

Use this to:
    - declare a CIRP in executable form
    - run tabletop exercises
    - verify compliance
    - generate an audit trail
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple
import hashlib
import uuid

import numpy as np

from heptagon.core.symbolic import (
    FiberBundle7D,
    Lineage,
    MoralJacobians,
    MoralSheaf,
    PresentationOperator,
    TestimonyOperator,
    UnifiedEvaluation,
)


# ---------------------------------------------------------------------------
# 1. CIRP primitives
# ---------------------------------------------------------------------------

@dataclass
class Team:
    """
    One of the 5 CIRP teams (R-C-C-P-T).
    """
    role: str                # "response", "cyber_mgmt", "crisis_mgmt",
                             # "product_owner", "third_party"
    members: List[str]
    contact: str             # primary contact (phone, email)
    backup: str              # backup contact
    mandate: str             # what this team is authorized to do

    def is_complete(self) -> bool:
        return bool(self.members and self.contact and self.backup and self.mandate)


@dataclass
class Stakeholder:
    name: str
    kind: str                # "internal" | "external"
    category: str            # "employee" | "regulator" | "customer" | ...
    contact: str
    need_to_know: List[str]  # which incident types they must be told about


@dataclass
class Scenario:
    """
    One of the Applicable Scenarios in the CIRP.
    """
    name: str
    triggers: List[str]           # observable signals that start this scenario
    escalation: List[str]         # ordered list of roles to notify
    key_considerations: List[str]
    training_simulations: List[str] = field(default_factory=list)


@dataclass
class Evidence:
    """
    A piece of preserved evidence (CIRP section 10.2).
    """
    evidence_id: str
    source: str
    timestamp: datetime
    sha256: str
    custodian: str
    description: str

    @staticmethod
    def from_bytes(source: str, custodian: str, data: bytes,
                   description: str = "") -> "Evidence":
        return Evidence(
            evidence_id=str(uuid.uuid4()),
            source=source,
            timestamp=datetime.now(timezone.utc),
            sha256=hashlib.sha256(data).hexdigest(),
            custodian=custodian,
            description=description,
        )


@dataclass
class Decision:
    """
    A logged decision with timestamp (CIRP section 9, rule 5).
    """
    decision_id: str
    actor: str
    timestamp: datetime
    rationale: str
    evidence_refs: List[str]
    break_glass: bool = False
    signature: str = ""

    @staticmethod
    def new(actor: str, rationale: str,
            evidence_refs: Optional[List[str]] = None,
            break_glass: bool = False) -> "Decision":
        d = Decision(
            decision_id=str(uuid.uuid4()),
            actor=actor,
            timestamp=datetime.now(timezone.utc),
            rationale=rationale,
            evidence_refs=evidence_refs or [],
            break_glass=break_glass,
        )
        # A simple content signature so the entry is tamper-evident.
        payload = f"{d.decision_id}|{d.actor}|{d.timestamp.isoformat()}|{d.rationale}"
        d.signature = hashlib.sha256(payload.encode()).hexdigest()[:16]
        return d


# ---------------------------------------------------------------------------
# 2. The CIRP model
# ---------------------------------------------------------------------------

@dataclass
class CIRPModel:
    """
    An executable CIRP.

    Maps directly onto the symbolic model:
        - teams          -> agents in the Lineage
        - reporting_chain-> the poset
        - scenarios      -> life_paths during tabletop
        - evidence_log   -> MoralSheaf.global_section
        - decisions_log  -> TestimonyOperator output
    """
    name: str
    version: str = "1.0"

    teams: List[Team] = field(default_factory=list)
    stakeholders: List[Stakeholder] = field(default_factory=list)
    scenarios: List[Scenario] = field(default_factory=list)

    reporting_chain: List[Tuple[str, str]] = field(default_factory=list)
    # (reporter_role, escalate_to_role)

    evidence_log: List[Evidence] = field(default_factory=list)
    decisions_log: List[Decision] = field(default_factory=list)

    bundle: FiberBundle7D = field(default_factory=FiberBundle7D)

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    def add_team(self, team: Team) -> None:
        self.teams.append(team)

    def add_stakeholder(self, s: Stakeholder) -> None:
        self.stakeholders.append(s)

    def add_scenario(self, s: Scenario) -> None:
        self.scenarios.append(s)

    def add_reporting_edge(self, reporter: str, escalate_to: str) -> None:
        self.reporting_chain.append((reporter, escalate_to))

    def log_evidence(self, ev: Evidence) -> None:
        self.evidence_log.append(ev)

    def log_decision(self, d: Decision) -> None:
        self.decisions_log.append(d)

    # ------------------------------------------------------------------
    # Compliance checks
    # ------------------------------------------------------------------

    def check_teams_complete(self) -> Dict:
        incomplete = [t.role for t in self.teams if not t.is_complete()]
        return {
            "ok": len(incomplete) == 0,
            "incomplete_teams": incomplete,
            "expected_roles": [
                "response", "cyber_mgmt", "crisis_mgmt",
                "product_owner", "third_party",
            ],
            "present_roles": [t.role for t in self.teams],
        }

    def check_reporting_chain(self) -> Dict:
        """
        Every reporter must eventually reach an executive role.
        """
        if not self.reporting_chain:
            return {"ok": False, "reason": "no reporting chain defined"}

        edges = dict()
        for reporter, target in self.reporting_chain:
            edges.setdefault(reporter, []).append(target)

        executive = {"cyber_mgmt", "crisis_mgmt"}
        unresolved = []
        for reporter in edges:
            seen = set()
            queue = [reporter]
            reached_exec = False
            while queue:
                node = queue.pop()
                if node in seen:
                    continue
                seen.add(node)
                if node in executive:
                    reached_exec = True
                    break
                queue.extend(edges.get(node, []))
            if not reached_exec:
                unresolved.append(reporter)

        return {
            "ok": len(unresolved) == 0,
            "unresolved_reporters": unresolved,
        }

    def check_evidence_completeness(self) -> Dict:
        """
        Every decision must reference at least one piece of evidence,
        and every evidence hash must be unique.
        """
        hashes = [e.sha256 for e in self.evidence_log]
        dup_hashes = [h for h in hashes if hashes.count(h) > 1]

        dangling = []
        known = {e.evidence_id for e in self.evidence_log}
        for d in self.decisions_log:
            for ref in d.evidence_refs:
                if ref not in known:
                    dangling.append((d.decision_id, ref))

        decisions_without_evidence = [
            d.decision_id for d in self.decisions_log
            if not d.evidence_refs
        ]

        return {
            "ok": not (dup_hashes or dangling or decisions_without_evidence),
            "duplicate_hashes": dup_hashes,
            "dangling_references": dangling,
            "decisions_without_evidence": decisions_without_evidence,
        }

    def check_no_hidden_thing(self) -> Dict:
        """
        The flabbiness condition: every piece of evidence is present
        in the global log, and every decision is timestamped + signed.
        """
        # Build the symbolic sheaf over evidence
        if not self.evidence_log:
            return {"ok": False, "reason": "no evidence logged"}

        global_section = np.array([
            int(e.sha256[:8], 16) for e in self.evidence_log
        ], dtype=float)

        sheaf = MoralSheaf(global_section=global_section)
        # Every local source contributes its slice
        by_source: Dict[str, List[int]] = {}
        for i, e in enumerate(self.evidence_log):
            by_source.setdefault(e.source, []).append(i)

        for source, indices in by_source.items():
            local = np.zeros_like(global_section)
            local[indices] = global_section[indices]
            # The flabbiness test is on the FULL global section, so
            # we register the source's own contribution:
            sheaf.add_local(source, local)

        # Unsigned decisions break the "no hidden thing" rule
        unsigned = [d.decision_id for d in self.decisions_log if not d.signature]

        return {
            "ok": sheaf.is_flabby() and not unsigned,
            "sheaf_flabby": sheaf.is_flabby(),
            "unsigned_decisions": unsigned,
        }

    def check_break_glass_logged(self) -> Dict:
        """
        Every break-glass decision must be marked and referenced.
        """
        bg = [d for d in self.decisions_log if d.break_glass]
        unmarked = [
            d.decision_id for d in bg
            if "break_glass" not in d.rationale.lower()
            or not d.evidence_refs
        ]
        return {
            "ok": not unmarked,
            "total_break_glass": len(bg),
            "unmarked_break_glass": unmarked,
        }

    def verify_all(self) -> Dict:
        """Run every compliance check and return a consolidated report."""
        checks = {
            "teams_complete": self.check_teams_complete(),
            "reporting_chain": self.check_reporting_chain(),
            "evidence_completeness": self.check_evidence_completeness(),
            "no_hidden_thing": self.check_no_hidden_thing(),
            "break_glass_logged": self.check_break_glass_logged(),
        }
        all_ok = all(c.get("ok", False) for c in checks.values())
        return {
            "cirp_name": self.name,
            "cirp_version": self.version,
            "all_checks_passed": all_ok,
            "checks": checks,
        }

    # ------------------------------------------------------------------
    # Tabletop exercise
    # ------------------------------------------------------------------

    def run_tabletop(
        self,
        scenario_name: str,
        num_rounds: int = 20,
        seed: int = 42,
    ) -> Dict:
        """
        Simulate a tabletop exercise for a given scenario.

        Each team becomes an agent. Influence is derived from the
        reporting chain. The exercise produces a timeline and a
        compliance verdict.
        """
        scenario = next(
            (s for s in self.scenarios if s.name == scenario_name),
            None,
        )
        if scenario is None:
            raise ValueError(f"unknown scenario: {scenario_name}")

        # 1. Build the Lineage from team roles
        roles = [t.role for t in self.teams]
        lineage = Lineage(labels=roles)
        N = lineage.N

        # 2. Build influence from reporting chain
        influence = np.zeros((N, N))
        role_to_idx = {r: i for i, r in enumerate(roles)}
        for reporter, target in self.reporting_chain:
            i = role_to_idx.get(reporter)
            j = role_to_idx.get(target)
            if i is not None and j is not None:
                influence[i, j] = 1.0

        # 3. Build life_paths: each team acts proportional to its mandate
        rng = np.random.default_rng(seed)
        life_paths = []
        for i, team in enumerate(self.teams):
            mandate_strength = min(1.0, len(team.mandate) / 100.0)
            path = rng.uniform(0.2, 1.0, size=num_rounds) * mandate_strength
            life_paths.append(path)

        # 4. Presentation operator: who sees what
        presenter = PresentationOperator(num_agents=N)
        presentations = presenter.present(life_paths, influence)
        coverage = presenter.coverage_matrix(influence)

        # 5. Responsibility vs influence
        responsibility = np.array([
            1.0 if t.is_complete() else -1.0 for t in self.teams
        ])
        jac = MoralJacobians(responsibility, influence)

        # 6. Faithfulness: can every team's contribution be distinguished?
        S = np.vstack(life_paths)
        ev = UnifiedEvaluation(global_sections=S, observers=S.copy())

        return {
            "scenario": scenario_name,
            "rounds": num_rounds,
            "num_teams": N,
            "roles": roles,
            "escalation_order": scenario.escalation,
            "coverage_edges": int(coverage.sum()),
            "responsibility_diagonal": jac.responsibility_is_diagonal(),
            "influence_non_diagonal": jac.influence_is_non_diagonal(),
            "faithful": ev.is_faithful(),
            "rank_deficiency": ev.rank_deficiency(),
            "distinctness_fraction": ev.distinctness_fraction(),
            "presentations_lengths": [len(p) for p in presentations],
        }


# ---------------------------------------------------------------------------
# 3. Reference CIRP
# ---------------------------------------------------------------------------

def build_reference_cirp() -> CIRPModel:
    """
    Build a reference CIRP with the 5 teams (R-C-C-P-T) and
    7 common scenarios.
    """
    cirp = CIRPModel(name="reference_cirp", version="1.0")

    # --- Teams ---
    cirp.add_team(Team(
        role="response",
        members=["IR lead", "SOC analyst 1", "SOC analyst 2", "forensics eng"],
        contact="+1-555-0101",
        backup="+1-555-0102",
        mandate="Fix the breach, rebuild systems, execute recovery.",
    ))
    cirp.add_team(Team(
        role="cyber_mgmt",
        members=["CISO", "deputy CISO", "legal counsel"],
        contact="+1-555-0201",
        backup="+1-555-0202",
        mandate="Supervise all cyber incidents, coordinate response.",
    ))
    cirp.add_team(Team(
        role="crisis_mgmt",
        members=["CEO", "COO", "PR lead", "general counsel"],
        contact="+1-555-0301",
        backup="+1-555-0302",
        mandate="Handle business fallout, reputation, continuity.",
    ))
    cirp.add_team(Team(
        role="product_owner",
        members=["head of infrastructure", "head of applications"],
        contact="+1-555-0401",
        backup="+1-555-0402",
        mandate="Report impact on their systems and departments.",
    ))
    cirp.add_team(Team(
        role="third_party",
        members=["forensics firm", "external counsel", "PR agency"],
        contact="+1-555-0501",
        backup="+1-555-0502",
        mandate="Provide specialist help when engaged.",
    ))

    # --- Reporting chain ---
    cirp.add_reporting_edge("response", "cyber_mgmt")
    cirp.add_reporting_edge("product_owner", "cyber_mgmt")
    cirp.add_reporting_edge("cyber_mgmt", "crisis_mgmt")
    cirp.add_reporting_edge("third_party", "cyber_mgmt")

    # --- Scenarios ---
    cirp.add_scenario(Scenario(
        name="data_breach",
        triggers=["DLP alert", "abnormal egress", "credential dump on dark web"],
        escalation=["response", "cyber_mgmt", "crisis_mgmt"],
        key_considerations=["scope of data", "notification windows", "regulator contact"],
        training_simulations=["tabletop with PR + legal", "mock GDPR notice"],
    ))
    cirp.add_scenario(Scenario(
        name="ransomware",
        triggers=["mass file rename", "shadow copy deletion", "ransom note"],
        escalation=["response", "cyber_mgmt", "crisis_mgmt", "third_party"],
        key_considerations=["backup integrity", "do not negotiate", "isolate segments"],
        training_simulations=["restore-from-backup drill", "comms dark-site test"],
    ))
    cirp.add_scenario(Scenario(
        name="phishing_compromise",
        triggers=["user report", "OAuth anomaly", "mailbox rule created"],
        escalation=["response", "cyber_mgmt"],
        key_considerations=["credential reset", "MFA enforcement", "lateral movement"],
        training_simulations=["phishing simulation", "credential reset drill"],
    ))
    cirp.add_scenario(Scenario(
        name="insider_threat",
        triggers=["after-hours access", "bulk download", "privilege escalation"],
        escalation=["cyber_mgmt", "crisis_mgmt"],
        key_considerations=["HR involvement", "legal hold", "preserve evidence"],
        training_simulations=["insider scenario walkthrough"],
    ))
    cirp.add_scenario(Scenario(
        name="ddos",
        triggers=["traffic spike", "upstream alerts", "service degradation"],
        escalation=["response", "cyber_mgmt", "third_party"],
        key_considerations=["scrubbing center", "customer comms", "SLA impact"],
        training_simulations=["failover drill"],
    ))
    cirp.add_scenario(Scenario(
        name="supply_chain",
        triggers=["vendor advisory", "malicious package", "build anomaly"],
        escalation=["response", "cyber_mgmt", "third_party"],
        key_considerations=["SBOM review", "downstream notification", "rebuild artifacts"],
        training_simulations=["vendor notification drill"],
    ))
    cirp.add_scenario(Scenario(
        name="physical_cyber",
        triggers=["badge anomaly", "unattended device", "network port active"],
        escalation=["response", "cyber_mgmt", "crisis_mgmt"],
        key_considerations=["physical access logs", "device quarantine", "law enforcement"],
        training_simulations=["red-team physical intrusion"],
    ))

    return cirp


# ---------------------------------------------------------------------------
# 4. Demonstration
# ---------------------------------------------------------------------------

def demo() -> None:
    print("=" * 64)
    print("CIRP Model — reference demonstration")
    print("=" * 64)

    cirp = build_reference_cirp()

    # --- Compliance verification (empty CIRP) ---
    print("\n[1] Initial compliance check (no evidence / decisions yet)")
    report = cirp.verify_all()
    print(f"    all_checks_passed: {report['all_checks_passed']}")
    for name, r in report["checks"].items():
        print(f"    - {name}: {r.get('ok')}")

    # --- Simulate evidence + decisions ---
    print("\n[2] Logging evidence and decisions ...")
    ev1 = Evidence.from_bytes("soc", "IR lead",
                              b"alert-2025-01-01-001",
                              "initial alert capture")
    ev2 = Evidence.from_bytes("edr", "forensics eng",
                              b"endpoint-memory-dump",
                              "memory image of host-12")
    cirp.log_evidence(ev1)
    cirp.log_evidence(ev2)

    d1 = Decision.new("cyber_mgmt",
                      "Isolate host-12 from network",
                      evidence_refs=[ev1.evidence_id, ev2.evidence_id])
    d2 = Decision.new("cyber_mgmt",
                      "Engage forensics firm via third_party",
                      evidence_refs=[ev2.evidence_id])
    d3 = Decision.new("response",
                      "Break-glass to recover admin access",
                      evidence_refs=[ev1.evidence_id],
                      break_glass=True)
    cirp.log_decision(d1)
    cirp.log_decision(d2)
    cirp.log_decision(d3)

    # --- Compliance after logging ---
    print("\n[3] Compliance after logging")
    report = cirp.verify_all()
    print(f"    all_checks_passed: {report['all_checks_passed']}")
    for name, r in report["checks"].items():
        print(f"    - {name}: {r.get('ok')}")

    # --- Tabletop exercise ---
    print("\n[4] Tabletop exercise: ransomware")
    result = cirp.run_tabletop("ransomware", num_rounds=20, seed=7)
    for k, v in result.items():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    demo()
