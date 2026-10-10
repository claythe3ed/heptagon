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

    Carries the seven-coordinate fields:
      - B (spacetime):  timestamp + actor
      - F5 (intention): rationale
      - F6 (effect):    effect_artifacts (evidence IDs of downstream
                        state changes)
      - F7 (lineage):   predecessor + successors (escalation edges)
    """
    decision_id: str
    actor: str
    timestamp: datetime
    rationale: str
    evidence_refs: List[str]
    break_glass: bool = False
    signature: str = ""
    effect_artifacts: List[str] = field(default_factory=list)
    predecessor: Optional[str] = None
    successors: List[str] = field(default_factory=list)

    @staticmethod
    def new(actor: str, rationale: str,
            evidence_refs: Optional[List[str]] = None,
            break_glass: bool = False,
            effect_artifacts: Optional[List[str]] = None,
            predecessor: Optional[str] = None,
            successors: Optional[List[str]] = None) -> "Decision":
        d = Decision(
            decision_id=str(uuid.uuid4()),
            actor=actor,
            timestamp=datetime.now(timezone.utc),
            rationale=rationale,
            evidence_refs=evidence_refs or [],
            break_glass=break_glass,
            effect_artifacts=effect_artifacts or [],
            predecessor=predecessor,
            successors=successors or [],
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
        """
        Verify that all five R-C-C-P-T roles are present AND that
        every present team is complete (members, contact, backup,
        mandate).

        A CIRP missing any of the five roles fails this check, even
        if every present team is otherwise complete.
        """
        expected = {
            "response", "cyber_mgmt", "crisis_mgmt",
            "product_owner", "third_party",
        }
        present = {t.role for t in self.teams}
        missing_roles = sorted(expected - present)
        incomplete = [t.role for t in self.teams if not t.is_complete()]
        return {
            "ok": len(missing_roles) == 0 and len(incomplete) == 0,
            "missing_roles": missing_roles,
            "incomplete_teams": incomplete,
            "expected_roles": sorted(expected),
            "present_roles": sorted(present),
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
        Verify:
          1. No two evidence items share a SHA-256 hash
          2. Every decision references at least one evidence record
          3. Every evidence reference points to an existing record
          4. Every decision timestamp is at or after all referenced
             evidence timestamps (chronology is not violated)
        """
        # 1. Duplicate hashes — O(n) with a counter
        hash_counts: Dict[str, int] = {}
        for e in self.evidence_log:
            hash_counts[e.sha256] = hash_counts.get(e.sha256, 0) + 1
        dup_hashes = sorted(h for h, c in hash_counts.items() if c > 1)

        # Build evidence index once
        evidence_by_id = {e.evidence_id: e for e in self.evidence_log}

        # 2/3/4. Walk decisions once
        dangling: List[Tuple[str, str]] = []
        decisions_without_evidence: List[str] = []
        chronology_violations: List[Tuple[str, str]] = []
        for d in self.decisions_log:
            if not d.evidence_refs:
                decisions_without_evidence.append(d.decision_id)
                continue
            for ref in d.evidence_refs:
                ev = evidence_by_id.get(ref)
                if ev is None:
                    dangling.append((d.decision_id, ref))
                    continue
                if d.timestamp < ev.timestamp:
                    chronology_violations.append((d.decision_id, ref))

        ok = not (
            dup_hashes
            or dangling
            or decisions_without_evidence
            or chronology_violations
        )
        return {
            "ok": ok,
            "duplicate_hashes": dup_hashes,
            "dangling_references": dangling,
            "decisions_without_evidence": decisions_without_evidence,
            "chronology_violations": chronology_violations,
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
        unmarked = []
        for d in bg:
            normalized = (
                d.rationale.lower()
                .replace("-", "_")
                .replace(" ", "_")
            )
            if "break_glass" not in normalized or not d.evidence_refs:
                unmarked.append(d.decision_id)
        return {
            "ok": not unmarked,
            "total_break_glass": len(bg),
            "unmarked_break_glass": unmarked,
        }

    def check_7d_completeness(self) -> Dict:
        """
        Verify that every logged record populates the seven
        coordinates defined by the 7D philosophy.

        Coordinate rules:
          B  (spacetime) - evidence: timestamp + source non-empty
                           decision: timestamp + actor non-empty
          F5 (intention) - decision: rationale non-empty
          F6 (effect)    - decision: effect_artifacts non-empty and
                           every reference points to a logged
                           evidence item
          F7 (lineage)   - decision: at least one of predecessor /
                           successors is declared
        """
        violations = []

        e_B_ok = e_B_missing = 0
        for e in self.evidence_log:
            if e.timestamp is not None and e.source and e.source.strip():
                e_B_ok += 1
            else:
                e_B_missing += 1
                violations.append(
                    (e.evidence_id, "B", "evidence missing timestamp or source")
                )

        d_B_ok = d_B_missing = 0
        d_F5_ok = d_F5_missing = 0
        d_F6_ok = d_F6_missing = 0
        d_F7_ok = d_F7_missing = 0

        known_evidence = {e.evidence_id for e in self.evidence_log}

        for d in self.decisions_log:
            # B
            if d.timestamp is not None and d.actor and d.actor.strip():
                d_B_ok += 1
            else:
                d_B_missing += 1
                violations.append(
                    (d.decision_id, "B", "decision missing timestamp or actor")
                )

            # F5
            if d.rationale and d.rationale.strip():
                d_F5_ok += 1
            else:
                d_F5_missing += 1
                violations.append((d.decision_id, "F5", "empty rationale"))

            # F6
            if d.effect_artifacts:
                bad_refs = [
                    r for r in d.effect_artifacts if r not in known_evidence
                ]
                if bad_refs:
                    d_F6_missing += 1
                    violations.append(
                        (d.decision_id, "F6",
                         f"effect_artifacts reference unknown evidence: {bad_refs}")
                    )
                else:
                    d_F6_ok += 1
            else:
                d_F6_missing += 1
                violations.append(
                    (d.decision_id, "F6", "no effect_artifacts declared")
                )

            # F7
            has_pred = d.predecessor is not None and d.predecessor != ""
            has_succ = bool(d.successors)
            if has_pred or has_succ:
                d_F7_ok += 1
            else:
                d_F7_missing += 1
                violations.append(
                    (d.decision_id, "F7",
                     "no predecessor or successors declared")
                )

        ok = len(violations) == 0

        return {
            "ok": ok,
            "coordinate_coverage": {
                "B_evidence": (e_B_ok, e_B_missing),
                "B_decision": (d_B_ok, d_B_missing),
                "F5_decision": (d_F5_ok, d_F5_missing),
                "F6_decision": (d_F6_ok, d_F6_missing),
                "F7_decision": (d_F7_ok, d_F7_missing),
            },
            "violations": violations,
        }

    def verify_all(self) -> Dict:
        """Run every compliance check and return a consolidated report."""
        checks = {
            "teams_complete": self.check_teams_complete(),
            "reporting_chain": self.check_reporting_chain(),
            "evidence_completeness": self.check_evidence_completeness(),
            "no_hidden_thing": self.check_no_hidden_thing(),
            "break_glass_logged": self.check_break_glass_logged(),
            "7d_completeness": self.check_7d_completeness(),
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

        Walks the scenario's escalation order through the reporting
        DAG and verifies that every escalation hop is achievable.

        Returns both symbolic diagnostics (backward compatible) and
        new escalation-validation fields:
          - escalation_valid:   True iff the full chain works
          - escalation_path:    (from_role, to_role, hops) triples
          - escalation_gaps:    hops that cannot be traversed
          - arrival_rounds:     role -> BFS depth from trigger
          - coverage_ratio:     reached / total escalation steps
          - mandate_violations: reached roles with empty mandate
        """
        scenario = next(
            (s for s in self.scenarios if s.name == scenario_name),
            None,
        )
        if scenario is None:
            raise ValueError(f"unknown scenario: {scenario_name}")

        roles = [t.role for t in self.teams]
        N = len(roles)
        role_to_idx = {r: i for i, r in enumerate(roles)}

        raw_edges = []
        for reporter, target in self.reporting_chain:
            i = role_to_idx.get(reporter)
            j = role_to_idx.get(target)
            if i is not None and j is not None and i != j:
                raw_edges.append((i, j))

        seen = set()
        unique_edges = []
        for e in raw_edges:
            if e not in seen:
                seen.add(e)
                unique_edges.append(e)

        if N > 0:
            lineage = Lineage(labels=roles, edges=unique_edges)
        else:
            lineage = None

        influence = np.zeros((N, N))
        for (i, j) in unique_edges:
            influence[i, j] = 1.0

        escalation = list(scenario.escalation)
        arrival_rounds = {}
        escalation_path = []
        escalation_gaps = []
        mandate_violations = []
        reached = []
        coverage_ratio = 0.0
        escalation_valid = False

        if not escalation or lineage is None:
            return {
                "escalation_valid": False,
                "escalation_path": [],
                "escalation_gaps": [],
                "arrival_rounds": {},
                "coverage_ratio": 0.0,
                "mandate_violations": [],
                "scenario": scenario_name,
                "rounds": num_rounds,
                "num_teams": N,
                "roles": roles,
                "escalation_order": escalation,
                "coverage_edges": 0,
                "responsibility_diagonal": None,
                "influence_non_diagonal": None,
                "faithful": True,
                "rank_deficiency": 0,
                "distinctness_fraction": 1.0,
                "presentations_lengths": [],
            }

        trigger = escalation[0]
        trigger_idx = role_to_idx.get(trigger)
        if trigger_idx is not None:
            arrival_rounds = {trigger: 0}
            frontier = [trigger_idx]
            depth = 0
            while frontier:
                depth += 1
                nxt = []
                for idx in frontier:
                    for child_idx in lineage.successors_of(idx):
                        child_role = roles[child_idx]
                        if child_role not in arrival_rounds:
                            arrival_rounds[child_role] = depth
                            nxt.append(child_idx)
                frontier = nxt

        for i, target_role in enumerate(escalation[1:], start=1):
            target_idx = role_to_idx.get(target_role)
            if target_idx is None:
                escalation_gaps.append((escalation[i - 1], target_role))
                continue
            reached_from = None
            for source_role in escalation[:i]:
                source_idx = role_to_idx.get(source_role)
                if source_idx is None:
                    continue
                if lineage.is_ancestor(source_idx, target_idx):
                    reached_from = source_role
                    break
            if reached_from is None:
                escalation_gaps.append((escalation[i - 1], target_role))
            else:
                hops = arrival_rounds.get(target_role, -1)
                escalation_path.append((reached_from, target_role, hops))

        reached = [r for r in escalation if r in arrival_rounds]

        team_by_role = {t.role: t for t in self.teams}
        for r in reached:
            t = team_by_role.get(r)
            if t is None or not t.mandate.strip():
                mandate_violations.append(r)

        coverage_ratio = (
            len(reached) / len(escalation) if escalation else 0.0
        )
        escalation_valid = (
            len(escalation_gaps) == 0
            and len(mandate_violations) == 0
            and coverage_ratio == 1.0
        )

        rng = np.random.default_rng(seed)
        life_paths = []
        for i, team in enumerate(self.teams):
            mandate_strength = min(1.0, len(team.mandate) / 100.0)
            path = rng.uniform(0.2, 1.0, size=num_rounds) * mandate_strength
            life_paths.append(path)

        presenter = PresentationOperator(num_agents=N)
        presentations = presenter.present(life_paths, influence)
        cov_matrix = presenter.coverage_matrix(influence)

        responsibility = np.array([
            1.0 if t.is_complete() else -1.0 for t in self.teams
        ])
        jac = MoralJacobians(responsibility, influence)

        S = np.vstack(life_paths)
        ev = UnifiedEvaluation(global_sections=S, observers=S.copy())

        return {
            "escalation_valid": escalation_valid,
            "escalation_path": escalation_path,
            "escalation_gaps": escalation_gaps,
            "arrival_rounds": arrival_rounds,
            "coverage_ratio": coverage_ratio,
            "mandate_violations": mandate_violations,
            "scenario": scenario_name,
            "rounds": num_rounds,
            "num_teams": N,
            "roles": roles,
            "escalation_order": scenario.escalation,
            "coverage_edges": int(cov_matrix.sum()),
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
                      evidence_refs=[ev1.evidence_id, ev2.evidence_id],
                      effect_artifacts=[ev2.evidence_id],
                      predecessor="response",
                      successors=["crisis_mgmt"])
    d2 = Decision.new("cyber_mgmt",
                      "Engage forensics firm via third_party",
                      evidence_refs=[ev2.evidence_id],
                      effect_artifacts=[ev2.evidence_id],
                      predecessor="response",
                      successors=["crisis_mgmt"])
    d3 = Decision.new("response",
                      "Break-glass to recover admin access",
                      evidence_refs=[ev1.evidence_id],
                      break_glass=True,
                      effect_artifacts=[ev1.evidence_id],
                      predecessor=None,
                      successors=["cyber_mgmt"])
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
