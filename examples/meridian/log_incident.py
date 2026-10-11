"""
Meridian Health ransomware incident — 22:14 Friday evening.

Every decision is logged with all seven coordinates:
  B (spacetime): timestamp + actor
  F5 (intention): rationale
  F6 (effect): effect_artifacts referencing downstream evidence
  F7 (lineage): predecessor + successors
"""
from heptagon.audit.log import IncidentLog, save_log
from heptagon.audit.signing import Signer
from heptagon.cirp.model import Decision, Evidence

# Generate a fresh keypair each run.
# The showcase does not ship a private key — this makes it
# self-contained and reproducible from a clean clone.
signer = Signer.generate()
log = IncidentLog()

# ---- Evidence as it accumulates ----

ev_alert = Evidence.from_bytes(
    "soc-siem", "Priya Raman",
    b"alert-ransomware-fs04-2214",
    "SIEM alert: mass file rename on FS-04, 22:14",
)
ev_shadow = Evidence.from_bytes(
    "edr-crowdstrike", "Sam Okafor",
    b"shadow-copy-deletion-artifact",
    "EDR evidence: vssadmin delete shadows executed",
)
ev_ransom_note = Evidence.from_bytes(
    "filesystem-fs04", "Sam Okafor",
    b"RANSOM_NOTE_readme.txt contents",
    "Ransom note: 'BlackCat' group claim",
)
ev_lateral = Evidence.from_bytes(
    "network-pcap", "Sam Okafor",
    b"smb-lateral-movement-to-db-cluster",
    "SMB traffic from FS-04 to EHR-DB-01",
)
ev_ehr_status = Evidence.from_bytes(
    "ehr-monitor", "David Marsh",
    b"EHR-DB-01 offline, clinical systems degraded",
    "EHR database offline, charting on paper",
)
ev_phi_confirmed = Evidence.from_bytes(
    "forensics-mandiant", "Mandiant",
    b"phi-exfiltration-confirmed-48k-records",
    "Confirmed: ~48,000 patient records exfiltrated",
)
ev_backup_intact = Evidence.from_bytes(
    "backup-vault", "Elena Vasquez",
    b"immutable-backups-verified-clean",
    "Immutable backups verified clean, restore possible",
)
ev_ocr_draft = Evidence.from_bytes(
    "legal-counsel", "Rebecca Lin",
    b"OCR-notification-draft-v1",
    "Draft HIPAA breach notification to OCR",
)

for ev in [
    ev_alert, ev_shadow, ev_ransom_note, ev_lateral,
    ev_ehr_status, ev_phi_confirmed, ev_backup_intact, ev_ocr_draft,
]:
    log.append_evidence(ev)

# ---- Decisions as they happen ----

d1 = Decision.new(
    actor="response",
    rationale="SIEM alert indicates mass encryption on FS-04. Escalating to IR lead.",
    evidence_refs=[ev_alert.evidence_id],
    effect_artifacts=[ev_alert.evidence_id],
    predecessor="response",
    successors=["cyber_mgmt"],
    signer=signer,
)

d2 = Decision.new(
    actor="response",
    rationale="Isolate FS-04 from network to stop lateral movement.",
    evidence_refs=[ev_shadow.evidence_id, ev_lateral.evidence_id],
    effect_artifacts=[ev_lateral.evidence_id],
    predecessor="response",
    successors=["cyber_mgmt"],
    signer=signer,
)

d3 = Decision.new(
    actor="cyber_mgmt",
    rationale="Authorize full subnet isolation for EHR segment pending forensics.",
    evidence_refs=[ev_lateral.evidence_id, ev_ransom_note.evidence_id],
    effect_artifacts=[ev_lateral.evidence_id],
    predecessor="response",
    successors=["crisis_mgmt", "product_owner"],
    signer=signer,
)

d4 = Decision.new(
    actor="product_owner",
    rationale="EHR-DB-01 offline. Activate paper-based charting and downtime procedures.",
    evidence_refs=[ev_ehr_status.evidence_id],
    effect_artifacts=[ev_ehr_status.evidence_id],
    predecessor="cyber_mgmt",
    successors=["crisis_mgmt"],
    signer=signer,
)

d5 = Decision.new(
    actor="response",
    rationale="break_glass to recover admin access to backup vault; standard auth unavailable.",
    evidence_refs=[ev_backup_intact.evidence_id],
    effect_artifacts=[ev_backup_intact.evidence_id],
    predecessor="cyber_mgmt",
    successors=["cyber_mgmt"],
    signer=signer,
    break_glass=True,
)

d6 = Decision.new(
    actor="cyber_mgmt",
    rationale="Engage Mandiant for forensic scope analysis and PHI assessment.",
    evidence_refs=[ev_ransom_note.evidence_id],
    effect_artifacts=[ev_phi_confirmed.evidence_id],
    predecessor="response",
    successors=["crisis_mgmt", "third_party"],
    signer=signer,
)

d7 = Decision.new(
    actor="third_party",
    rationale="Mandiant confirms exfiltration of ~48k patient records containing PHI.",
    evidence_refs=[ev_phi_confirmed.evidence_id],
    effect_artifacts=[ev_ocr_draft.evidence_id],
    predecessor="cyber_mgmt",
    successors=["crisis_mgmt", "cyber_mgmt"],
    signer=signer,
)

d8 = Decision.new(
    actor="crisis_mgmt",
    rationale="PHI confirmed exfiltrated. HIPAA 60-day clock starts. Draft OCR notification.",
    evidence_refs=[ev_phi_confirmed.evidence_id, ev_ocr_draft.evidence_id],
    effect_artifacts=[ev_ocr_draft.evidence_id],
    predecessor="third_party",
    successors=["third_party"],
    signer=signer,
)

for d in [d1, d2, d3, d4, d5, d6, d7, d8]:
    log.append_decision(d)

save_log(log, "meridian-incident.jsonl")
print(f"Logged {len(log.evidence)} evidence items, {len(log.decisions)} decisions")
print(f"Written to: meridian-incident.jsonl")
