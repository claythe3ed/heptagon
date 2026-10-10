"""
log.py
======

Read and write incident logs.

An incident log is a JSONL file. Each line is one JSON object of
the form::

    {"type": "evidence", "data": { ... Evidence fields ... }}
    {"type": "decision", "data": { ... Decision fields ... }}

Records are stored in insertion order. Append-only semantics are
recommended: never rewrite a log once written, only append to it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Union

from heptagon.cirp.model import Decision, Evidence


@dataclass
class IncidentLog:
    """An ordered collection of evidence and decisions."""
    evidence: List[Evidence] = field(default_factory=list)
    decisions: List[Decision] = field(default_factory=list)

    def append_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)

    def append_decision(self, d: Decision) -> None:
        self.decisions.append(d)

    def to_jsonl(self) -> str:
        lines: List[str] = []
        for ev in self.evidence:
            lines.append(json.dumps({"type": "evidence", "data": ev.to_dict()}))
        for d in self.decisions:
            lines.append(json.dumps({"type": "decision", "data": d.to_dict()}))
        return "\n".join(lines) + "\n"

    @classmethod
    def from_jsonl(cls, text: str) -> "IncidentLog":
        log = cls()
        for lineno, raw in enumerate(text.splitlines(), start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as e:
                raise ValueError(f"line {lineno}: invalid JSON: {e}") from e
            rtype = record.get("type")
            data = record.get("data", {})
            if rtype == "evidence":
                log.evidence.append(Evidence.from_dict(data))
            elif rtype == "decision":
                log.decisions.append(Decision.from_dict(data))
            else:
                raise ValueError(
                    f"line {lineno}: unknown record type {rtype!r}"
                )
        return log


def save_log(log: IncidentLog, path: Union[str, Path]) -> None:
    """Write an IncidentLog to a JSONL file."""
    Path(path).write_text(log.to_jsonl(), encoding="utf-8")


def load_log(path: Union[str, Path]) -> IncidentLog:
    """Read an IncidentLog from a JSONL file."""
    return IncidentLog.from_jsonl(Path(path).read_text(encoding="utf-8"))
