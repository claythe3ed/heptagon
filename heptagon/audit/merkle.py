"""
merkle.py
=========

Merkle root computation for incident logs.

Purpose
-------
Individual Ed25519 signatures on each record protect against
modification of that record. They do NOT protect against:

  - Deleting a whole record from the log
  - Reordering records within the log
  - Truncating the log at an arbitrary point

A Merkle root over all records detects all three, provided the
root is anchored somewhere the attacker does not control.

Custody (important)
-------------------
The root alone is not a security control. A root stored next to
the log file is deleted by the same attacker who deletes the log.
The root is only a useful primitive when its custody is separate
from the log's custody. See docs/threat-model.md for the full
boundary statement.

Usage
-----
    from heptagon.audit.merkle import compute_root, verify_root
    root = compute_root(lines)          # list of records
    ok = verify_root(lines, root)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Union


ALGORITHM_NAME = "sha256-merkle"


def _hash_leaf(data: bytes) -> bytes:
    """
    Hash a single leaf with a domain separator. The \\x00 prefix
    prevents a second-preimage attack where an internal node hash
    is presented as a leaf hash.
    """
    return hashlib.sha256(b"\x00" + data).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    """
    Hash an internal node with a different domain separator, so
    leaves and nodes cannot collide.
    """
    return hashlib.sha256(b"\x01" + left + right).digest()


def compute_root(lines: Iterable[Union[bytes, str]]) -> str:
    """
    Compute the Merkle root over a sequence of records.

    Each line is treated as one leaf. Trailing newlines are stripped
    because they are file separators, not part of the record.

    Returns the root as a hex string (64 characters).
    """
    leaves: List[bytes] = []
    for line in lines:
        if isinstance(line, str):
            line = line.encode("utf-8")
        line = line.rstrip(b"\r\n")
        # Skip empty and whitespace-only lines. Blank lines are file
        # separators, not records.
        if not line.strip():
            continue
        leaves.append(_hash_leaf(line))

    if not leaves:
        # Empty log has a well-defined root: hash of empty string.
        return hashlib.sha256(b"").hexdigest()

    while len(leaves) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(leaves), 2):
            if i + 1 < len(leaves):
                next_level.append(_hash_node(leaves[i], leaves[i + 1]))
            else:
                # Odd number of leaves: promote the last one to the
                # next level unchanged.
                next_level.append(leaves[i])
        leaves = next_level

    return leaves[0].hex()


def verify_root(
    lines: Iterable[Union[bytes, str]],
    expected_root_hex: str,
) -> bool:
    """
    Recompute the Merkle root and compare against an expected value.

    Returns True if they match, False otherwise.
    """
    return compute_root(lines) == expected_root_hex


@dataclass
class MerkleSeal:
    """
    A companion file that anchors the Merkle root of a log file.

    The seal can be signed with Ed25519 for additional integrity,
    but the signing key must be different from the log-signing
    key, or the seal's custody problem is the same as the log's.
    """
    log_file: str
    record_count: int
    merkle_root: str
    algorithm: str = ALGORITHM_NAME
    created_utc: str = ""
    signature: str = ""
    signer_public_key: str = ""

    def __post_init__(self):
        if not self.created_utc:
            self.created_utc = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "log_file": self.log_file,
            "record_count": self.record_count,
            "merkle_root": self.merkle_root,
            "created_utc": self.created_utc,
            "signature": self.signature,
            "signer_public_key": self.signer_public_key,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MerkleSeal":
        return cls(
            log_file=d["log_file"],
            record_count=d["record_count"],
            merkle_root=d["merkle_root"],
            algorithm=d.get("algorithm", ALGORITHM_NAME),
            created_utc=d.get("created_utc", ""),
            signature=d.get("signature", ""),
            signer_public_key=d.get("signer_public_key", ""),
        )

    def canonical_bytes(self) -> bytes:
        """
        Deterministic payload for optional signing. Excludes the
        signature and public key fields.
        """
        parts = [
            self.algorithm,
            self.log_file,
            str(self.record_count),
            self.merkle_root,
            self.created_utc,
        ]
        return "|".join(parts).encode("utf-8")


def seal_log(
    log_path: Union[str, Path],
    out_path: Optional[Union[str, Path]] = None,
    signer=None,
) -> MerkleSeal:
    """
    Compute the Merkle root of a JSONL log and write a companion
    ``.root`` file. Optionally sign the seal with Ed25519.

    Parameters
    ----------
    log_path : str or Path
        Path to the JSONL incident log.
    out_path : str or Path, optional
        Destination for the seal. Defaults to ``<log>.root``.
    signer : Signer, optional
        If provided, the seal is signed with the signer's Ed25519
        key.

    Returns
    -------
    MerkleSeal
        The sealed object, also written to ``out_path``.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        raise FileNotFoundError(f"log file not found: {log_path}")

    raw_lines = log_path.read_text(encoding="utf-8").splitlines()
    non_empty = [l for l in raw_lines if l.strip()]
    root = compute_root(non_empty)

    seal = MerkleSeal(
        log_file=log_path.name,
        record_count=len(non_empty),
        merkle_root=root,
    )

    if signer is not None:
        payload = seal.canonical_bytes()
        sig_bytes = signer.sign(payload)
        seal.signature = sig_bytes.hex()
        seal.signer_public_key = signer.public_key_hex

    if out_path is None:
        out_path = log_path.with_suffix(log_path.suffix + ".root")
    out_path = Path(out_path)
    out_path.write_text(
        json.dumps(seal.to_dict(), indent=2),
        encoding="utf-8",
    )
    return seal


def load_seal(path: Union[str, Path]) -> MerkleSeal:
    """Read a seal file from disk."""
    return MerkleSeal.from_dict(
        json.loads(Path(path).read_text(encoding="utf-8"))
    )


__all__ = [
    "ALGORITHM_NAME",
    "MerkleSeal",
    "compute_root",
    "verify_root",
    "seal_log",
    "load_seal",
]
