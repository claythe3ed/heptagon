"""
Adversarial tests for the Merkle seal.

These tests exercise the attack classes that per-record Ed25519
signatures alone cannot detect: deletion, reordering, and
truncation of records within an incident log.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.audit.merkle import (
    ALGORITHM_NAME,
    MerkleSeal,
    compute_root,
    load_seal,
    seal_log,
    verify_root,
)
from heptagon.audit.signing import Signer


# ---------------------------------------------------------------------------
# compute_root — the primitive
# ---------------------------------------------------------------------------

def test_root_of_empty_is_sha256_of_empty():
    """Empty log has a well-defined root: SHA-256 of empty bytes."""
    import hashlib
    assert compute_root([]) == hashlib.sha256(b"").hexdigest()


def test_root_of_single_record():
    """Single record is its own leaf hash (with domain separator)."""
    import hashlib
    record = b"one record"
    expected = hashlib.sha256(b"\x00" + record).hexdigest()
    assert compute_root([record]) == expected


def test_root_is_deterministic():
    """Same input -> same root, regardless of type (bytes/str)."""
    as_bytes = [b"a", b"b", b"c"]
    as_strings = ["a", "b", "c"]
    assert compute_root(as_bytes) == compute_root(as_strings)


def test_root_ignores_trailing_newlines():
    """Trailing \\n is a file separator, not part of the record."""
    a = compute_root(["rec-1", "rec-2"])
    b = compute_root(["rec-1\n", "rec-2\n"])
    c = compute_root(["rec-1\r\n", "rec-2\r\n"])
    assert a == b == c


def test_root_skips_blank_lines():
    """Blank lines are not records."""
    a = compute_root(["rec-1", "rec-2"])
    b = compute_root(["rec-1", "", "rec-2", "  "])
    assert a == b


# ---------------------------------------------------------------------------
# verify_root — detection of structural tampering
# ---------------------------------------------------------------------------

def test_verify_root_detects_deletion():
    records = ["rec-1", "rec-2", "rec-3", "rec-4"]
    root = compute_root(records)
    assert verify_root(records, root) is True
    assert verify_root(records[:-1], root) is False   # removed last
    assert verify_root([records[0], records[2], records[3]], root) is False  # removed middle


def test_verify_root_detects_reordering():
    records = ["a", "b", "c", "d"]
    root = compute_root(records)
    assert verify_root(["b", "a", "c", "d"], root) is False
    assert verify_root(["d", "c", "b", "a"], root) is False


def test_verify_root_detects_truncation():
    records = [f"r{i}" for i in range(20)]
    root = compute_root(records)
    for n in (1, 5, 10, 19):
        assert verify_root(records[:n], root) is False


def test_verify_root_detects_modification():
    records = ["alpha", "beta", "gamma"]
    root = compute_root(records)
    assert verify_root(["alpha", "BETA", "gamma"], root) is False


# ---------------------------------------------------------------------------
# seal_log — writing the companion file
# ---------------------------------------------------------------------------

def test_seal_writes_correct_record_count(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text("a\nb\nc\n", encoding="utf-8")

    seal = seal_log(log)
    assert seal.record_count == 3
    assert seal.merkle_root == compute_root(["a", "b", "c"])
    assert seal.algorithm == ALGORITHM_NAME


def test_seal_defaults_to_companion_root_file(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text("x\ny\n", encoding="utf-8")
    seal_log(log)

    expected = tmp_path / "log.jsonl.root"
    assert expected.exists()


def test_seal_signature_present_when_signer_passed(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text("one\ntwo\n", encoding="utf-8")

    signer = Signer.generate()
    seal = seal_log(log, signer=signer)

    assert seal.signature
    assert seal.signer_public_key == signer.public_key_hex

    # Signature must verify against the canonical payload
    payload = seal.canonical_bytes()
    assert Signer.verify(
        bytes.fromhex(seal.signer_public_key),
        payload,
        bytes.fromhex(seal.signature),
    ) is True


def test_seal_round_trip(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text("p\nq\nr\n", encoding="utf-8")
    seal_log(log)

    reloaded = load_seal(tmp_path / "log.jsonl.root")
    assert reloaded.record_count == 3
    assert reloaded.merkle_root == compute_root(["p", "q", "r"])


def test_seal_rejects_missing_log(tmp_path):
    with pytest.raises(FileNotFoundError):
        seal_log(tmp_path / "does-not-exist.jsonl")


# ---------------------------------------------------------------------------
# Signature on the seal — catches tampering with the seal itself
# ---------------------------------------------------------------------------

def test_seal_signature_rejects_modified_root(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text("a\nb\n", encoding="utf-8")

    signer = Signer.generate()
    seal = seal_log(log, signer=signer)

    # Tamper with the seal's root (attacker writes a new seal)
    seal.merkle_root = "00" * 32
    payload = seal.canonical_bytes()

    assert Signer.verify(
        bytes.fromhex(seal.signer_public_key),
        payload,
        bytes.fromhex(seal.signature),
    ) is False
