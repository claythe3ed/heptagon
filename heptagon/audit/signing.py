"""
signing.py
==========

Ed25519 signing for incident-response records.

Provides a ``Signer`` class that wraps a private/public keypair and
signs canonical byte representations of Decision records.

Key storage format
------------------
A signer is serialized as JSON:

    {
      "algorithm": "ed25519",
      "private_key_hex": "...",
      "public_key_hex": "...",
      "created_utc": "2026-10-10T20:35:00+00:00"
    }

The private key should be stored with strict filesystem permissions
(0600). The public key can be shared freely — it is the identifier
used to verify signed records.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from nacl import signing as ed25519
from nacl.exceptions import BadSignatureError


ALGORITHM_NAME = "ed25519"


@dataclass
class Signer:
    """An Ed25519 keypair capable of signing and verifying records."""
    private_key_bytes: bytes
    public_key_bytes: bytes
    created_utc: str = ""

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> "Signer":
        """Generate a fresh random keypair."""
        vk = ed25519.SigningKey.generate()
        sk_bytes = bytes(vk)
        pk_bytes = bytes(vk.verify_key)
        return cls(
            private_key_bytes=sk_bytes,
            public_key_bytes=pk_bytes,
            created_utc=datetime.now(timezone.utc).isoformat(),
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Union[str, Path]) -> None:
        """Write the keypair to a JSON file with 0600 permissions."""
        p = Path(path)
        payload = {
            "algorithm": ALGORITHM_NAME,
            "private_key_hex": self.private_key_bytes.hex(),
            "public_key_hex": self.public_key_bytes.hex(),
            "created_utc": self.created_utc,
        }
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        # Lock permissions down
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path: Union[str, Path]) -> "Signer":
        """Load a keypair from a JSON file."""
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        if data.get("algorithm") != ALGORITHM_NAME:
            raise ValueError(
                f"unsupported algorithm: {data.get('algorithm')}"
            )
        return cls(
            private_key_bytes=bytes.fromhex(data["private_key_hex"]),
            public_key_bytes=bytes.fromhex(data["public_key_hex"]),
            created_utc=data.get("created_utc", ""),
        )

    # ------------------------------------------------------------------
    # Sign / verify
    # ------------------------------------------------------------------

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def sign(self, payload: bytes) -> bytes:
        """Sign raw bytes. Returns the 64-byte signature."""
        vk = ed25519.SigningKey(self.private_key_bytes)
        # PyNaCl's SigningKey.sign() returns a SignedMessage container
        # (signature + original message). Extract only the signature.
        return vk.sign(payload).signature

    @staticmethod
    def verify(
        public_key_bytes: bytes,
        payload: bytes,
        signature_bytes: bytes,
    ) -> bool:
        """Verify a signature against a payload and public key."""
        try:
            vk = ed25519.VerifyKey(public_key_bytes)
            vk.verify(payload, signature_bytes)
            return True
        except (BadSignatureError, Exception):
            return False
