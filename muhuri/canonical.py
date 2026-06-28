"""
Deterministic encoding and hashing.

Every signature and every chain-link hash in Muhuri is computed over a
*canonical* byte representation so that independent parties (delegator,
holder, verifier) always reconstruct the identical bytes. We use canonical
CBOR (RFC 8949 §4.2.1): map keys sorted, shortest-form integers, no
indefinite-length items. This removes the serialization ambiguity that has
historically caused signature-bypass bugs in JSON/JWT systems.
"""
from __future__ import annotations

import hashlib
from typing import Any

import cbor2


def cenc(obj: Any) -> bytes:
    """Canonical CBOR encoding. Deterministic for the same logical value."""
    return cbor2.dumps(obj, canonical=True)


def cdec(data: bytes) -> Any:
    return cbor2.loads(data)


def h256(*parts: bytes) -> bytes:
    """SHA-256 over the concatenation of parts."""
    d = hashlib.sha256()
    for p in parts:
        d.update(p)
    return d.digest()


ZERO32 = b"\x00" * 32
