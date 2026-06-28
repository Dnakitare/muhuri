"""
Proof of possession (PoP) + replay defenses.

A Muhuri is not a bearer token. To exercise it, the holder signs a fresh,
server-issued challenge with the private key the leaf link was delegated to.
The resource server verifies under `tess.holder_pub`.

[AUDIT R2] The PoP nonce is single-use. `NonceStore` lets the resource server
issue a challenge and consume it exactly once, closing same-window replay.

[AUDIT R7] The PoP optionally binds an `audience` (the resource server's own
identifier), so a PoP minted for server A cannot be relayed to server B even if
both trust the same root and serve overlapping resources.
"""
from __future__ import annotations

import os

from .canonical import cenc, h256
from .credential import Muhuri, now
from .keys import KeyPair, verify_sig

DOMAIN_POP = b"muhuri/pop/v1"


def _pop_msg(muhuri_id: bytes, request: dict, server_nonce: bytes, ts: int, audience: bytes) -> bytes:
    return h256(DOMAIN_POP, muhuri_id, cenc(request), server_nonce,
                ts.to_bytes(8, "big"), audience)


def prove(tess: Muhuri, holder: KeyPair, request: dict, server_nonce: bytes,
          ts: int | None = None, audience: bytes = b"") -> dict:
    """Holder produces a PoP for `request` against a server-issued nonce."""
    if holder.pub != tess.holder_pub:
        raise ValueError("signing key is not the credential's current holder key")
    ts = now() if ts is None else ts
    msg = _pop_msg(tess.muhuri_id(), request, server_nonce, ts, audience)
    return {"ts": ts, "server_nonce": server_nonce, "audience": audience, "sig": holder.sign(msg)}


def check_pop(tess: Muhuri, request: dict, pop: dict, expected_nonce: bytes,
              max_skew: int = 60, at: int | None = None, audience: bytes = b"") -> None:
    """Raise ValueError unless the PoP is valid, fresh, for this request and audience."""
    at = now() if at is None else at
    if pop.get("server_nonce") != expected_nonce:
        raise ValueError("PoP nonce mismatch (possible replay)")
    if pop.get("audience", b"") != audience:
        raise ValueError("PoP audience mismatch (wrong resource server)")
    if abs(at - int(pop.get("ts", 0))) > max_skew:
        raise ValueError("PoP timestamp outside acceptance window")
    msg = _pop_msg(tess.muhuri_id(), request, expected_nonce, int(pop["ts"]), audience)
    if not verify_sig(tess.holder_pub, pop.get("sig", b""), msg):
        raise ValueError("PoP signature invalid (holder does not control leaf key)")


class NonceStore:
    """
    Minimal single-use challenge store for one resource server.

    issue()    -> a fresh random nonce, recorded as outstanding
    consume(n) -> True the first time, False on any reuse (replay)

    In production this is a short-TTL keyed cache (Redis, etc.); the contract is
    the same. Used for both PoP nonces and approval nonces (separate scopes).
    """

    def __init__(self):
        self._used: set[bytes] = set()
        self._outstanding: set[bytes] = set()

    def issue(self, nbytes: int = 16) -> bytes:
        n = os.urandom(nbytes)
        self._outstanding.add(n)
        return n

    def consume(self, scope: str, nonce: bytes) -> bool:
        key = scope.encode() + b":" + nonce
        if key in self._used:
            return False
        self._used.add(key)
        return True
