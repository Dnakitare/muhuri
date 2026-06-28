"""
Key material. Muhuri uses Ed25519 throughout:

  * The root *principal* (the accountable human or owning identity) holds a
    long-term keypair. Its public key is the verifier's trust anchor.
  * Every *agent instance* gets an ephemeral keypair, ideally minted at spawn
    and never persisted. The private key never leaves the agent; only public
    keys travel inside the credential.

Public-key signatures are deliberate: in a macaroon/HMAC design every party
that can *verify* a token can also *forge* one, because verification and
minting use the same shared secret. With Ed25519, a resource server can verify
a delegation chain it could never have produced.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


def _pub_bytes(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(frozen=True)
class KeyPair:
    """A signing keypair. `pub` is the 32-byte raw Ed25519 public key."""

    _sk: Ed25519PrivateKey
    pub: bytes

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = Ed25519PrivateKey.generate()
        return cls(sk, _pub_bytes(sk.public_key()))

    @classmethod
    def from_seed(cls, seed32: bytes) -> "KeyPair":
        sk = Ed25519PrivateKey.from_private_bytes(seed32)
        return cls(sk, _pub_bytes(sk.public_key()))

    def seed(self) -> bytes:
        return self._sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)


# --- low-order / degenerate public key rejection [AUDIT CRYPTO-1] -----------
#
# RFC 8032 Ed25519 verification does not reject small-order (torsion) public
# keys. The identity point (encoded 0x01 || 00*31) and the other 7 points of
# the 8-element torsion subgroup admit a universal forgery: the signature
# (R = identity, S = 0) verifies under such a key for ANY message with no
# private key. If one of these lands in a credential as a delegate or approver
# key it breaks holder-of-key, link authenticity, and the human-approval gate.
# We reject any public key whose point has order dividing 8, detected generically
# by [8]P == identity (no hardcoded blocklist to transcribe wrong).

_P = 2 ** 255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P


def _decode_point(pub: bytes):
    """Decode a 32-byte Ed25519 public key to extended coords (X, Y, Z, T), or
    None if it is not a canonical on-curve point."""
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        return None
    y = int.from_bytes(pub, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= _P:  # non-canonical y
        return None
    xx = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P  # x^2 = (y^2-1)/(d y^2+1)
    x = pow(xx, (_P + 3) // 8, _P)                              # p % 8 == 5
    if (x * x - xx) % _P != 0:
        x = (x * pow(2, (_P - 1) // 4, _P)) % _P
    if (x * x - xx) % _P != 0:
        return None  # no square root: not on curve
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = (_P - x) % _P
    return (x, y, 1, (x * y) % _P)


def _double(point):
    """Point doubling in a=-1 twisted Edwards extended coordinates (dbl-2008-hwcd)."""
    X1, Y1, Z1, _T1 = point
    A = (X1 * X1) % _P
    B = (Y1 * Y1) % _P
    C = (2 * Z1 * Z1) % _P
    D = (-A) % _P
    E = ((X1 + Y1) * (X1 + Y1) - A - B) % _P
    G = (D + B) % _P
    F = (G - C) % _P
    H = (D - B) % _P
    return ((E * F) % _P, (G * H) % _P, (F * G) % _P, (E * H) % _P)


def _is_torsion(point) -> bool:
    """True iff the decoded point has order dividing 8 ([8]P == identity)."""
    X, Y, Z, _T = _double(_double(_double(point)))  # [8]P
    return X % _P == 0 and (Y - Z) % _P == 0  # identity is (0 : 1 : 1 : 0)


@lru_cache(maxsize=8192)
def _is_acceptable_key_cached(pub: bytes) -> bool:
    point = _decode_point(pub)
    if point is None:
        return False  # non-canonical / off-curve / inconsistent sign
    return not _is_torsion(point)


def is_acceptable_key(pub: bytes) -> bool:
    """True iff `pub` is the CANONICAL encoding of an on-curve Ed25519 point of
    full prime order, i.e. safe to use as a delegate, approver, or leaf key.

    Two classes must be rejected because raw Ed25519 verification accepts them yet
    they admit the universal forgery R = identity, S = 0 [AUDIT CRYPTO-1, FRESH-1]:
      1. Torsion points (order dividing 8), detected generically by [8]P == identity.
      2. NON-CANONICAL encodings of those points (y >= p, or x == 0 with the sign
         bit set). pyca/cryptography reduces y mod p and accepts these as the
         underlying torsion point, so we must reject them up front rather than
         assume verification will. `_decode_point` returns None for exactly this
         set, so a None decode is a rejection, not a pass.
    Honest keys from KeyPair.generate are always canonical full-order points."""
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        return False
    # Validation is deterministic per key; cache it (keys recur across a chain and
    # across requests) so the pure-Python point math is not paid on every verify.
    return _is_acceptable_key_cached(bytes(pub))


def is_small_order(pub: bytes) -> bool:
    """True iff `pub` must be rejected as a degenerate key: a non-canonical
    encoding, an off-curve point, or a torsion point. The negation of
    is_acceptable_key for a 32-byte key; named for the dominant case."""
    return not is_acceptable_key(pub)


def verify_sig(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """
    Return True iff `sig` is a valid Ed25519 signature of `msg` under `pub`.
    Fails closed (returns False) on any malformed input — wrong-length keys,
    non-bytes, etc. [AUDIT R5/R8] — and on degenerate keys (non-canonical or
    torsion), which would otherwise admit a universal forgery [AUDIT CRYPTO-1].
    """
    if not is_acceptable_key(pub):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
