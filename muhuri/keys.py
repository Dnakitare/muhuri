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


def verify_sig(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """
    Return True iff `sig` is a valid Ed25519 signature of `msg` under `pub`.
    Fails closed (returns False) on any malformed input — wrong-length keys,
    non-bytes, etc. [AUDIT R5/R8]
    """
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
