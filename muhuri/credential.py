"""
The Muhuri credential.

A Muhuri is an append-only chain of signed delegation *links*:

    L0:  principal_root --delegates--> agent_A     (caveats c0)   signed by root
    L1:  agent_A        --delegates--> agent_B     (caveats c1)   signed by A
    L2:  agent_B        --delegates--> agent_C     (caveats c2)   signed by B
                                                   ...

Three bindings make the chain non-spliceable ("the two halves of the muhuri
must match"):

  1. body.dgr of link i  ==  body.dge of link i-1   (delegator now == delegate before)
  2. body.prev of link i  ==  link_id(i-1)          (commits to exact parent bytes+sig)
  3. sig of link i verifies under body.dgr          (the delegator actually signed)

You cannot lift link L2 from one chain and graft it after some L1' from
another chain: its dgr won't equal L1'.dge, and its prev won't equal L1'.id.
This is the direct fix for RFC 8693 delegation-chain splicing.

The whole chain is one compact artifact (~150 bytes + caveats per hop, linear
in depth) and is verifiable fully offline by anyone who knows the root public
key — no authorization-server round trip, no registry lookup.
"""
from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass
from typing import Any

from .canonical import ZERO32, cdec, cenc, h256
from .keys import KeyPair

VERSION = 1
DOMAIN_LINK = b"muhuri/link/v1"
DOMAIN_CRED = b"muhuri/cred/v1"
DOMAIN_SIG = b"muhuri/sig/v1"

# [AUDIT R4] Bound work an attacker can force on a verifier.
MAX_DEPTH = 64           # links per credential
MAX_BYTES = 64 * 1024    # encoded credential size


class MalformedCredential(ValueError):
    """Raised when bytes cannot be parsed into a well-formed credential."""


_REQUIRED = ("v", "prev", "dgr", "dge", "cav", "nbf", "exp", "non", "meta", "sig")


def now() -> int:
    return int(time.time())


@dataclass
class Link:
    prev: bytes          # link_id of parent, or ZERO32 for the root link
    dgr: bytes           # delegator public key (signs this link)
    dge: bytes           # delegate public key (receives authority)
    cav: list[dict]      # caveats added at this hop
    nbf: int             # not-before (unix seconds)
    exp: int             # not-after  (unix seconds)
    non: bytes           # 16-byte uniqueness nonce
    meta: dict           # provenance (agent_id, model, code_digest, ...)
    sig: bytes = b""     # Ed25519 over body_bytes, by dgr

    # ---- canonical body (everything that is signed) ----
    def body(self) -> dict:
        return {
            "v": VERSION, "prev": self.prev, "dgr": self.dgr, "dge": self.dge,
            "cav": self.cav, "nbf": self.nbf, "exp": self.exp,
            "non": self.non, "meta": self.meta,
        }

    def body_bytes(self) -> bytes:
        return cenc(self.body())

    def signing_msg(self) -> bytes:
        return h256(DOMAIN_SIG, self.body_bytes())

    def link_id(self) -> bytes:
        return h256(DOMAIN_LINK, self.body_bytes(), self.sig)

    def sealed(self) -> dict:
        d = self.body()
        d["sig"] = self.sig
        return d

    @classmethod
    def from_sealed(cls, d: dict) -> "Link":
        if not isinstance(d, dict):
            raise MalformedCredential("link is not a map")
        for k in _REQUIRED:
            if k not in d:
                raise MalformedCredential(f"link missing field {k!r}")
        for k in ("prev", "dgr", "dge", "non", "sig"):
            if not isinstance(d[k], (bytes, bytearray)):
                raise MalformedCredential(f"field {k!r} must be bytes")
        if not isinstance(d["cav"], list) or not isinstance(d["meta"], dict):
            raise MalformedCredential("cav must be a list and meta a map")
        if not isinstance(d["nbf"], int) or not isinstance(d["exp"], int):
            raise MalformedCredential("nbf/exp must be integers")
        return cls(
            prev=bytes(d["prev"]), dgr=bytes(d["dgr"]), dge=bytes(d["dge"]),
            cav=d["cav"], nbf=d["nbf"], exp=d["exp"], non=bytes(d["non"]),
            meta=d["meta"], sig=bytes(d["sig"]),
        )


@dataclass
class Muhuri:
    links: list[Link]

    # ---- identity ----
    def muhuri_id(self) -> bytes:
        return h256(DOMAIN_CRED, *[l.link_id() for l in self.links])

    def link_ids(self) -> list[bytes]:
        return [l.link_id() for l in self.links]

    @property
    def leaf(self) -> Link:
        return self.links[-1]

    @property
    def root_pub(self) -> bytes:
        return self.links[0].dgr

    @property
    def holder_pub(self) -> bytes:
        """The key the current holder must prove possession of to act."""
        return self.links[-1].dge

    # ---- serialization (compact, linear) ----
    def to_bytes(self) -> bytes:
        return cenc([l.sealed() for l in self.links])

    def to_string(self) -> str:
        return "mhr1_" + base64.urlsafe_b64encode(self.to_bytes()).decode().rstrip("=")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Muhuri":
        if not isinstance(data, (bytes, bytearray)):
            raise MalformedCredential("credential must be bytes")
        if len(data) > MAX_BYTES:
            raise MalformedCredential(f"credential exceeds {MAX_BYTES} bytes")
        try:
            arr = cdec(data)
        except Exception as e:  # any CBOR decoding failure
            raise MalformedCredential(f"not valid CBOR: {e}")
        if not isinstance(arr, list) or not arr:
            raise MalformedCredential("credential is not a non-empty array of links")
        if len(arr) > MAX_DEPTH:
            raise MalformedCredential(f"credential exceeds max depth {MAX_DEPTH}")
        return cls([Link.from_sealed(d) for d in arr])

    @classmethod
    def from_string(cls, s: str) -> "Muhuri":
        if not isinstance(s, str) or not s.startswith("mhr1_"):
            raise MalformedCredential("not a muhuri string")
        raw = s[len("mhr1_"):]
        raw += "=" * (-len(raw) % 4)
        try:
            data = base64.urlsafe_b64decode(raw)
        except Exception as e:
            raise MalformedCredential(f"bad base64: {e}")
        return cls.from_bytes(data)

    def size_report(self) -> dict:
        return {"hops": len(self.links), "bytes": len(self.to_bytes())}


# ---- minting & attenuation ----------------------------------------------

def mint(root: KeyPair, delegate_pub: bytes, caveats: list[dict],
         ttl_seconds: int = 300, nbf: int | None = None,
         meta: dict | None = None) -> Muhuri:
    """Root principal issues the first delegation link to an agent."""
    nbf = now() if nbf is None else nbf
    link = Link(
        prev=ZERO32, dgr=root.pub, dge=delegate_pub, cav=list(caveats),
        nbf=nbf, exp=nbf + ttl_seconds, non=os.urandom(16), meta=meta or {},
    )
    link.sig = root.sign(link.signing_msg())
    return Muhuri([link])


def attenuate(tess: Muhuri, holder: KeyPair, delegate_pub: bytes,
              add_caveats: list[dict], ttl_seconds: int | None = None,
              meta: dict | None = None) -> Muhuri:
    """
    The current holder narrows the credential and hands it to the next agent.
    Runs fully offline; no contact with the root or any server.

    `holder` MUST control the key the previous link delegated to, otherwise the
    new link will not verify (its dgr must equal the parent's dge). Caveats are
    *added*; the verifier ANDs them with all prior caveats, so scope can only
    shrink. The validity window can only shrink (verifier intersects windows).
    """
    parent = tess.leaf
    if holder.pub != parent.dge:
        raise ValueError("holder key does not match the delegate of the parent link")
    base_nbf = max(now(), parent.nbf)
    exp = parent.exp if ttl_seconds is None else min(parent.exp, base_nbf + ttl_seconds)
    link = Link(
        prev=parent.link_id(), dgr=holder.pub, dge=delegate_pub,
        cav=list(add_caveats), nbf=base_nbf, exp=exp,
        non=os.urandom(16), meta=meta or {},
    )
    link.sig = holder.sign(link.signing_msg())
    return Muhuri(tess.links + [link])
