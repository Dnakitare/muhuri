"""
Revocation.

Offline-verifiable credentials and instant revocation are in tension: if a
verifier never phones home, how does it learn a credential was pulled? Muhuri
takes the honest, layered position the IETF thread also lands on:

  1. Short lifetimes by default (set at mint/attenuate). This is the primary
     control and needs no infrastructure. A 5-minute credential bounds blast
     radius cheaply.

  2. An optional revocation oracle for the window before expiry. Because every
     link has a stable `link_id`, you can revoke at any granularity:
        - revoke the ROOT link_id  -> the entire delegation subtree dies
        - revoke a MIDDLE link_id  -> just that branch and its descendants die
     The base `RevocationSet` is a simple published deny-list. The
     `Accumulator` protocol is the drop-in seam for a cryptographic
     accumulator / short-lived signed status list in production, so verifiers
     can check non-membership without downloading the whole set.

Muhuri does NOT claim to solve instant global offline revocation — no bearer-
style credential can. It makes the tradeoff explicit and gives operators the
knobs.
"""
from __future__ import annotations

from typing import Iterable, Protocol


class Revoker(Protocol):
    def is_revoked(self, link_id: bytes) -> bool: ...


class RevocationSet:
    """A simple deny-list of revoked link_ids (any hop)."""

    def __init__(self, revoked: Iterable[bytes] = ()):
        self._revoked = set(revoked)

    def revoke(self, link_id: bytes) -> None:
        self._revoked.add(link_id)

    def is_revoked(self, link_id: bytes) -> bool:
        return link_id in self._revoked


class AllowAll:
    """No revocation. Relies purely on short lifetimes."""

    def is_revoked(self, link_id: bytes) -> bool:
        return False
