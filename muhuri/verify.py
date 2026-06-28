"""
Offline verification.

`verify_chain` validates the cryptographic structure of a Muhuri against an
explicit set of trusted root keys. It needs no network.

`authorize` is the full per-request gate: structure + freshness/PoP + scope +
replay defenses. It returns a Decision or raises VerifyError. Every check fails
closed.

  root anchor      links[0].dgr in trusted_roots   forged / unrooted chains
  splice bind 1    link.dgr == parent.dge          chain splicing (mismatched actor)
  splice bind 2    link.prev == parent.link_id     chain splicing (grafted parent)
  signature        Ed25519 verify under dgr        forgery; HMAC verifier-as-forger
  depth cap        len(chain) <= max_depth         CPU DoS                 [R4]
  window           max(nbf) <= now <= min(exp)     stale / not-yet-valid
  revocation       no link_id revoked              withdrawn delegations
  PoP              holder signs fresh challenge     stolen-credential replay
  PoP single-use   nonce consumed once             same-window replay      [R2]
  audience         PoP bound to this server         cross-server relay      [R7]
  approval         fresh, single-use, unexpired     approval double-spend   [R1]
  caveats          conjunction of all hops holds    scope escalation

[AUDIT R3] The trust anchor MUST come from the verifier's configuration, never
from the credential itself. `authorize`/`verify_chain` take `trusted_roots`
explicitly and never derive it from the token. Passing `tess.root_pub` as the
anchor is the one fatal footgun and is called out loudly here and in the docs.
"""
from __future__ import annotations

from dataclasses import dataclass

from .canonical import ZERO32
from .caveats import CaveatError, evaluate
from .credential import MAX_DEPTH, VERSION, MalformedCredential, Muhuri, now
from .keys import verify_sig
from .pop import check_pop
from .revocation import AllowAll, Revoker


class VerifyError(Exception):
    pass


@dataclass
class Decision:
    authorized: bool
    muhuri_id: bytes
    root_pub: bytes
    holder_pub: bytes
    effective_caveats: list[dict]
    nbf: int
    exp: int
    depth: int


def _normalize_roots(trusted_roots) -> set[bytes]:
    if isinstance(trusted_roots, (bytes, bytearray)):
        return {bytes(trusted_roots)}
    roots = {bytes(r) for r in trusted_roots}
    if not roots:
        raise VerifyError("no trusted roots configured")
    return roots


def verify_chain(tess: Muhuri, trusted_roots, at: int | None = None,
                 revoker: Revoker | None = None, max_depth: int = MAX_DEPTH) -> Decision:
    at = now() if at is None else at
    revoker = revoker or AllowAll()
    roots = _normalize_roots(trusted_roots)

    if not tess.links:
        raise VerifyError("empty credential")
    if len(tess.links) > max_depth:
        raise VerifyError(f"chain too deep ({len(tess.links)} > {max_depth})")
    if tess.links[0].dgr not in roots:
        raise VerifyError("root link is not anchored to a trusted principal")

    eff_nbf, eff_exp, eff_caveats = 0, 1 << 62, []
    for i, link in enumerate(tess.links):
        if link.body()["v"] != VERSION:
            raise VerifyError(f"link {i}: unsupported version")
        if link.nbf > link.exp:
            raise VerifyError(f"link {i}: inverted validity window")

        if i == 0:
            if link.prev != ZERO32:
                raise VerifyError("root link must have empty prev")
        else:
            parent = tess.links[i - 1]
            if link.prev != parent.link_id():
                raise VerifyError(f"link {i}: prev does not match parent (splice)")
            if link.dgr != parent.dge:
                raise VerifyError(f"link {i}: delegator != parent delegate (splice)")

        if not verify_sig(link.dgr, link.sig, link.signing_msg()):
            raise VerifyError(f"link {i}: signature invalid")
        if revoker.is_revoked(link.link_id()):
            raise VerifyError(f"link {i}: revoked")

        eff_nbf = max(eff_nbf, link.nbf)
        eff_exp = min(eff_exp, link.exp)
        eff_caveats.extend(link.cav)

    if at < eff_nbf:
        raise VerifyError("credential not yet valid")
    if at > eff_exp:
        raise VerifyError("credential expired")

    return Decision(
        authorized=False, muhuri_id=tess.muhuri_id(), root_pub=tess.root_pub,
        holder_pub=tess.holder_pub, effective_caveats=eff_caveats,
        nbf=eff_nbf, exp=eff_exp, depth=len(tess.links),
    )


def authorize(tess: Muhuri, trusted_roots, request: dict, pop: dict,
              expected_nonce: bytes, approvals: list[dict] | None = None,
              revoker: Revoker | None = None, at: int | None = None,
              max_skew: int = 60, max_depth: int = MAX_DEPTH,
              nonce_store=None, audience: bytes = b"") -> Decision:
    """Full per-request gate. Returns an authorized Decision or raises VerifyError."""
    at = now() if at is None else at
    dec = verify_chain(tess, trusted_roots, at=at, revoker=revoker, max_depth=max_depth)

    # [R2] single-use PoP nonce
    if nonce_store is not None and not nonce_store.consume("pop", expected_nonce):
        raise VerifyError("PoP nonce already used (replay)")

    # holder must control the leaf key, for THIS request, THIS server, freshly
    try:
        check_pop(tess, request, pop, expected_nonce, max_skew=max_skew, at=at, audience=audience)
    except ValueError as e:
        raise VerifyError(f"proof-of-possession failed: {e}")

    # [R1] single-use approval nonces
    if nonce_store is not None:
        for a in (approvals or []):
            n = a.get("nonce")
            if not isinstance(n, (bytes, bytearray)) or not nonce_store.consume("approval", bytes(n)):
                raise VerifyError("approval nonce already used or missing (replay)")

    # the concrete action must satisfy every caveat across every hop
    try:
        evaluate(dec.effective_caveats, request, dec.muhuri_id, approvals, at=at)
    except CaveatError as e:
        raise VerifyError(f"scope check failed: {e}")

    dec.authorized = True
    return dec


def parse(data) -> Muhuri:
    """Parse wire bytes or a mhr1_ string into a Muhuri, failing closed."""
    try:
        if isinstance(data, str):
            return Muhuri.from_string(data)
        return Muhuri.from_bytes(data)
    except MalformedCredential as e:
        raise VerifyError(f"malformed credential: {e}")
