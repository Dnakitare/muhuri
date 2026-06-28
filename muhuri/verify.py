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
from .pop import check_pop, NonceStore
from .revocation import AllowAll, Revoker


class VerifyError(Exception):
    pass


class _NoReplayProtection:
    """Sentinel for the explicit, greppable opt-out from single-use replay
    protection. See NO_REPLAY_PROTECTION."""
    __slots__ = ()

    def __repr__(self):
        return "NO_REPLAY_PROTECTION"


# [AUDIT AUTHZ-1] `authorize` requires a nonce_store so replay protection (R1
# approval double-spend, R2 PoP replay) cannot be silently disabled by omission.
# A caller with no shared store (e.g. a context that handles replay elsewhere)
# must opt out on purpose by passing this sentinel.
NO_REPLAY_PROTECTION = _NoReplayProtection()


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
              *, nonce_store, audience: bytes = b"") -> Decision:
    """Full per-request gate. Returns an authorized Decision or raises VerifyError.

    `nonce_store` is required [AUDIT AUTHZ-1]: pass a single-use NonceStore shared
    across requests to enforce R1/R2 replay protection, or NO_REPLAY_PROTECTION to
    opt out on purpose. Omitting it is an error rather than a silent insecure path.

    Fail-closed contract: all UNTRUSTED, per-request inputs (the credential bytes,
    `request`, `pop`, `approvals`) fail closed as VerifyError on any malformation.
    Verifier CONFIGURATION (`trusted_roots`, `at`, `max_depth`, `revoker`,
    `audience`) is the integrator's own input; misconfiguring it surfaces as an
    ordinary exception (a loud programming error), not VerifyError. [AUDIT FAILCLOSED-CONFIG]
    """
    at = now() if at is None else at

    # [AUDIT AUTHZ-1, REPLAY-3] Resolve the replay-protection contract before any
    # work. Gate on the real NonceStore type (or a subclass), not a bare consume()
    # attribute, so a no-op object cannot silently disable single-use protection.
    if nonce_store is NO_REPLAY_PROTECTION:
        store = None
    elif isinstance(nonce_store, NonceStore):
        store = nonce_store
    else:
        raise VerifyError(
            "authorize requires a NonceStore (or subclass) for single-use replay "
            "protection (R1 approval double-spend, R2 PoP replay). Pass one shared "
            "across requests, or NO_REPLAY_PROTECTION to opt out explicitly.")

    dec = verify_chain(tess, trusted_roots, at=at, revoker=revoker, max_depth=max_depth)

    # Holder must control the leaf key, for THIS request, THIS server, freshly.
    # [REPLAY-2] Verify the proof BEFORE consuming the nonce, so a forged PoP that
    # cites an honest outstanding nonce cannot burn it (denial of service).
    try:
        check_pop(tess, request, pop, expected_nonce, max_skew=max_skew, at=at, audience=audience)
    except ValueError as e:
        raise VerifyError(f"proof-of-possession failed: {e}")
    except Exception as e:  # [FRESH-1] backstop: a malformed pop fails closed too
        raise VerifyError(f"proof-of-possession failed (malformed pop): {e!r}")
    # [R2] single-use PoP nonce, consumed only after the proof verified.
    if store is not None and not store.consume("pop", expected_nonce):
        raise VerifyError("PoP nonce already used (replay)")

    # The concrete action must satisfy every caveat across every hop.
    # [FAILCLOSED-1/2/3] Attacker-influenced caveat/approval/request content must
    # fail closed as VerifyError, never escape as a raw KeyError/OverflowError/etc.
    try:
        used_approval_nonces = evaluate(dec.effective_caveats, request, dec.muhuri_id, approvals, at=at)
    except CaveatError as e:
        raise VerifyError(f"scope check failed: {e}")
    except Exception as e:  # backstop; _eval_one also guards each shape inline
        raise VerifyError(f"scope check failed (malformed caveat/approval/request): {e!r}")

    # [R1][REPLAY-2][FRESH-B] Consume only the approval nonces that actually
    # satisfied a caveat (verified and label-bound), after evaluate() validated
    # them, so an unmatched or unverified approval in the list can't burn a nonce.
    # [AUDIT APPROVAL-1] Consume each DISTINCT nonce once: two identical gates
    # (g AND g == g) share one approval, so dedup before consuming or the second
    # consume would wrongly reject a legitimate request.
    if store is not None:
        for n in dict.fromkeys(used_approval_nonces):
            if not store.consume("approval", bytes(n)):
                raise VerifyError("approval nonce already used (replay)")
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
