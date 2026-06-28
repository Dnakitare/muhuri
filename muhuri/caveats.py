"""
Caveats: the scope-narrowing constraint language.

A caveat is a small, typed predicate over a *request descriptor* — the concrete
action an agent is trying to perform right now, e.g.
    {"op": "transfer", "resource": "/accounts/alice/", "args": {"amount": 40}}

Authority in a Muhuri is the *conjunction* of every caveat across every link
in the chain. Each hop can only ADD caveats; the verifier ANDs them; every
caveat must hold. There is no operator in this language that can widen scope
(no disjunction, no negation, no "unless"). That is what makes holder-side,
offline attenuation safe even when the holder is malicious.

`requires_approval` is a *third-party caveat*: satisfied only by a fresh,
single-use signature from a designated approver (a human, or a policy service),
bound to THIS credential, THIS request, with its own nonce and expiry.

[AUDIT R1] Approvals carry a nonce + expiry and are single-use (enforced by the
verifier's nonce store). Without this a single human "approve $500" could be
replayed to move $500 repeatedly.
"""
from __future__ import annotations

import math
import os
import time

from .canonical import cenc, h256
from .keys import is_small_order, verify_sig

APPROVAL_DOMAIN = b"muhuri/approval/v1"


# ---- caveat constructors -------------------------------------------------

def op_in(*ops: str) -> dict:
    return {"t": "op_in", "ops": sorted(set(ops))}


def resource_prefix(prefix: str) -> dict:
    """Confine the request `resource` to a textual prefix.

    [AUDIT FRESH-2] Matching is a raw `str.startswith`, NOT path-aware. Two
    consequences the integrator must handle:
      * Use a trailing separator. `resource_prefix("/accounts/alice")` also admits
        "/accounts/alice_attacker/..."; write "/accounts/alice/" to mean the dir.
      * The resource server MUST canonicalize the resource before acting on it.
        This caveat does not normalize "../", so "/accounts/alice/../bob" passes
        the textual check; resolve paths on your side first.
    """
    return {"t": "resource_prefix", "prefix": prefix}


def max_amount(limit: float, field: str = "amount") -> dict:
    return {"t": "max_amount", "field": field, "limit": limit}


def arg_in(field: str, allowed: list) -> dict:
    return {"t": "arg_in", "field": field, "allowed": sorted(allowed, key=repr)}


def requires_approval(approver_pub: bytes, label: str = "") -> dict:
    # [AUDIT CRYPTO-1] A low-order approver key would let a forged approval
    # (sig over the identity point) satisfy the human gate. The verifier already
    # rejects it via verify_sig; refuse to build the caveat in the first place.
    if not isinstance(approver_pub, (bytes, bytearray)) or len(approver_pub) != 32:
        raise ValueError("approver public key must be 32 bytes")
    if is_small_order(approver_pub):
        raise ValueError("approver public key is a low-order point (forgeable); rejected")
    return {"t": "requires_approval", "approver": approver_pub, "label": label}


# ---- discharge for third-party caveats -----------------------------------

def _approval_msg(muhuri_id: bytes, request: dict, nonce: bytes, exp: int, label: str = "") -> bytes:
    # [AUDIT FRESH-4] The gate's label is bound into the signature so an approval
    # for one gate (e.g. "spend") cannot discharge a different same-approver gate
    # (e.g. "delete"). Without this, label is cryptographically decorative.
    return h256(APPROVAL_DOMAIN, muhuri_id, cenc(request), nonce,
                exp.to_bytes(8, "big"), cenc(label))


def make_approval(approver_kp, muhuri_id: bytes, request: dict, label: str = "",
                  ttl: int = 120) -> dict:
    """
    An approver signs THIS request for THIS gate (`label`) bound to THIS
    credential, with a unique nonce and a short expiry. `label` must match the
    `requires_approval` caveat's label. Single-use: the verifier records the nonce
    and refuses a second presentation.
    """
    nonce = os.urandom(16)
    exp = int(time.time()) + ttl
    msg = _approval_msg(muhuri_id, request, nonce, exp, label)
    return {"approver": approver_kp.pub, "nonce": nonce, "exp": exp,
            "label": label, "sig": approver_kp.sign(msg)}


# ---- evaluation ----------------------------------------------------------

class CaveatError(Exception):
    pass


def _eval_one(cav: dict, request: dict, muhuri_id: bytes, approvals: list[dict], at: int) -> None:
    # [AUDIT FAILCLOSED-1/3] A malformed-but-signed caveat or a non-dict request
    # `args` must fail closed as CaveatError, not crash with KeyError/TypeError.
    if not isinstance(cav, dict):
        raise CaveatError(f"caveat is not a map: {cav!r}")
    t = cav.get("t")
    args = request.get("args", {})
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise CaveatError(f"request args must be a map, got {type(args).__name__}")

    if t == "op_in":
        ops = cav.get("ops")
        if not isinstance(ops, list):
            raise CaveatError("op_in caveat missing a list 'ops'")
        if request.get("op") not in ops:
            raise CaveatError(f"op {request.get('op')!r} not in {ops}")

    elif t == "resource_prefix":
        prefix = cav.get("prefix")
        if not isinstance(prefix, str):
            raise CaveatError("resource_prefix caveat missing a string 'prefix'")
        res = request.get("resource", "")
        if not isinstance(res, str) or not res.startswith(prefix):
            raise CaveatError(f"resource {res!r} not under {prefix!r}")

    elif t == "max_amount":
        if "field" not in cav or "limit" not in cav:
            raise CaveatError("max_amount caveat missing 'field' or 'limit'")
        field, limit = cav["field"], cav["limit"]
        if not isinstance(limit, (int, float)) or isinstance(limit, bool):
            raise CaveatError("max_amount 'limit' must be a number")
        if field not in args:
            raise CaveatError(f"missing required numeric arg {field!r}")
        try:
            val = float(args[field])
        except (TypeError, ValueError):
            raise CaveatError(f"arg {field!r} is not numeric")
        # [AUDIT CAVEAT-1] NaN defeats every ordered comparison (NaN > x and
        # NaN <= x are both False), so a bare `val > limit` silently passes on a
        # NaN amount. Reject non-finite values, and use the negated form so any
        # comparison that returns False (including against NaN) fails closed.
        if not math.isfinite(val):
            raise CaveatError(f"arg {field!r} is not a finite number ({val})")
        if not (val <= limit):
            raise CaveatError(f"{field}={val} exceeds limit {limit}")

    elif t == "arg_in":
        if "field" not in cav or not isinstance(cav.get("allowed"), list):
            raise CaveatError("arg_in caveat missing 'field' or a list 'allowed'")
        field = cav["field"]
        if args.get(field) not in cav["allowed"]:
            raise CaveatError(f"arg {field}={args.get(field)!r} not in allowed set")

    elif t == "requires_approval":
        approver = cav.get("approver")
        if not isinstance(approver, (bytes, bytearray)):
            raise CaveatError("requires_approval caveat missing a bytes 'approver'")
        label = cav.get("label", "")
        if not isinstance(label, str):
            raise CaveatError("requires_approval caveat 'label' must be a string")
        used = None
        for a in approvals:
            if not isinstance(a, dict) or a.get("approver") != approver:
                continue
            # [AUDIT FAILCLOSED-2] exp is attacker-controlled: a non-numeric value
            # or one outside an 8-byte range would crash _approval_msg's to_bytes.
            # Treat malformed/out-of-range exp as a skipped (invalid) approval.
            try:
                exp = int(a.get("exp", 0))
            except (TypeError, ValueError):
                continue
            if not (0 <= exp < (1 << 64)) or exp < at:
                continue  # out of range, or expired
            nonce = a.get("nonce", b"")
            if not isinstance(nonce, (bytes, bytearray)):
                continue
            # [AUDIT FRESH-4] verify against the CAVEAT's label, so an approval
            # signed for another gate does not satisfy this one.
            msg = _approval_msg(muhuri_id, request, nonce, exp, label)
            if verify_sig(approver, a.get("sig", b""), msg):
                used = bytes(nonce)
                break
        if used is None:
            raise CaveatError(
                f"missing valid, unexpired {label or 'approval'} signature from designated approver")
        return used  # [AUDIT FRESH-B] the one approval nonce this gate consumed

    else:
        # Unknown caveat type: fail closed. A verifier must never silently
        # ignore a constraint it does not understand. [AUDIT R-failclosed]
        raise CaveatError(f"unknown caveat type {t!r} (failing closed)")

    return None


def evaluate(caveats: list[dict], request: dict, muhuri_id: bytes,
             approvals: list[dict] | None = None, at: int | None = None) -> list[bytes]:
    """Raise CaveatError if ANY caveat is unsatisfied. Returns the approval nonces
    that actually satisfied a `requires_approval` caveat (verified and label-bound),
    so the caller consumes only those for single-use. [AUDIT FRESH-B] An unmatched
    or unverified approval in the list never gets its nonce burned."""
    approvals = approvals or []
    if not isinstance(approvals, (list, tuple)):
        raise CaveatError("approvals must be a list")
    at = int(time.time()) if at is None else at
    used_nonces = []
    for cav in caveats:
        n = _eval_one(cav, request, muhuri_id, approvals, at)
        if n is not None:
            used_nonces.append(n)
    return used_nonces
