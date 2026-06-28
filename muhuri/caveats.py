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

import os
import time

from .canonical import cenc, h256
from .keys import verify_sig

APPROVAL_DOMAIN = b"muhuri/approval/v1"


# ---- caveat constructors -------------------------------------------------

def op_in(*ops: str) -> dict:
    return {"t": "op_in", "ops": sorted(set(ops))}


def resource_prefix(prefix: str) -> dict:
    return {"t": "resource_prefix", "prefix": prefix}


def max_amount(limit: float, field: str = "amount") -> dict:
    return {"t": "max_amount", "field": field, "limit": limit}


def arg_in(field: str, allowed: list) -> dict:
    return {"t": "arg_in", "field": field, "allowed": sorted(allowed, key=repr)}


def requires_approval(approver_pub: bytes, label: str = "") -> dict:
    return {"t": "requires_approval", "approver": approver_pub, "label": label}


# ---- discharge for third-party caveats -----------------------------------

def _approval_msg(muhuri_id: bytes, request: dict, nonce: bytes, exp: int) -> bytes:
    return h256(APPROVAL_DOMAIN, muhuri_id, cenc(request), nonce, exp.to_bytes(8, "big"))


def make_approval(approver_kp, muhuri_id: bytes, request: dict, ttl: int = 120) -> dict:
    """
    An approver signs THIS request bound to THIS credential, with a unique nonce
    and a short expiry. Single-use: the verifier records the nonce and refuses a
    second presentation.
    """
    nonce = os.urandom(16)
    exp = int(time.time()) + ttl
    msg = _approval_msg(muhuri_id, request, nonce, exp)
    return {"approver": approver_kp.pub, "nonce": nonce, "exp": exp, "sig": approver_kp.sign(msg)}


# ---- evaluation ----------------------------------------------------------

class CaveatError(Exception):
    pass


def _eval_one(cav: dict, request: dict, muhuri_id: bytes, approvals: list[dict], at: int) -> None:
    t = cav.get("t")
    args = request.get("args", {}) or {}

    if t == "op_in":
        if request.get("op") not in cav["ops"]:
            raise CaveatError(f"op {request.get('op')!r} not in {cav['ops']}")

    elif t == "resource_prefix":
        res = request.get("resource", "")
        if not isinstance(res, str) or not res.startswith(cav["prefix"]):
            raise CaveatError(f"resource {res!r} not under {cav['prefix']!r}")

    elif t == "max_amount":
        field, limit = cav["field"], cav["limit"]
        if field not in args:
            raise CaveatError(f"missing required numeric arg {field!r}")
        try:
            val = float(args[field])
        except (TypeError, ValueError):
            raise CaveatError(f"arg {field!r} is not numeric")
        if val > limit:
            raise CaveatError(f"{field}={val} exceeds limit {limit}")

    elif t == "arg_in":
        field = cav["field"]
        if args.get(field) not in cav["allowed"]:
            raise CaveatError(f"arg {field}={args.get(field)!r} not in allowed set")

    elif t == "requires_approval":
        ok = False
        for a in approvals:
            if a.get("approver") != cav["approver"]:
                continue
            exp = int(a.get("exp", 0))
            if exp < at:
                continue  # expired approval
            msg = _approval_msg(muhuri_id, request, a.get("nonce", b""), exp)
            if verify_sig(cav["approver"], a.get("sig", b""), msg):
                ok = True
                break
        if not ok:
            label = cav.get("label") or "approval"
            raise CaveatError(f"missing valid, unexpired {label} signature from designated approver")

    else:
        # Unknown caveat type: fail closed. A verifier must never silently
        # ignore a constraint it does not understand. [AUDIT R-failclosed]
        raise CaveatError(f"unknown caveat type {t!r} (failing closed)")


def evaluate(caveats: list[dict], request: dict, muhuri_id: bytes,
             approvals: list[dict] | None = None, at: int | None = None) -> None:
    """Raise CaveatError if ANY caveat is unsatisfied. Silence == authorized."""
    approvals = approvals or []
    at = int(time.time()) if at is None else at
    for cav in caveats:
        _eval_one(cav, request, muhuri_id, approvals, at)
