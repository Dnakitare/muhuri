"""
Generate cross-language test vectors for Muhuri.

Each vector is a self-contained (credential, request, proof-of-possession,
trusted-root, expected-decision) tuple. The Python reference impl is the source
of truth (CLAUDE.md): it emits these, `tests/test_vectors.py` replays them
through the real verifier, and any conforming port (a future Rust core, or a
spec-conformant WASM verifier) must reach the *same decision* on the *same
canonical bytes*.

Determinism: `mint`/`attenuate`/`prove` draw random nonces from `os.urandom`.
To make the emitted bytes byte-stable across runs we install a deterministic,
counter-seeded byte stream for the duration of generation only. The library is
not modified; we patch the `os.urandom` symbol the modules call. Ed25519 itself
is deterministic (RFC 8032), so signatures over identical messages are
identical, and the whole credential hex is reproducible.

    python tools/gen_vectors.py            # writes tests/vectors.json
    python tools/gen_vectors.py --check    # fail if committed vectors are stale

NOTE ON THE BROWSER DEMO: `muhuri-demo.html` signs over a deterministic-JSON
encoding, not the canonical CBOR of the reference. It is a live visual prop, not
a wire-format-conformant port, so it cannot reproduce these byte-for-byte today.
Making the demo consume this file is the WASM-verifier work in NEXT_STEPS (P2.8).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import muhuri.credential as _credmod
import muhuri.pop as _popmod
from muhuri import KeyPair, Muhuri, attenuate, authorize, mint
from muhuri import caveats as cav
from muhuri.pop import prove

OUT = Path(__file__).resolve().parent.parent / "tests" / "vectors.json"

# A fixed mint time well inside any window; all `at`/`ts` are derived from it so
# vectors never depend on the wall clock.
BASE_TIME = 1_700_000_000
TTL = 300


class _DetRandom:
    """Deterministic byte stream: SHA-256 counter mode. Stands in for os.urandom
    during generation so credential/PoP nonces are reproducible."""

    def __init__(self, label: bytes):
        self._seed = b"muhuri-vectors/" + label
        self._ctr = 0

    def __call__(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(self._seed + self._ctr.to_bytes(8, "big")).digest()
            self._ctr += 1
        return out[:n]


def _seed_kp(label: str) -> KeyPair:
    """A keypair from a fixed 32-byte seed, so public keys are stable too."""
    return KeyPair.from_seed(hashlib.sha256(b"muhuri-vectors/key/" + label.encode()).digest()[:32])


# Fixed principals for every vector.
ROOT = _seed_kp("root")
A = _seed_kp("orchestrator")
B = _seed_kp("worker")
APPROVER = _seed_kp("approver")
OUTSIDER = _seed_kp("outsider-root")

# Fixed server challenge (16 bytes) used by the PoP vectors.
SERVER_NONCE = hashlib.sha256(b"muhuri-vectors/server-nonce").digest()[:16]


def _build_two_hop() -> Muhuri:
    """Root grants A (transfer/read under /accounts/alice/, <=$1000); A narrows
    B to <=$50. Mirrors the demo and the existing test backbone."""
    t = mint(ROOT, A.pub,
             [cav.op_in("transfer", "read"),
              cav.resource_prefix("/accounts/alice/"),
              cav.max_amount(1000)],
             ttl_seconds=TTL, nbf=BASE_TIME)
    return attenuate(t, A, B.pub, [cav.max_amount(50)], ttl_seconds=TTL)


def _build_readonly() -> Muhuri:
    """Root grants A a pure read scope (no max_amount), so amount-less reads pass."""
    return mint(ROOT, A.pub,
                [cav.op_in("read"), cav.resource_prefix("/accounts/alice/")],
                ttl_seconds=TTL, nbf=BASE_TIME)


def _build_approval_chain() -> Muhuri:
    """Root grants A a transfer that additionally requires APPROVER's sign-off."""
    t = mint(ROOT, A.pub,
             [cav.op_in("transfer"),
              cav.resource_prefix("/accounts/alice/"),
              cav.max_amount(1000),
              cav.requires_approval(APPROVER.pub, "treasurer")],
             ttl_seconds=TTL, nbf=BASE_TIME)
    return attenuate(t, A, B.pub, [], ttl_seconds=TTL)


def _pop_record(t: Muhuri, holder: KeyPair, request: dict, *, audience: bytes = b"") -> dict:
    pop = prove(t, holder, request, SERVER_NONCE, ts=BASE_TIME + 1, audience=audience)
    return {
        "ts": pop["ts"],
        "server_nonce_hex": pop["server_nonce"].hex(),
        "audience_hex": pop["audience"].hex(),
        "sig_hex": pop["sig"].hex(),
    }


def _vector(name, expect, t, request, holder, *, reason="", at=None,
            trusted_root=ROOT.pub, approvals=None, audience=b"") -> dict:
    v = {
        "name": name,
        "expect": expect,                      # "authorized" | "blocked"
        "trusted_root_hex": trusted_root.hex(),
        "credential_hex": t.to_bytes().hex(),
        "request": request,
        "pop": _pop_record(t, holder, request, audience=audience),
        "expected_nonce_hex": SERVER_NONCE.hex(),
        "audience_hex": audience.hex(),
        "at": BASE_TIME + 1 if at is None else at,
    }
    if reason:
        v["reason"] = reason
    if approvals is not None:
        v["approvals"] = approvals
    return v


def build_vectors() -> dict:
    two = _build_two_hop()
    readonly = _build_readonly()
    appr = _build_approval_chain()
    vectors = []

    # --- authorized ---
    vectors.append(_vector(
        "happy_path_within_scope", "authorized", two,
        {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 40}}, B))

    vectors.append(_vector(
        "read_op_within_scope", "authorized", readonly,
        {"op": "read", "resource": "/accounts/alice/checking", "args": {}}, A))

    # PoP bound to a specific resource server.
    aud = b"https://bank.example/api"
    vectors.append(_vector(
        "audience_bound_match", "authorized", two,
        {"op": "transfer", "resource": "/accounts/alice/savings", "args": {"amount": 10}}, B,
        audience=aud))

    # requires_approval satisfied by a fresh, bound approver signature.
    appr_req = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 500}}
    approval = cav.make_approval(APPROVER, appr.muhuri_id(), appr_req, ttl=600)
    # Pin the approval's timestamp-derived expiry deterministically.
    approval = {
        "approver": approval["approver"], "nonce": approval["nonce"],
        "exp": BASE_TIME + 600, "sig": None,
    }
    # Re-sign with the deterministic exp (make_approval used wall-clock exp).
    from muhuri.caveats import _approval_msg  # internal: vectors must pin exp
    approval["sig"] = APPROVER.sign(_approval_msg(appr.muhuri_id(), appr_req, approval["nonce"], approval["exp"]))
    appr_record = [{"approver": approval["approver"].hex(), "nonce": approval["nonce"].hex(),
                    "exp": approval["exp"], "sig_hex": approval["sig"].hex()}]
    vectors.append(_vector(
        "requires_approval_satisfied", "authorized", appr, appr_req, B,
        approvals=appr_record))

    # --- blocked ---
    vectors.append(_vector(
        "amount_over_narrowed_limit", "blocked", two,
        {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 75}}, B,
        reason="scope: amount 75 exceeds the $50 limit added at the second hop"))

    vectors.append(_vector(
        "op_not_in_scope", "blocked", two,
        {"op": "delete", "resource": "/accounts/alice/checking", "args": {}}, B,
        reason="scope: op 'delete' not in {read, transfer}"))

    vectors.append(_vector(
        "resource_outside_prefix", "blocked", two,
        {"op": "transfer", "resource": "/accounts/bob/checking", "args": {"amount": 10}}, B,
        reason="scope: resource not under /accounts/alice/ (the demo's 'send to Bob')"))

    vectors.append(_vector(
        "expired_credential", "blocked", two,
        {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 10}}, B,
        at=BASE_TIME + TTL + 1,
        reason="window: evaluated after exp"))

    vectors.append(_vector(
        "wrong_trusted_root", "blocked", two,
        {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 10}}, B,
        trusted_root=OUTSIDER.pub,
        reason="anchor: chain root is not the configured trusted principal"))

    vectors.append(_vector(
        "requires_approval_missing", "blocked", appr, appr_req, B,
        approvals=[],
        reason="scope: third-party approval caveat undischarged"))

    # AUDIT R8: a max_amount caveat fails closed on an amount-less op sharing the
    # same credential. Blocking is the correct, documented default.
    vectors.append(_vector(
        "max_amount_fails_closed_on_read", "blocked", two,
        {"op": "read", "resource": "/accounts/alice/checking", "args": {}}, B,
        reason="scope (R8): max_amount requires an 'amount'; read has none, so fail closed"))

    # Tampered caveat: decode the valid two-hop credential, rewrite the leaf's
    # $50 limit to $9000, re-encode WITHOUT re-signing. Signature must fail.
    tampered = Muhuri.from_bytes(two.to_bytes())
    for c in tampered.leaf.cav:
        if c.get("t") == "max_amount":
            c["limit"] = 9000
    tampered_req = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 9000}}
    vt = _vector("tampered_caveat_signature", "blocked", tampered, tampered_req, B,
                 reason="crypto: leaf signature no longer matches the canonical body")
    vectors.append(vt)

    # Spliced chain: graft B's hop from a *different* parent chain onto a root
    # link it was never issued under. prev/dgr bindings must reject it.
    other = mint(ROOT, A.pub, [cav.op_in("transfer"), cav.resource_prefix("/accounts/alice/"),
                               cav.max_amount(1_000_000)], ttl_seconds=TTL, nbf=BASE_TIME)
    spliced = Muhuri([other.links[0], two.links[1]])
    splice_req = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 900_000}}
    vectors.append(_vector(
        "spliced_chain", "blocked", spliced, splice_req, B,
        reason="splice: leaf.prev/dgr do not bind to the grafted root link"))

    return {
        "suite": "Ed25519 + SHA-256, canonical CBOR (RFC 8949 §4.2.1)",
        "wire_version": 1,
        "generator": "tools/gen_vectors.py",
        "source_of_truth": "Python reference implementation (muhuri/)",
        "note": ("Conforming ports must reach the same `expect` on the same "
                 "credential_hex. The browser demo uses a JSON encoding, not this "
                 "canonical CBOR, so it is not yet a conforming port (NEXT_STEPS P2.8)."),
        "base_time": BASE_TIME,
        "vectors": vectors,
    }


def _generate() -> dict:
    # Install deterministic randomness AND a frozen clock for the generation
    # window only. `attenuate` reads the wall clock for the link's not-before, so
    # without freezing `now()` the emitted bytes would shift every run.
    cred_orig, pop_orig = _credmod.os.urandom, _popmod.os.urandom
    now_orig = _credmod.now
    cav_mod = sys.modules["muhuri.caveats"]
    cav_orig = cav_mod.os.urandom
    _credmod.os.urandom = _DetRandom(b"cred")
    _popmod.os.urandom = _DetRandom(b"pop")
    cav_mod.os.urandom = _DetRandom(b"cav")
    _credmod.now = lambda: BASE_TIME
    try:
        data = build_vectors()
    finally:
        _credmod.os.urandom, _popmod.os.urandom = cred_orig, pop_orig
        cav_mod.os.urandom = cav_orig
        _credmod.now = now_orig
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Muhuri cross-language test vectors.")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if committed vectors differ from a fresh generation")
    args = ap.parse_args()

    data = _generate()
    rendered = json.dumps(data, indent=2, sort_keys=True) + "\n"

    if args.check:
        if not OUT.exists():
            print(f"missing {OUT}", file=sys.stderr)
            return 1
        if OUT.read_text() != rendered:
            print(f"{OUT} is stale; run `python tools/gen_vectors.py`", file=sys.stderr)
            return 1
        print(f"{OUT.name} up to date ({len(data['vectors'])} vectors)")
        return 0

    OUT.write_text(rendered)
    print(f"wrote {OUT} ({len(data['vectors'])} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
