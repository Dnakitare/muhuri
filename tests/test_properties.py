"""
Property-based tests (Hypothesis) for Muhuri's load-bearing invariants.

These complement the hand-written attack tests in `test_muhuri.py`: instead of
one crafted case per property, they assert the property over thousands of
generated inputs and shrink any counterexample to a minimal failing case.

Invariants exercised:
  1. Attenuation never widens authority. If the narrowed credential authorizes a
     request, the parent (broader) credential would have authorized it too. There
     is no representable operation that grows scope.
  2. Out-of-scope requests are never authorized, however the chain is built.
  3. Malformed bytes always fail closed (VerifyError / MalformedCredential) and
     never crash the parser with an unexpected exception type.
"""
import os

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from muhuri import (KeyPair, MalformedCredential, Muhuri, NO_REPLAY_PROTECTION,
                    VerifyError, attenuate, mint, parse)
from muhuri import caveats as cav
from muhuri.pop import prove
from muhuri.verify import authorize, verify_chain

# `attenuate` stamps the not-before from the wall clock, so these tests run on
# real time (with a generous TTL) rather than a frozen instant.
TTL = 3600


def _world():
    return KeyPair.generate(), KeyPair.generate(), KeyPair.generate()


def _try_authorize(t: Muhuri, root_pub: bytes, holder: KeyPair, request: dict) -> bool:
    """True iff the credential authorizes the request right now. No nonce store,
    so single-use replay is out of scope here (covered in test_muhuri.py)."""
    nonce = os.urandom(16)
    pop = prove(t, holder, request, nonce)
    try:
        return authorize(t, root_pub, request, pop, expected_nonce=nonce,
                         nonce_store=NO_REPLAY_PROTECTION).authorized
    except VerifyError:
        return False


# --- Invariant 1 & 2: attenuation only narrows -----------------------------

@settings(max_examples=200, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(
    root_limit=st.integers(min_value=1, max_value=1_000_000),
    narrow_limit=st.integers(min_value=1, max_value=1_000_000),
    amount=st.integers(min_value=0, max_value=2_000_000),
)
def test_attenuation_never_widens_amount(root_limit, narrow_limit, amount):
    root, a, b = _world()
    t0 = mint(root, a.pub,
              [cav.op_in("transfer"), cav.resource_prefix("/x/"), cav.max_amount(root_limit)],
              ttl_seconds=TTL)
    # The narrowed credential delegates to b and adds a second cap.
    t1 = attenuate(t0, a, b.pub, [cav.max_amount(narrow_limit)], ttl_seconds=TTL)

    req = {"op": "transfer", "resource": "/x/acct", "args": {"amount": amount}}

    narrowed_ok = _try_authorize(t1, root.pub, b, req)
    parent_ok = _try_authorize(t0, root.pub, a, req)

    # Core invariant: anything the narrowed credential allows, the parent allows.
    if narrowed_ok:
        assert parent_ok, "attenuation authorized something the parent would not"
    # And the effective limit is exactly the min of the two caps.
    effective = min(root_limit, narrow_limit)
    assert narrowed_ok == (amount <= effective)


@settings(max_examples=200, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(
    allowed_op=st.sampled_from(["transfer", "read", "write"]),
    request_op=st.sampled_from(["transfer", "read", "write", "delete", "admin"]),
)
def test_op_outside_scope_never_authorized(allowed_op, request_op):
    root, a, b = _world()
    t = mint(root, a.pub, [cav.op_in(allowed_op), cav.resource_prefix("/x/")],
             ttl_seconds=TTL)
    req = {"op": request_op, "resource": "/x/acct", "args": {}}
    ok = _try_authorize(t, root.pub, a, req)
    assert ok == (request_op == allowed_op)


@settings(max_examples=150, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(
    prefix=st.text(alphabet="/abcde", min_size=1, max_size=8),
    resource=st.text(alphabet="/abcde", min_size=0, max_size=12),
)
def test_resource_prefix_is_exact(prefix, resource):
    root, a, b = _world()
    t = mint(root, a.pub, [cav.op_in("read"), cav.resource_prefix(prefix)],
             ttl_seconds=TTL)
    req = {"op": "read", "resource": resource, "args": {}}
    ok = _try_authorize(t, root.pub, a, req)
    assert ok == resource.startswith(prefix)


# --- Invariant 3: malformed input always fails closed ----------------------

@settings(max_examples=2000, deadline=None)
@given(blob=st.binary(min_size=0, max_size=4096))
def test_random_bytes_fail_closed(blob):
    """parse() on arbitrary bytes either returns a Muhuri or raises VerifyError —
    never a TypeError, KeyError, or any other uncaught exception."""
    try:
        parse(blob)
    except VerifyError:
        pass  # the only acceptable failure mode


@settings(max_examples=1000, deadline=None)
@given(blob=st.binary(min_size=0, max_size=4096))
def test_from_bytes_fail_closed(blob):
    """The lower-level Muhuri.from_bytes fails closed as MalformedCredential."""
    try:
        Muhuri.from_bytes(blob)
    except MalformedCredential:
        pass


@settings(max_examples=300, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(flip=st.integers(min_value=0, max_value=10_000), val=st.integers(0, 255))
def test_bitflip_breaks_verification(flip, val):
    """Flipping any byte of a valid credential either fails to parse or fails to
    verify — a mutated credential is never silently accepted as valid."""
    root, a, b = _world()
    t = mint(root, a.pub, [cav.op_in("read"), cav.resource_prefix("/x/")],
             ttl_seconds=TTL)
    t = attenuate(t, a, b.pub, [], ttl_seconds=TTL)
    raw = bytearray(t.to_bytes())
    idx = flip % len(raw)
    assume(raw[idx] != val)  # an actual change
    raw[idx] = val

    try:
        cred = parse(bytes(raw))
    except VerifyError:
        return  # failed to parse: acceptable
    try:
        verify_chain(cred, root.pub)
    except VerifyError:
        return  # failed to verify: acceptable
    # If it both parsed and verified, the bytes must be semantically identical to
    # the original (canonical re-encoding can absorb a non-semantic byte change).
    assert cred.to_bytes() == t.to_bytes()
