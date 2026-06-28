"""
Regression tests for the three High-severity findings from the independent
red-team (June 2026). Each test reproduces the original attack and asserts it is
now blocked. These call the REAL `authorize` (not the test shim), so they pin the
actual fixed contract.

  CRYPTO-1  low-order / identity Ed25519 keys -> universal signature forgery
  AUTHZ-1   replay protection silently off when nonce_store is omitted
  CAVEAT-1  NaN defeats the max_amount spending cap
"""
import os

import pytest

from muhuri import (KeyPair, mint, attenuate, authorize, verify_chain, verify_sig,
                    is_small_order, NonceStore, NO_REPLAY_PROTECTION, VerifyError)
from muhuri import caveats as cav
from muhuri.caveats import _approval_msg
from muhuri.pop import prove

# The identity point and its universal forgery (R = identity, S = 0).
LOW = bytes.fromhex("01" + "00" * 31)
FORGE = LOW + bytes(32)
ALLZERO = bytes(32)


# ---- CRYPTO-1 -------------------------------------------------------------

def test_verify_sig_rejects_low_order_forgery():
    # The forgery verified under the identity key before the fix.
    assert verify_sig(LOW, FORGE, b"hello") is False
    assert verify_sig(LOW, FORGE, b"a totally different message") is False
    assert verify_sig(ALLZERO, ALLZERO + bytes(32), b"x") is False


def test_is_small_order_flags_torsion_points_only():
    assert is_small_order(LOW) is True
    assert is_small_order(ALLZERO) is True
    # 2000 honestly generated keys are never torsion points.
    for _ in range(2000):
        assert is_small_order(KeyPair.generate().pub) is False


def test_real_signatures_still_verify():
    kp = KeyPair.generate()
    msg = b"legitimate message"
    assert verify_sig(kp.pub, kp.sign(msg), msg) is True


def test_mint_and_attenuate_reject_low_order_delegate():
    root, mid = KeyPair.generate(), KeyPair.generate()
    with pytest.raises(ValueError, match="low-order"):
        mint(root, LOW, [cav.op_in("read")], 300)
    good = mint(root, mid.pub, [cav.op_in("read")], 300)
    with pytest.raises(ValueError, match="low-order"):
        attenuate(good, mid, LOW, [])


def test_low_order_approver_forgery_blocked_end_to_end():
    # requires_approval refuses a low-order approver at construction...
    with pytest.raises(ValueError, match="low-order"):
        cav.requires_approval(LOW, "treasury")

    # ...and even if a malicious delegator hand-builds the caveat, a forged
    # approval signed by "nobody" (FORGE under LOW) does not satisfy the gate.
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    evil_caveat = {"t": "requires_approval", "approver": LOW, "label": "treasury"}
    t = mint(root, a.pub, [cav.op_in("transfer"), evil_caveat], 300)
    t = attenuate(t, a, b.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 10}}
    n = os.urandom(16)
    forged_approval = {"approver": LOW, "nonce": os.urandom(16),
                       "exp": 1 << 40, "sig": FORGE}
    with pytest.raises(VerifyError, match="approver"):
        authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                  approvals=[forged_approval], nonce_store=NO_REPLAY_PROTECTION)


# ---- AUTHZ-1 --------------------------------------------------------------

def _chain():
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("read"), cav.resource_prefix("/x/")], 300)
    t = attenuate(t, a, b.pub, [])
    return root, b, t


def test_authorize_requires_nonce_store():
    root, b, t = _chain()
    req = {"op": "read", "resource": "/x/y", "args": {}}
    n = os.urandom(16)
    pop = prove(t, b, req, n)
    # Omitting nonce_store is a hard, loud failure, not a silent insecure pass.
    with pytest.raises(TypeError):
        authorize(t, root.pub, req, pop, expected_nonce=n)
    # An explicit None (or any non-store) fails closed as VerifyError.
    with pytest.raises(VerifyError, match="requires a NonceStore"):
        authorize(t, root.pub, req, pop, expected_nonce=n, nonce_store=None)


def test_pop_replay_blocked_with_store():
    root, b, t = _chain()
    store = NonceStore()
    req = {"op": "read", "resource": "/x/y", "args": {}}
    n = store.issue()
    pop = prove(t, b, req, n)
    assert authorize(t, root.pub, req, pop, expected_nonce=n, nonce_store=store).authorized
    with pytest.raises(VerifyError, match="already used"):
        authorize(t, root.pub, req, pop, expected_nonce=n, nonce_store=store)


def test_approval_double_spend_blocked_with_store():
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    approver = KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("transfer"),
                           cav.requires_approval(approver.pub, "treasury")], 300)
    t = attenuate(t, a, b.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 500}}
    approval = cav.make_approval(approver, t.muhuri_id(), req, "treasury")
    store = NonceStore()
    n1 = store.issue()
    assert authorize(t, root.pub, req, prove(t, b, req, n1), expected_nonce=n1,
                     approvals=[approval], nonce_store=store).authorized
    # One human approval must not authorize a second transfer.
    n2 = store.issue()
    with pytest.raises(VerifyError, match="approval nonce already used"):
        authorize(t, root.pub, req, prove(t, b, req, n2), expected_nonce=n2,
                  approvals=[approval], nonce_store=store)


def test_no_replay_protection_is_an_explicit_opt_out():
    # The sentinel exists so opting out is deliberate and greppable.
    root, b, t = _chain()
    req = {"op": "read", "resource": "/x/y", "args": {}}
    n = os.urandom(16)
    pop = prove(t, b, req, n)
    # Same nonce twice succeeds only because replay protection was explicitly off.
    assert authorize(t, root.pub, req, pop, expected_nonce=n,
                     nonce_store=NO_REPLAY_PROTECTION).authorized
    assert authorize(t, root.pub, req, pop, expected_nonce=n,
                     nonce_store=NO_REPLAY_PROTECTION).authorized


# ---- CAVEAT-1 -------------------------------------------------------------

@pytest.mark.parametrize("amount", [float("nan"), "nan", float("inf"), "inf", "-inf"])
def test_nan_and_inf_do_not_bypass_max_amount(amount):
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("transfer"), cav.resource_prefix("/x/"),
                           cav.max_amount(100)], 300)
    t = attenuate(t, a, b.pub, [])
    req = {"op": "transfer", "resource": "/x/acct", "args": {"amount": amount}}
    n = os.urandom(16)
    with pytest.raises(VerifyError):
        authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                  nonce_store=NO_REPLAY_PROTECTION)


def test_max_amount_still_allows_legitimate_and_blocks_over_limit():
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("transfer"), cav.resource_prefix("/x/"),
                           cav.max_amount(100)], 300)
    t = attenuate(t, a, b.pub, [])
    for amount, allowed in [(40, True), (100, True), (100.01, False), (500, False)]:
        req = {"op": "transfer", "resource": "/x/acct", "args": {"amount": amount}}
        n = os.urandom(16)
        if allowed:
            assert authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                             nonce_store=NO_REPLAY_PROTECTION).authorized
        else:
            with pytest.raises(VerifyError, match="exceeds"):
                authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                          nonce_store=NO_REPLAY_PROTECTION)


# ---- Round 2 regressions --------------------------------------------------

# CRYPTO-1 / FRESH-1: non-canonical encodings of torsion points must be rejected.
def _forgeable_encodings():
    """Every 'suspicious' 32-byte encoding that raw Ed25519 accepts the forgery
    (R=identity, S=0) for. The fix must reject exactly these."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    P = 2 ** 255 - 19
    msgs = [b"a", b"b", b"transfer 1000000", bytes(32)]
    cands = set()
    for y in [0, 1, P - 1, P, P + 1, (1 << 255) - 1]:
        for sign in (0, 1):
            cands.add(((sign << 255) | (y & ((1 << 255) - 1))).to_bytes(32, "little"))
    for hx in ["e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
               "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
               "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
               "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"]:
        b = bytes.fromhex(hx)
        cands.add(b); cands.add(b[:31] + bytes([b[31] | 0x80]))
    forgeable = []
    for E in cands:
        try:
            k = Ed25519PublicKey.from_public_bytes(E)
        except Exception:
            continue
        for m in msgs:
            try:
                k.verify(FORGE, m); forgeable.append(E); break
            except InvalidSignature:
                continue
            except Exception:
                break
    return forgeable


def test_noncanonical_torsion_encodings_are_rejected():
    forgeable = _forgeable_encodings()
    assert len(forgeable) >= 8, "test set should include the dangerous encodings"
    for E in forgeable:
        assert is_small_order(E) is True, E.hex()       # rejected by the predicate
        assert verify_sig(E, FORGE, b"a") is False, E.hex()  # forgery dead


def test_low_order_link_append_is_rejected_by_verify_chain():
    # A holder of only the public bytes tries to append a link delegating from a
    # degenerate key to their own key, signed with the universal forgery.
    from muhuri import Muhuri
    from muhuri.credential import Link, ZERO32
    forgeable = _forgeable_encodings()
    bad = forgeable[0]
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("read")], 300)
    t = attenuate(t, a, b.pub, [])
    attacker = KeyPair.generate()
    forged_link = Link(prev=t.leaf.link_id(), dgr=bad, dge=attacker.pub,
                       cav=[], nbf=t.leaf.nbf, exp=t.leaf.exp, non=bytes(16),
                       meta={}, sig=FORGE)
    spliced = Muhuri(t.links + [forged_link])
    with pytest.raises(VerifyError):
        verify_chain(spliced, root.pub)


# REPLAY-2: a forged PoP must not burn an honest outstanding nonce.
def test_forged_pop_does_not_burn_honest_nonce():
    root, b, t = _chain()
    store = NonceStore()
    req = {"op": "read", "resource": "/x/y", "args": {}}
    n = store.issue()                       # server issues the honest client a nonce
    forged = {"ts": 0, "server_nonce": n, "audience": b"", "sig": bytes(64)}
    with pytest.raises(VerifyError, match="proof-of-possession"):
        authorize(t, root.pub, req, forged, expected_nonce=n, nonce_store=store)
    # The honest holder's real request for the same nonce must still succeed.
    assert authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                     nonce_store=store).authorized


# REPLAY-3: the replay gate requires a real NonceStore, not a consume-shaped object.
def test_consume_shaped_object_is_rejected():
    root, b, t = _chain()
    req = {"op": "read", "resource": "/x/y", "args": {}}
    n = os.urandom(16)
    pop = prove(t, b, req, n)

    class FakeStore:
        def consume(self, scope, nonce):
            return True
    with pytest.raises(VerifyError, match="NonceStore"):
        authorize(t, root.pub, req, pop, expected_nonce=n, nonce_store=FakeStore())


# FAILCLOSED-1/2/3: malformed caveat/approval/request fail closed as VerifyError.
@pytest.mark.parametrize("caveat", [
    42, "x", {"t": "max_amount"}, {"t": "op_in"}, {"t": "resource_prefix"},
    {"t": "arg_in", "field": "x"},
])
def test_malformed_signed_caveat_fails_closed(caveat):
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("transfer"), caveat], 300)
    t = attenuate(t, a, b.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 1}}
    n = os.urandom(16)
    with pytest.raises(VerifyError):     # never a raw KeyError/AttributeError
        authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                  nonce_store=NO_REPLAY_PROTECTION)


def test_nondict_request_args_fails_closed():
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("transfer"), cav.max_amount(100)], 300)
    t = attenuate(t, a, b.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": 5}     # args is not a map
    n = os.urandom(16)
    with pytest.raises(VerifyError):
        authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                  nonce_store=NO_REPLAY_PROTECTION)


@pytest.mark.parametrize("exp", [1 << 64, 10 ** 30, "abc", -5, b"x"])
def test_malformed_approval_exp_fails_closed(exp):
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    approver = KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("transfer"),
                           cav.requires_approval(approver.pub, "treasury")], 300)
    t = attenuate(t, a, b.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 1}}
    n = os.urandom(16)
    bad_approval = {"approver": approver.pub, "nonce": os.urandom(16),
                    "exp": exp, "sig": bytes(64)}
    with pytest.raises(VerifyError):     # OverflowError/ValueError must not escape
        authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                  approvals=[bad_approval], nonce_store=NO_REPLAY_PROTECTION)


# FRESH-2: oversized mhr1_ string is rejected before the base64 buffer is built.
def test_from_string_rejects_oversized_input():
    from muhuri import Muhuri
    from muhuri.credential import MAX_BYTES
    from muhuri import MalformedCredential
    huge = "mhr1_" + "A" * (MAX_BYTES * 3)
    with pytest.raises(MalformedCredential, match="too large"):
        Muhuri.from_string(huge)


# ---- Round 3 regressions --------------------------------------------------

# FRESH-1: a malformed PoP must fail closed as VerifyError, not crash.
@pytest.mark.parametrize("make_pop", [
    lambda n: None,
    lambda n: [1, 2, 3],
    lambda n: "not-a-dict",
    lambda n: {"server_nonce": n, "audience": b"", "ts": [], "sig": b""},
    lambda n: {"server_nonce": n, "audience": b"", "ts": "soon", "sig": b""},
])
def test_malformed_pop_fails_closed(make_pop):
    root, b, t = _chain()
    req = {"op": "read", "resource": "/x/y", "args": {}}
    n = os.urandom(16)
    with pytest.raises(VerifyError):     # never AttributeError/TypeError
        authorize(t, root.pub, req, make_pop(n), expected_nonce=n,
                  nonce_store=NO_REPLAY_PROTECTION)


# FRESH-4: an approval for one gate must not discharge a different same-approver gate.
def test_approval_label_is_bound_to_the_gate():
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    approver = KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("delete"),
                           cav.requires_approval(approver.pub, "spend"),
                           cav.requires_approval(approver.pub, "delete")], 300)
    t = attenuate(t, a, b.pub, [])
    req = {"op": "delete", "resource": "/x", "args": {}}
    spend = cav.make_approval(approver, t.muhuri_id(), req, "spend")
    # One "spend" approval cannot also clear the "delete" gate.
    n = os.urandom(16)
    with pytest.raises(VerifyError, match="delete"):
        authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                  approvals=[spend], nonce_store=NO_REPLAY_PROTECTION)
    # Two correctly-labelled approvals clear both gates.
    delete = cav.make_approval(approver, t.muhuri_id(), req, "delete")
    n2 = os.urandom(16)
    assert authorize(t, root.pub, req, prove(t, b, req, n2), expected_nonce=n2,
                     approvals=[spend, delete], nonce_store=NO_REPLAY_PROTECTION).authorized


# FRESH-3: the wire version is enforced (not dead code).
def test_unsupported_wire_version_rejected():
    from muhuri import Muhuri
    from muhuri.credential import Link, ZERO32
    root, a = KeyPair.generate(), KeyPair.generate()
    link = Link(prev=ZERO32, dgr=root.pub, dge=a.pub, cav=[cav.op_in("read")],
                nbf=0, exp=1 << 40, non=bytes(16), meta={}, v=2)   # future version
    link.sig = root.sign(link.signing_msg())                      # validly signed
    with pytest.raises(VerifyError, match="version"):
        verify_chain(Muhuri([link]), root.pub)


# ---- Round 4 regressions --------------------------------------------------

# Non-iterable `approvals` must fail closed, not crash with TypeError.
@pytest.mark.parametrize("approvals", [5, "x", 3.14])
def test_noniterable_approvals_fails_closed(approvals):
    root, b, t = _chain()
    store = NonceStore()
    req = {"op": "read", "resource": "/x/y", "args": {}}
    n = store.issue()
    with pytest.raises(VerifyError):     # never a raw TypeError
        authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                  approvals=approvals, nonce_store=store)


# FRESH-B: an unmatched / unverified approval in the list must NOT have its nonce burned.
def test_unmatched_approval_nonce_is_not_consumed():
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    approver = KeyPair.generate()
    t = mint(root, a.pub, [cav.op_in("transfer"),
                           cav.requires_approval(approver.pub, "treasury")], 300)
    t = attenuate(t, a, b.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 1}}
    real = cav.make_approval(approver, t.muhuri_id(), req, "treasury")
    # An attacker-supplied junk approval that matches no gate, reusing a nonce the
    # honest flow will later present for a different purpose.
    victim_nonce = os.urandom(16)
    junk = {"approver": os.urandom(32), "nonce": victim_nonce, "exp": 1 << 40, "sig": bytes(64)}
    store = NonceStore()
    n = store.issue()
    assert authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                     approvals=[real, junk], nonce_store=store).authorized
    # The junk approval's nonce was never bound to a caveat, so it was not burned:
    # it can still be consumed for the approval scope.
    assert store.consume("approval", victim_nonce) is True
    # The real approval's nonce WAS consumed (single-use).
    assert store.consume("approval", real["nonce"]) is False


# APPROVAL-1: two identical requires_approval gates are satisfied by one approval
# (g AND g == g), and that approval's nonce is consumed exactly once.
def test_duplicate_identical_approval_gates_authorize_with_one_approval():
    root, a, b = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    approver = KeyPair.generate()
    # Parent and child independently require the same approver+label (redundant).
    t = mint(root, a.pub, [cav.op_in("transfer"),
                           cav.requires_approval(approver.pub, "treasury")], 300)
    t = attenuate(t, a, b.pub, [cav.requires_approval(approver.pub, "treasury")])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 1}}
    approval = cav.make_approval(approver, t.muhuri_id(), req, "treasury")
    store = NonceStore()
    n = store.issue()
    assert authorize(t, root.pub, req, prove(t, b, req, n), expected_nonce=n,
                     approvals=[approval], nonce_store=store).authorized
    # The shared nonce was consumed exactly once.
    assert store.consume("approval", approval["nonce"]) is False
