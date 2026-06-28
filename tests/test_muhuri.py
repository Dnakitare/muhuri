"""
Security properties of Muhuri, as executable tests.

Scenario backbone: a human principal (root) authorizes an orchestrator agent A,
which sub-delegates to a worker agent B, which talks to a payments resource
server. Money should only move within the scope the human actually granted,
proven cryptographically at every hop.
"""
import copy
import os

import pytest

from muhuri import KeyPair, mint, attenuate, Muhuri, authorize, verify_chain, VerifyError
from muhuri import caveats as cav
from muhuri.pop import prove
from muhuri.revocation import RevocationSet


# ---- fixtures: principals and agents -------------------------------------

def fresh_world():
    root = KeyPair.generate()        # the accountable human
    A = KeyPair.generate()           # orchestrator
    B = KeyPair.generate()           # worker (final holder)
    server_nonce = os.urandom(16)    # challenge the resource server issues
    return root, A, B, server_nonce


def build_chain(root, A, B):
    # Root grants A: transfers under /accounts/alice/, up to $1000.
    t = mint(root, A.pub,
             [cav.op_in("transfer", "read"),
              cav.resource_prefix("/accounts/alice/"),
              cav.max_amount(1000)],
             ttl_seconds=300)
    # A narrows to B: only up to $50 (can only shrink).
    t = attenuate(t, A, B.pub, [cav.max_amount(50)])
    return t


# ---- 1. happy path -------------------------------------------------------

def test_happy_path_authorizes():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    req = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 40}}
    pop = prove(t, B, req, nonce)
    dec = authorize(t, root.pub, req, pop, expected_nonce=nonce)
    assert dec.authorized
    assert dec.depth == 2
    assert dec.root_pub == root.pub


# ---- 2. attenuation can only narrow --------------------------------------

def test_attenuation_narrows_amount():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)               # B capped at $50 by A's hop
    req = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 75}}
    pop = prove(t, B, req, nonce)
    with pytest.raises(VerifyError, match="exceeds limit 50"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce)


def test_child_cannot_widen_parent_scope():
    # Even if a malicious A tries to "grant" B a higher limit, the verifier ANDs
    # all caveats, so the parent's $1000 and child's attempt to allow $5000 both
    # apply; the binding limit is whatever is strictest across the chain.
    root, A, B, nonce = fresh_world()
    t = mint(root, A.pub, [cav.max_amount(1000), cav.op_in("transfer")], ttl_seconds=300)
    t = attenuate(t, A, B.pub, [cav.max_amount(5000)])  # tries to widen
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 2000}}
    pop = prove(t, B, req, nonce)
    with pytest.raises(VerifyError, match="exceeds limit 1000"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce)


# ---- 3. delegation-chain splicing is rejected ----------------------------

def test_splice_attack_rejected():
    """
    Two separate credentials exist. An attacker controlling an intermediary
    tries to graft a high-authority link from chain X onto chain Y to escalate.
    Both bindings (dgr==parent.dge and prev==parent.id) break the graft.
    """
    root, A, B, nonce = fresh_world()
    # Chain Y: root -> A -> B, tightly scoped ($50).
    y = build_chain(root, A, B)

    # Chain X: a DIFFERENT root grants A a fat $1,000,000 link.
    evil_root = KeyPair.generate()
    x = mint(evil_root, A.pub, [cav.op_in("transfer"), cav.max_amount(1_000_000)], 300)

    # Splice: replace Y's leaf with X's fat link.
    spliced = Muhuri(links=[y.links[0], x.links[0]])
    with pytest.raises(VerifyError, match="splice|signature|delegator"):
        verify_chain(spliced, root.pub)


def test_splice_grafting_foreign_leaf_rejected():
    root, A, B, nonce = fresh_world()
    y = build_chain(root, A, B)
    # build an unrelated chain root2 -> A2 -> C and try to append C's leaf to y
    root2 = KeyPair.generate(); A2 = KeyPair.generate(); C = KeyPair.generate()
    other = mint(root2, A2.pub, [cav.op_in("transfer")], 300)
    other = attenuate(other, A2, C.pub, [])
    frankenstein = Muhuri(links=[y.links[0], y.links[1], other.links[1]])
    with pytest.raises(VerifyError, match="splice|delegator|prev"):
        verify_chain(frankenstein, root.pub)


# ---- 4. scope escalation / confused deputy (the Grok class) --------------

def test_out_of_scope_operation_rejected():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    # B was scoped to alice's accounts; a prompt-injected instruction tries bob's.
    req = {"op": "transfer", "resource": "/accounts/bob/checking", "args": {"amount": 10}}
    pop = prove(t, B, req, nonce)
    with pytest.raises(VerifyError, match="not under"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce)


def test_out_of_scope_method_rejected():
    root, A, B, nonce = fresh_world()
    t = mint(root, A.pub, [cav.op_in("read")], 300)
    t = attenuate(t, A, B.pub, [])
    req = {"op": "delete", "resource": "/x", "args": {}}
    pop = prove(t, B, req, nonce)
    with pytest.raises(VerifyError, match="not in"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce)


# ---- 5. tamper detection -------------------------------------------------

def test_caveat_tamper_rejected():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    # Attacker rewrites B's limit from 50 to 99999 in the wire bytes.
    tampered = copy.deepcopy(t)
    for c in tampered.links[1].cav:
        if c["t"] == "max_amount":
            c["limit"] = 99999
    req = {"op": "transfer", "resource": "/accounts/alice/x", "args": {"amount": 9000}}
    pop = prove(tampered, B, req, nonce)
    with pytest.raises(VerifyError, match="signature"):
        authorize(tampered, root.pub, req, pop, expected_nonce=nonce)


# ---- 6. stolen credential without the key (bearer-theft class) -----------

def test_stolen_credential_without_key_is_useless():
    """
    Attacker exfiltrates the full credential bytes (Salesloft/Vercel class) but
    not B's private key. They cannot produce a valid PoP.
    """
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    stolen = Muhuri.from_string(t.to_string())  # full credential on the wire

    attacker = KeyPair.generate()
    req = {"op": "transfer", "resource": "/accounts/alice/x", "args": {"amount": 10}}
    # Attacker can only sign with their own key; PoP must be under B's key.
    forged_pop = {"ts": __import__("muhuri").now(), "server_nonce": nonce,
                  "sig": attacker.sign(b"whatever")}
    with pytest.raises(VerifyError, match="proof-of-possession"):
        authorize(stolen, root.pub, req, forged_pop, expected_nonce=nonce)


def test_pop_replay_with_old_nonce_rejected():
    root, A, B, _ = fresh_world()
    t = build_chain(root, A, B)
    req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    old_nonce = os.urandom(16)
    pop = prove(t, B, req, old_nonce)            # captured from an earlier session
    new_nonce = os.urandom(16)                   # server issues a fresh one
    with pytest.raises(VerifyError, match="nonce mismatch"):
        authorize(t, root.pub, req, pop, expected_nonce=new_nonce)


def test_pop_bound_to_request():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    signed_req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    pop = prove(t, B, signed_req, nonce)
    other_req = {"op": "transfer", "resource": "/accounts/alice/x", "args": {"amount": 50}}
    with pytest.raises(VerifyError, match="proof-of-possession"):
        authorize(t, root.pub, other_req, pop, expected_nonce=nonce)


# ---- 7. lifetime ---------------------------------------------------------

def test_expired_credential_rejected():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    pop = prove(t, B, req, nonce, ts=t.leaf.exp + 1000)
    with pytest.raises(VerifyError, match="expired"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce, at=t.leaf.exp + 1000)


# ---- 8. revocation at any granularity ------------------------------------

def test_revoke_root_kills_whole_tree():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    rev = RevocationSet([t.links[0].link_id()])   # revoke the root delegation
    req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    pop = prove(t, B, req, nonce)
    with pytest.raises(VerifyError, match="revoked"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce, revoker=rev)


def test_revoke_branch_only():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    rev = RevocationSet([t.links[1].link_id()])   # revoke just B's sub-delegation
    req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    pop = prove(t, B, req, nonce)
    with pytest.raises(VerifyError, match="revoked"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce, revoker=rev)


# ---- 9. human-in-the-loop third-party caveat -----------------------------

def test_requires_approval_enforced_for_high_value():
    root, A, B, nonce = fresh_world()
    human = KeyPair.generate()                    # the approver (e.g., a person)
    t = mint(root, A.pub,
             [cav.op_in("transfer"),
              cav.requires_approval(human.pub, label="treasury-approval")],
             ttl_seconds=300)
    t = attenuate(t, A, B.pub, [])
    req = {"op": "transfer", "resource": "/accounts/alice/x", "args": {"amount": 500}}
    pop = prove(t, B, req, nonce)

    # Without approval: rejected.
    with pytest.raises(VerifyError, match="treasury-approval"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce)

    # With a fresh approval bound to THIS request: allowed.
    approval = cav.make_approval(human, t.muhuri_id(), req)
    dec = authorize(t, root.pub, req, pop, expected_nonce=nonce, approvals=[approval])
    assert dec.authorized

    # Approval cannot be replayed onto a different request.
    other = {"op": "transfer", "resource": "/accounts/alice/x", "args": {"amount": 9000}}
    pop2 = prove(t, B, other, nonce)
    with pytest.raises(VerifyError, match="treasury-approval"):
        authorize(t, root.pub, other, pop2, expected_nonce=nonce, approvals=[approval])


# ---- 10. wrong trust anchor ----------------------------------------------

def test_wrong_root_anchor_rejected():
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    not_the_root = KeyPair.generate()
    with pytest.raises(VerifyError, match="anchored"):
        verify_chain(t, not_the_root.pub)


# ---- 11. unknown caveat fails closed -------------------------------------

def test_unknown_caveat_fails_closed():
    root, A, B, nonce = fresh_world()
    t = mint(root, A.pub, [{"t": "from_the_future", "x": 1}], 300)
    req = {"op": "read", "resource": "/x", "args": {}}
    pop = prove(t, A, req, nonce)
    with pytest.raises(VerifyError, match="unknown caveat"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce)


# ---- 12. compactness: linear, not quadratic ------------------------------

def test_size_is_linear_in_depth():
    root = KeyPair.generate()
    holder = root
    t = mint(root, KeyPair.generate().pub, [cav.op_in("read")], 300)
    sizes = []
    prev_holder_pub = t.leaf.dge
    # rebuild a deep chain tracking keys
    keys = [root]
    t = mint(root, (k1 := KeyPair.generate()).pub, [cav.op_in("read")], 300)
    keys.append(k1)
    for _ in range(8):
        nxt = KeyPair.generate()
        t = attenuate(t, keys[-1], nxt.pub, [cav.op_in("read")])
        keys.append(nxt)
        sizes.append(t.size_report()["bytes"])
    # per-hop growth should be roughly constant (linear overall)
    deltas = [b - a for a, b in zip(sizes, sizes[1:])]
    assert max(deltas) - min(deltas) < 40, f"non-linear growth: {deltas}"


# =====================================================================
# Regression tests for adversarial-review findings R1-R7
# =====================================================================
from muhuri import NonceStore, parse, MalformedCredential
from muhuri.verify import verify_chain as _vc


def test_R1_approval_single_use_with_store():
    root, A, B, _ = fresh_world()
    human = KeyPair.generate()
    store = NonceStore()
    t = mint(root, A.pub, [cav.op_in("transfer"),
                           cav.requires_approval(human.pub, "treasury")], 300)
    t = attenuate(t, A, B.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 500}}
    approval = cav.make_approval(human, t.muhuri_id(), req)

    n1 = store.issue()
    dec = authorize(t, root.pub, req, prove(t, B, req, n1), expected_nonce=n1,
                    approvals=[approval], nonce_store=store)
    assert dec.authorized
    # Same approval, fresh PoP nonce -> must be rejected (single-use).
    n2 = store.issue()
    with pytest.raises(VerifyError, match="approval nonce already used"):
        authorize(t, root.pub, req, prove(t, B, req, n2), expected_nonce=n2,
                  approvals=[approval], nonce_store=store)


def test_R1_approval_expires():
    root, A, B, nonce = fresh_world()
    human = KeyPair.generate()
    t = mint(root, A.pub, [cav.op_in("transfer"),
                           cav.requires_approval(human.pub, "treasury")], 600)
    t = attenuate(t, A, B.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 500}}
    approval = cav.make_approval(human, t.muhuri_id(), req, ttl=120)
    # 200s later the approval has expired even though the credential is valid.
    future = approval["exp"] + 80
    with pytest.raises(VerifyError, match="unexpired"):
        authorize(t, root.pub, req, prove(t, B, req, nonce, ts=future),
                  expected_nonce=nonce, approvals=[approval], at=future)


def test_R2_pop_nonce_single_use():
    root, A, B, _ = fresh_world()
    t = mint(root, A.pub, [cav.op_in("read"), cav.resource_prefix("/accounts/alice/")], 300)
    t = attenuate(t, A, B.pub, [])
    store = NonceStore()
    req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    n = store.issue()
    pop = prove(t, B, req, n)
    assert authorize(t, root.pub, req, pop, expected_nonce=n, nonce_store=store).authorized
    with pytest.raises(VerifyError, match="nonce already used"):
        authorize(t, root.pub, req, pop, expected_nonce=n, nonce_store=store)


def test_R3_self_anchored_forgery_rejected_with_real_root():
    # A forged chain rooted in an attacker key must fail against the REAL root.
    root, A, B, nonce = fresh_world()
    evil = KeyPair.generate()
    forged = mint(evil, A.pub, [cav.op_in("transfer"), cav.max_amount(10**9)], 300)
    forged = attenuate(forged, A, B.pub, [])
    req = {"op": "transfer", "resource": "/x", "args": {"amount": 10**6}}
    with pytest.raises(VerifyError, match="not anchored to a trusted"):
        authorize(forged, root.pub, req, prove(forged, B, req, nonce), expected_nonce=nonce)


def test_R3_trusted_roots_set():
    # Multiple acceptable roots; the credential's root must be one of them.
    root, A, B, nonce = fresh_world()
    other_root = KeyPair.generate()
    t = mint(root, A.pub, [cav.op_in("read"), cav.resource_prefix("/accounts/alice/")], 300)
    t = attenuate(t, A, B.pub, [])
    req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    dec = authorize(t, {other_root.pub, root.pub}, req, prove(t, B, req, nonce),
                    expected_nonce=nonce)
    assert dec.authorized
    with pytest.raises(VerifyError, match="not anchored"):
        authorize(t, {other_root.pub}, req, prove(t, B, req, nonce), expected_nonce=nonce)


def test_R4_depth_cap():
    root = KeyPair.generate()
    keys = [root]
    t = mint(root, (k := KeyPair.generate()).pub, [cav.op_in("read")], 300)
    keys.append(k)
    for _ in range(20):
        nxt = KeyPair.generate()
        t = attenuate(t, keys[-1], nxt.pub, [])
        keys.append(nxt)
    with pytest.raises(VerifyError, match="too deep"):
        _vc(t, root.pub, max_depth=8)


def test_R5_malformed_input_fails_closed():
    for bad in [b"\xff\xff not cbor", b"", "mhr1_!!!notbase64", "hello"]:
        with pytest.raises(VerifyError, match="malformed"):
            parse(bad)
    # oversized
    with pytest.raises(VerifyError, match="malformed"):
        parse(b"\x80" + b"\x00" * (70 * 1024))


def test_R6_truncation_by_leaf_cannot_escalate():
    # B is capped at $50 by its own link. B tries to present only the root link
    # (which grants $1000 to A) and act. It cannot: PoP at the prefix requires
    # A's key, which B does not hold.
    root, A, B, nonce = fresh_world()
    t = build_chain(root, A, B)
    prefix = Muhuri(links=[t.links[0]])      # leaf delegate is now A
    req = {"op": "transfer", "resource": "/accounts/alice/x", "args": {"amount": 900}}
    # B forges a PoP with its own key against the prefix (whose holder is A):
    forged = {"ts": __import__("muhuri").now(), "server_nonce": nonce,
              "audience": b"", "sig": B.sign(b"x")}
    with pytest.raises(VerifyError, match="proof-of-possession"):
        authorize(prefix, root.pub, req, forged, expected_nonce=nonce)


def test_R7_audience_binding_blocks_cross_server_relay():
    root, A, B, nonce = fresh_world()
    t = mint(root, A.pub, [cav.op_in("read"), cav.resource_prefix("/accounts/alice/")], 300)
    t = attenuate(t, A, B.pub, [])
    req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    # PoP minted for server "payments.internal"
    pop = prove(t, B, req, nonce, audience=b"payments.internal")
    # Relayed to a different server identity -> rejected.
    with pytest.raises(VerifyError, match="audience mismatch"):
        authorize(t, root.pub, req, pop, expected_nonce=nonce, audience=b"reporting.internal")
    # Correct audience -> ok.
    assert authorize(t, root.pub, req, pop, expected_nonce=nonce,
                     audience=b"payments.internal").authorized
