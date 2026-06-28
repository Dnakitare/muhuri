"""
Muhuri end-to-end demo.

Walks a payments scenario through real 2026 attack classes and shows each one
defended. Run:  python demo.py
"""
from muhuri import KeyPair, mint, attenuate, Muhuri, authorize, VerifyError, NonceStore
from muhuri import caveats as cav
from muhuri.pop import prove
from muhuri.revocation import RevocationSet


def line(c="-"):
    print(c * 70)


def ok(s):    print(f"  \033[92mPASS\033[0m  {s}")
def block(s): print(f"  \033[93mBLOCKED\033[0m  {s}")


def main():
    line("=")
    print("MUHURI — splice-proof delegation credentials for agent chains")
    line("=")

    # ---- principals ----
    human = KeyPair.generate()       # the accountable human (root of trust)
    orchestrator = KeyPair.generate()
    worker = KeyPair.generate()      # the leaf agent that actually calls the API

    # The resource server (a payments API) trusts exactly one thing: `human.pub`.
    trust_anchor = human.pub

    print("\nPrincipals:")
    print(f"  human (root) ......... {human.pub.hex()[:16]}…")
    print(f"  orchestrator agent ... {orchestrator.pub.hex()[:16]}…")
    print(f"  worker agent (leaf) .. {worker.pub.hex()[:16]}…")

    # ---- delegation ----
    line()
    print("Delegation chain (each hop only narrows authority):\n")
    t = mint(human, orchestrator.pub,
             [cav.op_in("transfer", "read"),
              cav.resource_prefix("/accounts/alice/"),
              cav.max_amount(1000)],
             ttl_seconds=300,
             meta={"agent": "orchestrator", "model": "opus-4.8"})
    print("  human -> orchestrator :  transfer|read on /accounts/alice/, <= $1000")

    t = attenuate(t, orchestrator, worker.pub,
                  [cav.max_amount(50)],
                  meta={"agent": "worker", "model": "haiku-4.5"})
    print("  orchestrator -> worker:  + tighten to <= $50")

    rep = t.size_report()
    print(f"\n  whole credential: {rep['hops']} hops, {rep['bytes']} bytes, verifiable offline")
    print(f"  wire form: {t.to_string()[:54]}…")

    # The resource server keeps one single-use nonce store and issues a fresh
    # challenge per request. Passing it to authorize() turns on R1/R2 replay
    # protection; without a store authorize() refuses to run (no silent insecure
    # path). [AUDIT AUTHZ-1]
    store = NonceStore()

    # ============================================================
    line("=")
    print("LEGITIMATE REQUEST")
    line("=")
    req = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 40}}
    nonce = store.issue()
    pop = prove(t, worker, req, nonce)
    dec = authorize(t, trust_anchor, req, pop, expected_nonce=nonce, nonce_store=store)
    ok(f"$40 transfer on alice's account, authorized={dec.authorized} (depth {dec.depth})")

    print("  Now replay the exact same request + proof a second time:")
    try:
        authorize(t, trust_anchor, req, pop, expected_nonce=nonce, nonce_store=store)
    except VerifyError as e:
        block(f"single-use nonce already spent: {e}")

    # ============================================================
    line("=")
    print("ATTACK 1 — scope escalation via prompt injection  (the xAI Grok $200k class)")
    line("=")
    print("  A poisoned instruction tells the worker to move $40 to BOB instead.")
    evil = {"op": "transfer", "resource": "/accounts/bob/wallet", "args": {"amount": 40}}
    nonce = store.issue()
    pop = prove(t, worker, evil, nonce)
    try:
        authorize(t, trust_anchor, evil, pop, expected_nonce=nonce, nonce_store=store)
    except VerifyError as e:
        block(f"resource outside granted scope: {e}")

    print("  Same injection, but trying $900 (within orchestrator's $1000, over worker's $50):")
    evil2 = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 900}}
    nonce = store.issue()
    pop = prove(t, worker, evil2, nonce)
    try:
        authorize(t, trust_anchor, evil2, pop, expected_nonce=nonce, nonce_store=store)
    except VerifyError as e:
        block(f"exceeds the narrowed limit: {e}")

    # ============================================================
    line("=")
    print("ATTACK 2 — delegation-chain splicing  (the IETF RFC 8693 weakness, Feb 2026)")
    line("=")
    print("  Attacker grafts a fat $1,000,000 link (from another root) onto our chain.")
    evil_root = KeyPair.generate()
    fat = mint(evil_root, orchestrator.pub, [cav.op_in("transfer"), cav.max_amount(10**6)], 300)
    spliced = Muhuri(links=[t.links[0], fat.links[0]])
    sreq = {"op": "transfer", "resource": "/x", "args": {"amount": 500000}}
    nonce = store.issue()
    try:
        authorize(spliced, trust_anchor, sreq,
                  prove(spliced, orchestrator, sreq, nonce),
                  expected_nonce=nonce, nonce_store=store)
    except VerifyError as e:
        block(f"graft fails the two-halves binding: {e}")

    # ============================================================
    line("=")
    print("ATTACK 3 — stolen credential  (the Salesloft Drift bearer-token class, 700+ orgs)")
    line("=")
    print("  Attacker exfiltrates the ENTIRE credential bytes but not the worker's key.")
    stolen = Muhuri.from_string(t.to_string())
    thief = KeyPair.generate()
    req = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 40}}
    nonce = store.issue()
    forged_pop = {"ts": __import__("muhuri").now(), "server_nonce": nonce,
                  "sig": thief.sign(b"x")}
    try:
        authorize(stolen, trust_anchor, req, forged_pop, expected_nonce=nonce, nonce_store=store)
    except VerifyError as e:
        block(f"no proof-of-possession of the leaf key: {e}")

    # ============================================================
    line("=")
    print("HUMAN-IN-THE-LOOP — high-value action gated by a third-party caveat")
    line("=")
    treasurer = KeyPair.generate()
    th = mint(human, orchestrator.pub,
              [cav.op_in("transfer"), cav.requires_approval(treasurer.pub, "treasury-approval")], 300)
    th = attenuate(th, orchestrator, worker.pub, [])
    big = {"op": "transfer", "resource": "/accounts/alice/x", "args": {"amount": 500}}
    nonce = store.issue()
    try:
        authorize(th, trust_anchor, big, prove(th, worker, big, nonce),
                  expected_nonce=nonce, nonce_store=store)
    except VerifyError as e:
        block(f"high-value transfer without sign-off: {e}")
    approval = cav.make_approval(treasurer, th.muhuri_id(), big, "treasury-approval")
    nonce = store.issue()
    dec = authorize(th, trust_anchor, big, prove(th, worker, big, nonce),
                    expected_nonce=nonce, approvals=[approval], nonce_store=store)
    ok(f"same transfer WITH a fresh treasury signature bound to it: authorized={dec.authorized}")

    # ============================================================
    line("=")
    print("REVOCATION — pull one sub-delegation without touching the rest")
    line("=")
    rev = RevocationSet([t.links[1].link_id()])
    req = {"op": "read", "resource": "/accounts/alice/x", "args": {}}
    nonce = store.issue()
    pop = prove(t, worker, req, nonce)
    try:
        authorize(t, trust_anchor, req, pop, expected_nonce=nonce, nonce_store=store, revoker=rev)
    except VerifyError as e:
        block(f"worker's branch revoked: {e}")

    line("=")
    print("All attack classes defended. Verification was 100% offline.")
    line("=")


if __name__ == "__main__":
    main()
