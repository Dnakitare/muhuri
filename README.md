# Muhuri

**Splice-proof, offline-attenuating delegation credentials for AI-agent chains.**

One compact credential carries a whole delegation chain — human → orchestrator →
worker → tool — and proves cryptographically, with no server round-trip, *who
authorized whom to do exactly what*. It's the missing credential layer for the
problem Entrust calls "the hardest unsolved problem in agentic AI."

```python
from muhuri import KeyPair, mint, attenuate, authorize
from muhuri import caveats as cav
from muhuri.pop import prove
import os

human, orchestrator, worker = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()

# Root delegates, then the holder narrows it offline — no AS, no network:
t = mint(human, orchestrator.pub,
         [cav.op_in("transfer", "read"),
          cav.resource_prefix("/accounts/alice/"),
          cav.max_amount(1000)], ttl_seconds=300)
t = attenuate(t, orchestrator, worker.pub, [cav.max_amount(50)])  # can only narrow

# Resource server: one offline call gates the request.
nonce = os.urandom(16)                                  # server-issued challenge
req = {"op": "transfer", "resource": "/accounts/alice/checking", "args": {"amount": 40}}
pop = prove(t, worker, req, nonce)                       # holder proves key possession
dec = authorize(t, human.pub, req, pop, expected_nonce=nonce)
assert dec.authorized
```

## What it defends (see `demo.py`)

| Real 2026 incident class | Muhuri mechanism |
|---|---|
| Scope escalation via prompt injection (xAI Grok, ~$200k) | per-action scope check, AND of all hops |
| Delegation-chain splicing (IETF RFC 8693, Feb 2026) | `dgr==parent.dge` + `prev==parent.link_id` binding |
| Stolen bearer token (Salesloft Drift, 700+ orgs) | holder-of-key proof of possession per request |
| Missing human-in-the-loop on high-value actions | `requires_approval` third-party caveat |
| Withdrawn delegation | `link_id`-granular revocation |

## Run it

```bash
pip install cryptography cbor2 pytest hypothesis
python -m pytest tests/ -q     # 48 tests: attacks + properties + cross-impl vectors
python demo.py                 # narrated end-to-end walkthrough
```

## Files

- `muhuri/` — the library (~600 lines): `credential.py` (mint/attenuate),
  `verify.py` (offline decision engine), `caveats.py`, `pop.py`, `revocation.py`,
  `keys.py`, `canonical.py`.
- `tests/test_muhuri.py` — each test encodes a specific attack and shows it blocked.
- `SPEC.md` — wire format, verification algorithm, threat model, prior-art map.

## Status

Working reference implementation, not yet independently audited. The cipher
suite is fixed (Ed25519 + SHA-256) and the crypto comes from a vetted library
(`cryptography`). Get an independent cryptographic review and a formal model of
the authorization properties before any production or standards-track use. See
`AUDIT.md` for the self-review and the honest residual risks, and `docs/standards.md`
for how Muhuri maps to the in-flight IETF drafts and prior art.
