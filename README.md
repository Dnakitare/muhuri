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
pip install cryptography cbor2 pytest
python -m pytest tests/ -q     # 18 security tests
python demo.py                 # narrated end-to-end walkthrough
```

## Files

- `muhuri/` — the library (~600 lines): `credential.py` (mint/attenuate),
  `verify.py` (offline decision engine), `caveats.py`, `pop.py`, `revocation.py`,
  `keys.py`, `canonical.py`.
- `tests/test_muhuri.py` — each test encodes a specific attack and shows it blocked.
- `SPEC.md` — wire format, verification algorithm, threat model, prior-art map.

## Why this is the lucrative wedge

Agent identity/NHI was the largest category at RSA 2026 (41 companies), and the
delegation-chain piece is the part everyone names as unsolved and nobody has
shipped as a clean primitive. It is pre-standardization (active IETF draft +
arXiv papers, March–April 2026) — the window to define the reference is open
now. The credential format is the chokepoint the entire control plane routes
through: brokers mint it, audit buses key on it, every resource server verifies
it. Plays available from this core: (1) open-source reference + standards track
to own the format, (2) the enforcement/verifier SDK and managed broker as the
commercial layer (the Mlinzi integration), (3) a native (Rust) verifier as
the drop-in for high-throughput gateways.

Status: working reference, not yet audited. Use Ed25519/SHA-256 from a vetted
library (this uses `cryptography`); get an independent review before production.
