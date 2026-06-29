# CLAUDE.md — project context for Claude Code

## What this is

**Muhuri** is a compact, offline-verifiable cryptographic credential that carries an
entire AI-agent **delegation chain** (human principal → orchestrator → worker → tool)
and proves who authorized whom to do exactly what. It is the credential layer beneath
the broader **Mlinzi** capability-broker design.

This repo is a working **reference implementation in Python** (`muhuri/`), an audited
test suite, a CLI demo, and a self-contained interactive browser demo that runs real
signatures live. It has passed three rounds of self-administered adversarial review
(see `AUDIT.md`). It is **not** yet production-hardened or independently audited.

Current version: `0.2.0`. Reference impl language: Python 3.11+. Demo: vanilla JS + WebCrypto.

## Commands

```bash
# from repo root
pip install -e ".[test]" --break-system-packages   # install package + test deps
python -m pytest tests/ -q                  # run the suite (expect 92 passing)
python tools/gen_vectors.py --check         # cross-impl vectors are not stale
python demo.py                              # CLI narrative demo (all attacks blocked)
# open muhuri-demo.html in a browser for the interactive demo
```

## Layout

```
muhuri/                 reference implementation
  canonical.py           canonical CBOR encoding + SHA-256 helpers
  keys.py                Ed25519 keypair + verify (fails closed)
  credential.py          Link, Muhuri, mint(), attenuate(); size/depth caps
  caveats.py             constraint language + single-use, expiring approvals
  pop.py                 proof-of-possession + NonceStore (single-use) + audience
  revocation.py          revocation interfaces (honest: no instant offline revoke)
  verify.py              verify_chain(), authorize() — the full per-request gate
tests/test_muhuri.py    27 adversarial + R1–R7 regression tests
tests/test_properties.py Hypothesis fuzzing of the 3 load-bearing invariants
tests/test_vectors.py    replays tests/vectors.json + wire determinism
tests/vectors.json       13 cross-implementation (chain, request, decision) vectors
tools/gen_vectors.py     deterministic vector generator (--check in CI)
demo.py                  CLI narrative demo
muhuri-demo.html        interactive browser demo (real WebCrypto, no backend)
SPEC.md                  wire format, verification algorithm, threat model, prior art
AUDIT.md                 the adversarial review log + residual risks
docs/standards.md        map to RFC 8693 / IETF drafts / prior art + gap-family scorecard
PITCH.md                 60-second pitch script + recording shot list
NEXT_STEPS.md            prioritized roadmap (start here for new work)
.github/workflows/ci.yml CI: tests + vector-staleness + demo + JS syntax check
```

## Security invariants — DO NOT REGRESS

These are the load-bearing properties. Every change must keep them, and ideally add a
test. The suite already encodes each; run it before and after any change.

1. **Monotonic attenuation.** Hops may only ADD caveats. Authority is the AND of all
   caveats across all links. There is no representable operation that widens scope.
2. **Splice resistance.** Each link binds to its parent two ways: `link.dgr == parent.dge`
   AND `link.prev == parent.link_id()`. The signature must verify under `dgr`.
3. **Public-key per hop (Ed25519).** Verifiers cannot forge. Never introduce a symmetric
   (HMAC/macaroon-style) verification path; that reintroduces verifier-as-forger.
4. **Holder-of-key PoP.** Possessing the credential bytes is not enough; the leaf must
   sign a fresh, single-use, server-issued challenge. Stolen bytes are inert.
5. **Trusted roots are caller-supplied.** `verify_chain`/`authorize` take `trusted_roots`
   explicitly and must NEVER derive the anchor from the credential itself.
6. **Fail closed everywhere.** Unknown caveat types, malformed input, missing fields →
   reject. Never silently ignore a constraint you don't understand.
7. **Fixed cipher suite.** Ed25519 + SHA-256, no algorithm negotiation. The `v` field is
   for future migration, not runtime agility. Do not add an `alg` selector.
8. **Reject degenerate keys.** [AUDIT CRYPTO-1] `verify_sig` and `mint`/`attenuate`/
   `requires_approval` reject low-order (torsion) and non-canonical Ed25519 encodings via
   `keys.is_acceptable_key`. Raw Ed25519 verify accepts them and they admit a universal
   forgery (`R=identity, S=0`). Never call `crypto.verify` on a public key without this gate.
9. **Replay protection is required, not optional.** [AUDIT AUTHZ-1] `authorize` requires a
   `nonce_store` (or the explicit `NO_REPLAY_PROTECTION` sentinel); omitting it errors.
   Single-use nonces are consumed only AFTER the signature verifies, and only for approvals
   actually bound to a caveat. Do not reintroduce a silent off-by-default path.

## Conventions

- Canonical encoding is RFC 8949 §4.2.1 canonical CBOR. Signatures are over
  `H(DOMAIN || canonical(body))`; verification re-canonicalizes, so non-canonical wire
  bytes can never change semantics. Keep domain-separation tags distinct per message type.
- Errors fail closed as `VerifyError` (verification) or `MalformedCredential` (parsing).
- The Python impl is the source of truth for the wire format; any other implementation
  (e.g. a Rust port, or the JS in the demo) must match `SPEC.md` exactly and round-trip
  against Python test vectors.

## State of play

- Verified: 92 tests pass (27 adversarial + 6 property + 15 vector + 44 red-team regression); CLI +
  browser demos run clean; all R1–R7 findings fixed and re-probed; C1–C4 confusion
  attacks blocked. An independent multi-agent red-team (5 rounds, June 2026) then found and fixed
  3 High + several medium/low issues, including a universal forgery the prior review missed; see
  the "Independent red-team" section of `AUDIT.md`.
- Honest gaps (read `AUDIT.md` "Residual & accepted risks"): no instant global offline
  revocation; provenance honesty depends on the signer; `NonceStore` is in-memory;
  audience binding is opt-in; needs an independent professional crypto audit + a formal
  model before any production or standards use.

When starting new work, read `NEXT_STEPS.md` first.
