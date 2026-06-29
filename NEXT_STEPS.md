# NEXT_STEPS.md — Muhuri roadmap

Prioritized for a Claude Code session to pick up. Each item names the goal, where to
work, and a "done when" check. Keep the security invariants in `CLAUDE.md` intact and
run `python -m pytest tests/ -q` before and after every change.

---

## Status (updated 2026-06-28)

**Done:** P0.1 cross-impl vectors (`tests/vectors.json` + `tools/gen_vectors.py`),
P0.2 property tests (`tests/test_properties.py`), P0.3 CI (`.github/workflows/ci.yml`),
P3.10 standards note (`docs/standards.md`), P4.11–12 demo recording + demo-first README
(`docs/muhuri-demo.gif`). An independent 5-round red-team also hardened the library (see
`AUDIT.md` "Independent red-team"); `nonce_store` is now required and low-order keys are
rejected, so part of P1.5's intent (don't ship an insecure default) is already met.

**Still open / recommended next, in order:** P1.4 durable `NonceStore` backend (the
most-cited residual; in-memory today), P1.5 `authorize_request` convenience that requires
an explicit audience (audience binding is still opt-in), P1.6 revocation oracle, then the
P2 Rust/WASM and P3 middleware work. **Gate before any production trust:** an independent
professional cryptographic review (the hand-rolled Ed25519 point math in `keys.py`, the
CBOR decoder-differential, and the `h256` framing are unproven) plus a formal model of the
authorization properties. Those are external assurance, not open exploits.

---

## P0 — Make the claims independently checkable

These raise external credibility the most for the least work.

1. **Publish cross-language test vectors.**
   Emit a `vectors.json` of (chain, request, expected-decision) tuples from the Python
   impl, and assert the demo's JS and any future port reproduce them byte-for-byte.
   *Where:* new `tools/gen_vectors.py`, `tests/test_vectors.py`.
   *Done when:* JS in `muhuri-demo.html` and Python agree on every vector.

2. **Property-based tests with Hypothesis.**
   Fuzz: random chains never authorize out-of-scope requests; attenuation never widens;
   malformed bytes always raise `MalformedCredential`/`VerifyError`, never crash.
   *Where:* `tests/test_properties.py`. Add `hypothesis` to dev deps.
   *Done when:* 10k+ generated cases pass; at least one invariant has a shrinking test.

3. **CI + reproducible env.**
   GitHub Actions: install, run pytest, run `demo.py`, syntax-check the demo JS
   (`node --check` on the extracted `<script>`). Pin versions.
   *Done when:* green badge; CI fails if any invariant test fails.

## P1 — Close the honest gaps from AUDIT.md

4. **Durable NonceStore backend.**
   Replace the in-memory set with a TTL-bounded interface and a Redis adapter; nonces
   must persist for at least the credential/approval lifetime.
   *Where:* `muhuri/pop.py` (define `NonceStore` protocol), `muhuri/stores/redis_store.py`.
   *Done when:* single-use survives process restart in an integration test.

5. **Make audience binding the default in the high-level gate.**
   Today `audience=b""` (opt-in). Add an `authorize_request(...)` convenience that
   requires an explicit server identity, and document the bare `authorize` as low-level.
   *Done when:* the recommended path can't be called without an audience.

6. **Revocation oracle reference.**
   Ship a tiny signed revocation-list service + client (`link_id` granularity, short TTL,
   fail-open vs fail-closed configurable) so the "layered revocation" story is runnable,
   not just described.
   *Where:* `muhuri/revocation.py` + `examples/revocation_oracle/`.

## P2 — Performance & portability

7. **Rust core (`muhuri-rs`) with Python bindings.**
   Port verify/mint/attenuate to Rust (ed25519-dalek + a canonical-CBOR crate), expose
   via PyO3, match `SPEC.md` and the P0 vectors. Target ~100× the pure-Python ~1,260
   authorizations/sec.
   *Done when:* `muhuri-rs` passes the same `vectors.json`.

8. **WASM build of the verifier.**
   Compile the Rust verifier to WASM so the browser demo (and real JS integrators) run
   the *same* verification code as the backend, not a parallel JS reimplementation.

## P3 — Integration surface

9. **Reference resource-server middleware.**
   A ~50-line FastAPI (and Express) dependency: parse credential, issue/consume nonce,
   call `authorize`, enforce. This is the adoption story — show how little a verifier needs.
   *Where:* `examples/fastapi_gateway/`.

10. **Standards alignment note.**
    Map Muhuri's wire fields and checks to `draft-niyikiza-oauth-attenuating-agent-tokens`,
    RFC 8693 act-claims, Biscuit, and UCAN in a short `docs/standards.md`. Identify what
    would need to change to interop or contribute upstream.

## P4 — Pitch & distribution polish

11. **Record the demo** following `PITCH.md`'s shot list (screen capture is the spine).
12. **Lead the README with the demo.** Embed a GIF/screen-capture of the splice + tamper
    moments above the fold; move the prose down.
13. **One-page brief** (PDF) pairing the plain-English story with the AUDIT.md findings
    table for technical buyers.

---

### Suggested first session

Do **P0.1 → P0.2 → P0.3** in order. That gives you machine-checked, fuzzed, CI-enforced
guarantees and cross-impl vectors — the foundation everything else (especially the Rust
port) builds on. Then pick P1.4 (durable nonce store) since it's the most-cited residual
risk in the audit.

### Ground rules

- The Python wire format is canonical; ports conform to it, never the reverse.
- Never weaken a security invariant for performance or ergonomics. If a change forces a
  trade-off, document it in `AUDIT.md` and add a test that pins the chosen behavior.
- This remains a pre-audit reference implementation. Don't describe it as production-ready
  in any artifact until an independent cryptographic review and a formal model exist.
