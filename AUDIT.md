# Muhuri — Adversarial Review Log

This records the self-red-team performed on the reference implementation. Every
finding below was reproduced as an executable attack, fixed, and the fix
re-probed. The goal is to be honest about what is proven, what is mitigated, and
what only an independent professional audit can establish.

## Method

Three independent passes, each with a different lens, each attack written as
runnable code (not prose):

1. **Protocol / authorization design** — escalation, replay, downgrade.
2. **Implementation robustness** — malformed input, resource exhaustion, footguns.
3. **Cryptographic confusion** — encoding ambiguity, signature reuse, cross-context replay.

## Findings (pass 1 + 2)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| R1 | **High** | A single human approval could be replayed to authorize the *same* high-value action repeatedly (HITL double-spend). | **Fixed** — approvals now carry a unique nonce + short expiry and are single-use, enforced by the verifier's nonce store. |
| R2 | **High** | PoP nonces were not enforced single-use by the library, allowing replay of a captured PoP within the clock-skew window. | **Fixed** — `NonceStore` issues and consumes each challenge exactly once; `authorize` rejects reuse. |
| R3 | Medium | If an integrator passed the credential's *own* root as the trust anchor, verification was vacuous (trust-the-token's-issuer footgun). | **Fixed** — `authorize`/`verify_chain` take `trusted_roots` explicitly (a key or a set) and never derive it from the token; the footgun is documented loudly. |
| R4 | Medium | No depth cap: a multi-thousand-link credential forced unbounded signature verification (CPU DoS). | **Fixed** — `MAX_DEPTH` (64) and `MAX_BYTES` (64 KiB) caps; configurable per call. |
| R5 | Medium | Malformed wire bytes raised an uncaught `TypeError` instead of failing closed. | **Fixed** — strict typed parsing; all malformed input raises `VerifyError` via `parse()`. |
| R6 | — | Suspected: a narrowed leaf could *truncate* the chain to escape its own restriction. | **Not a vuln** — truncating to a prefix requires the prefix's leaf private key, which the narrowed holder does not have. Now covered by an explicit test. |
| R7 | Medium | No audience binding: a PoP for server A could in principle be relayed to server B sharing the same root and resources. | **Fixed (defense-in-depth)** — PoP optionally binds an `audience`; mismatch is rejected. Per-server single-use nonces already made live relay impractical. |
| R8 | Low | A `max_amount` caveat unconditionally requires an `amount` field, so it fails-closed on amount-less ops (e.g. `read`) sharing the credential. | **By design (safe)** — documented; recommend op-scoped caveats. Fail-closed is the correct default. |

## Confusion attacks (pass 3) — all blocked, no fix needed

| # | Attack | Why it fails |
|---|--------|--------------|
| C1 | Mutate a caveat in the wire bytes and re-encode. | Signatures are verified over the *canonical* re-encoding of the decoded body, so any semantic change invalidates the signature. |
| C2 | Lift a valid link signature onto a forged link with widened caveats. | The signature covers the full canonical body including caveats and `prev`; altering caveats breaks it. |
| C3 | Replay a valid human approval from chain X onto chain Y (same approver, same request). | Approvals bind `muhuri_id`; a different chain has a different id, so the approval does not verify. |
| C4 | Strip a caveat by self-delegating (A → A) and acting beyond the original limit. | Attenuation only ever *adds* caveats; the verifier ANDs all of them. There is no representable widening operation. |

## Residual & accepted risks (honest limits)

These are **not** solved and should be stated to any evaluator:

- **Instant global offline revocation is impossible** for any self-contained
  credential. Mitigation is layered: short default lifetimes (primary) + an
  optional revocation oracle for the pre-expiry window, at `link_id` granularity.
- **A fully compromised leaf agent that also holds its private key** acts as that
  agent — but only within the attenuated scope, still anchored to the human
  principal, still revocable, still audit-logged by `link_id`. Blast radius is
  bounded, not eliminated.
- **Provenance honesty.** `meta` (agent id, model, code digest) is signed and
  tamper-evident, but a dishonest *delegator* can assert false provenance about
  its own delegate. Provenance is only as trustworthy as the signing party.
- **Nonce-store durability.** Single-use guarantees require the store to retain
  nonces for at least the credential/approval lifetime. The in-repo `NonceStore`
  is in-memory; production needs a TTL-bounded shared cache.
- **Audience binding is opt-in** (`audience=b""` by default). Setting it is
  recommended where multiple resource servers share a root.

## What this review does NOT replace

This is a developer self-audit with executable adversarial tests (27 passing,
covering each finding). It is **not** a substitute for:

- an independent cryptographic review of the protocol,
- a formal model / machine-checked proof of the authorization properties, and
- a review of the Ed25519/CBOR library usage and side-channel surface.

Those are the gates before any production or standards-track use. The design was
deliberately kept to a fixed cipher suite (Ed25519 + SHA-256, no algorithm
negotiation) specifically to shrink that audit surface.
