# Muhuri — Splice-Proof Attenuating Delegation Credentials for Agent Chains

**Version 0.2 · reference implementation · June 2026**

A Muhuri is a single, compact, offline-verifiable credential that carries an
entire AI-agent delegation chain — from an accountable human principal down to
the leaf agent that actually calls a tool — and proves, cryptographically and
without any server round-trip, *who authorized whom to do exactly what*.

*Muhuri* is Swahili for **seal** — the mark a delegator presses onto each link
to authorize the next holder. The splice-resistance mechanism is a split-token
design (as in the ancient *tessera hospitalis*, a token broken in two whose
halves had to match to prove a relationship): each delegation link is bound to
the previous one so the halves only mate on a genuine chain, which is what makes
it non-spliceable.

---

## The problem it solves

Across the 2026 literature the same gap recurs: agent A invokes agent B invokes
a tool that moves money, and no deployed protocol can cryptographically prove
the lineage back to an accountable human at hop three or four. The specific,
documented failure modes:

- **Delegation-chain splicing** — RFC 8693 token exchange does not cross-validate
  the `subject_token` and `actor_token`, so a compromised intermediary can
  present links from *different* delegation contexts and escalate. Documented by
  the IETF OAuth WG, February 2026.
- **Verifier-as-forger** — macaroons authenticate links with a shared HMAC
  secret, so anyone who can verify a token can also mint one.
- **Opaque exchange** — each RFC 8693 hop mints a fresh token from the AS with
  no self-verifiable record of the chain, and requires a reachable endpoint.
- **Token bloat** — UCAN nests a full JWT per hop, growing quadratically.
- **Bearer theft** — OAuth access tokens are bearer credentials; stealing the
  bytes is sufficient to use them (Salesloft Drift, 700+ orgs; Vercel).
- **Scope escalation via side channel** — an agent gains capability through
  content it reads and forwards an action with no scope check at the boundary
  (xAI Grok, ~$200k).

Muhuri addresses all six in one artifact.

---

## Wire format

A Muhuri is canonical-CBOR (RFC 8949 §4.2.1, sorted keys, minimal ints) array
of **sealed links**. Each link's signed body is:

| field  | type      | meaning |
|--------|-----------|---------|
| `v`    | int       | format version |
| `prev` | bytes(32) | `link_id` of the parent link, or 32 zero bytes at the root |
| `dgr`  | bytes(32) | delegator public key (Ed25519) — signs this link |
| `dge`  | bytes(32) | delegate public key — receives the authority |
| `cav`  | array     | caveats added at this hop (the scope narrowing) |
| `nbf`  | int       | not-before (unix seconds) |
| `exp`  | int       | not-after  (unix seconds) |
| `non`  | bytes(16) | uniqueness nonce |
| `meta` | map       | provenance: agent id, model, code digest, … |

Derived values:

```
signing_msg = SHA256("muhuri/sig/v1"  || canonical(body))
sig         = Ed25519_sign(dgr_private, signing_msg)
link_id     = SHA256("muhuri/link/v1" || canonical(body) || sig)
muhuri_id  = SHA256("muhuri/cred/v1" || link_id[0] || … || link_id[n])
```

Encoded as `mhr1_` + base64url. Size is **strictly linear**: 258 bytes/hop +
caveats (measured), no quadratic nesting.

---

## Verification algorithm (fully offline)

Given the chain and one trust anchor (the root principal's public key):

1. **Root anchor.** `links[0].dgr == trust_anchor`. Otherwise the chain is not
   rooted in the expected principal → reject.
2. For each link *i*, in order:
   a. **Splice binding (parent bytes).** `links[i].prev == link_id(links[i-1])`
      (root: `prev == 0`). Commits to the exact parent, sig included.
   b. **Splice binding (key continuity).** `links[i].dgr == links[i-1].dge`.
      The delegator now must be the delegate before.
   c. **Authenticity.** `Ed25519_verify(links[i].dgr, links[i].sig, signing_msg)`.
   d. **Revocation.** `link_id(links[i])` not in the revocation oracle.
3. **Window.** `max(nbf) ≤ now ≤ min(exp)` across all links (intersection).
4. **Scope.** The request must satisfy the **conjunction of every caveat across
   every hop**. Unknown caveat types fail closed.
5. **Proof of possession.** The caller must present a fresh signature over
   `SHA256("muhuri/pop/v1" || muhuri_id || canonical(request) || server_nonce
   || ts || audience)` under `links[n].dge`, within the timestamp window,
   matching the server-issued nonce. `audience` is the resource server's
   identifier (empty by default); when set, it binds the PoP to one server so a
   proof minted for server A cannot be relayed to server B (R7). The `ts` and
   `audience` are encoded as in the reference impl (`ts` big-endian 8 bytes,
   `audience` raw bytes); the Python implementation is normative for the bytes.

(a)+(b)+(c) are the three-way "matched halves" binding that defeats splicing.
(5) converts the credential from bearer to holder-of-key.

---

## Security properties

- **Rooted accountability.** Every link chains by signature back to the human
  principal that is the verifier's trust anchor. (Principal gap.)
- **Self-verifiable lineage in one artifact.** No AS, no registry, no network.
  (Provenance / Composition gaps.)
- **Monotonic attenuation by construction.** Authority is the AND of all
  caveats; a hop can only add caveats; no representable operation widens scope —
  so holder-side offline narrowing is safe even if the holder is malicious.
  (Composition / attenuation gap.)
- **Splice resistance.** A link cannot be grafted across chains; its `dgr` and
  `prev` pin it to one specific parent. (Composition gap; fixes the RFC 8693
  weakness.)
- **Public-key verification.** Verifiers can validate but never forge — unlike
  HMAC macaroons.
- **Holder-of-key, not bearer.** Stolen credential bytes are inert without the
  leaf private key, and each PoP is bound to one request and one challenge.
  (Defeats the Salesloft/Vercel theft class and replay.)
- **Per-action gating.** The concrete request is checked against scope *and*
  freshly signed by the holder, so an injected instruction cannot exceed grant.
  (Defeats the Grok scope-escalation class. This is per-action scope, not a
  trajectory mechanism: it does not reason over a *sequence* of in-scope actions.)
- **Human-in-the-loop.** A `requires_approval` third-party caveat binds a named
  approver's signature to the specific high-value action.
- **Granular revocation.** Revoke any `link_id` to kill a whole subtree or a
  single branch.

Muhuri is a complete answer to the composition/attenuation gap, and adds rooted
accountability and holder-of-key possession on top. It is deliberately *not* a
purpose or trajectory mechanism, and only partially addresses lifetime. See
`docs/standards.md` for the honest per-gap-family scorecard (YES on attenuation,
partial on lifetime, no on purpose/trajectory/principal-isolation/provenance).

---

## Threat model and honest limits

**Assumes:** Ed25519 / SHA-256 unbroken; agents protect their own private keys
(HSM / TEE / OS keystore as available); the verifier knows the correct root
public key; clocks are loosely synchronized (PoP skew default ±60s).

**Does NOT solve, by design:**

- **Instant global offline revocation.** No self-contained bearer-style
  credential can. Muhuri's answer is layered: short default lifetimes (primary
  control) plus an optional revocation oracle for the pre-expiry window. The
  `link_id` granularity and the `Accumulator` seam let production deployments
  plug in a cryptographic accumulator or short-lived signed status list.
- **A compromised leaf with its private key.** If an attacker fully owns the
  leaf agent and its key, they act as that agent — but still only within the
  attenuated scope, still bound to the human principal, still revocable, still
  audit-logged by `link_id`. Blast radius is bounded, not eliminated.
- **Semantic correctness of the model's intent.** Muhuri enforces the
  *authorization* boundary; it does not decide whether a permitted action is a
  good idea. That is the layer above.

---

## Performance (pure-Python reference)

- Credential size: 258 bytes/hop (linear).
- Full per-request `authorize` on a 3-hop credential: ~1,300/sec single-thread
  (~0.76 ms) with the public-key validation cache warm, dominated by the n+1
  Ed25519 verifies. Each *first* validation of a new key adds a pure-Python
  low-order-point check (two ~255-bit modexps, cached thereafter per key). A
  native (Rust) verifier is expected ~100× faster and is the intended production
  target.

---

## Relationship to prior art

- **Macaroons (2014):** Muhuri keeps offline attenuation but replaces the HMAC
  chain with per-hop Ed25519 so verifiers cannot forge, and adds principal
  anchoring + PoP + splice binding.
- **Biscuit:** similar public-key attenuable spirit; Muhuri adds the explicit
  cross-link splice binding, the holder-of-key PoP per request, the third-party
  human-approval caveat, and `link_id`-granular revocation.
- **UCAN:** avoids the per-hop nested-JWT quadratic blow-up; linear bytes.
- **RFC 8693 token exchange:** complementary. Muhuri is the self-verifiable
  provenance artifact that travels *with* the task and needs no reachable AS;
  it directly closes the Feb-2026 splicing weakness via the `dgr==parent.dge`
  and `prev==parent.link_id` bindings the WG proposed.
- **`draft-niyikiza-oauth-attenuating-agent-tokens-01` (2026-06-15), AIP, HDP:**
  same problem space, all pre-standardization. Muhuri is a working, tested
  reference of the splice-proof + holder-of-key + monotonic-scope combination
  that those drafts describe but that no surveyed tool fully implements.

---

## Integration

The credential is transport-agnostic: drop the `mhr1_…` string into an MCP
request header or an A2A message envelope; the resource server runs `authorize`
locally. It is the natural credential layer for a capability broker
(e.g. Mlinzi): the broker mints and attenuates Muhurie, the audit bus keys
events by `link_id`, and resource servers enforce with a ~50-line verifier.
