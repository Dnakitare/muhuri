# Muhuri and the standards landscape

Where Muhuri sits relative to the OAuth/agent-delegation drafts in flight, the
attenuable-credential prior art, and the authority-drift taxonomy this work came
out of. The point is to be precise about what Muhuri is a clean answer to, what
it deliberately is not, and what would have to change to interoperate with or
contribute to the emerging standards. `SPEC.md` is the wire format; this is the
positioning.

> Draft identifiers below (IETF I-Ds, arXiv numbers) are carried over from the
> project's research notes. Re-verify each against the IETF datatracker and arXiv
> before citing any of them in a public artifact; pre-standardization drafts move
> and lapse.

## 1. What Muhuri is, in one line

A bearer-presented, offline-verifiable credential that carries a public-key
delegation chain and enforces **monotonic attenuation with verifiable lineage in
the credential itself**. Ed25519 + canonical CBOR, no authorization-server round
trip at use time.

That sentence is doing specific work: "in the credential itself" and "no AS round
trip" are the two properties that separate it from the policy-enforced-at-issuance
designs (RFC 8693 token exchange, Keycard) and put it in the macaroons / Biscuit /
UCAN family instead.

## 2. Map to RFC 8693 and the agent-token drafts

| Mechanism | RFC 8693 / draft shape | Muhuri |
|---|---|---|
| Delegation actor chain | nested `act` claims, asserted by the STS | the link chain; each hop is a separate Ed25519-signed `Link` |
| Narrowing across a hop | STS evaluates policy, mints a new token | `attenuate()` adds caveats; verifier ANDs all hops, offline |
| Who can verify | parties trusting the STS / its keys | anyone holding the root public key |
| Splice protection | none specified; cross-validation is left open (the gap the OAuth WG flagged, Feb 2026) | `dgr == parent.dge` **and** `prev == parent.link_id`, signature under `dgr` |
| Holder binding | DPoP / mTLS at the token endpoint | per-request holder-of-key PoP over a server nonce, optional audience |

Muhuri is **complementary** to RFC 8693, not a replacement. An STS can keep doing
issuance and policy; Muhuri is the self-verifiable provenance artifact that travels
*with* the task and needs no reachable AS to check. The directly relevant in-flight
draft is `draft-niyikiza-oauth-attenuating-agent-tokens` ("Attenuating
Authorization Tokens for Agentic Delegation Chains," `-01`, 2026-06-15): same
problem, pre-standardization. Muhuri is a working, tested reference of the
splice-proof + holder-of-key + monotonic-scope combination those drafts describe.
`draft-nelson-agent-delegation-receipts` ("Delegation Receipt Protocol for AI
Agent Authorization," `-10`, 2026-06-13) is the closest in spirit: its
strict-proper-subset narrowing requirement per delegation step is exactly Muhuri's
monotonic-attenuation invariant, stated as a protocol requirement rather than a
running enforcement.

## 3. Prior-art comparison

| System | Verification | Attenuation | Lineage in credential | Splice binding | PoP | Purpose binding |
|---|---|---|---|---|---|---|
| Macaroons (2014) | symmetric HMAC (verifier can forge) | caveats | yes | no | no | no |
| Biscuit | public-key + datalog | datalog caveats | yes | partial | no | no |
| UCAN | public-key, DID, nested JWT | capability narrowing | yes (quadratic bytes) | no | invocation sig | no |
| RFC 8693 / Keycard | trust the STS | policy at issuance | no (asserted) | no | DPoP/mTLS | no |
| **Muhuri** | **per-hop Ed25519** | **typed caveats, ANDed** | **yes (linear bytes)** | **yes (two-way)** | **per-request HoK** | **no** |

The deltas worth naming:

- **vs Macaroons:** Muhuri replaces the HMAC chain with per-hop Ed25519, so a
  verifier can check a chain it could never have produced. This is the single most
  important difference: HMAC macaroons make every verifier a potential forger.
- **vs Biscuit:** closest cousin (public-key, offline-attenuable). Muhuri trades
  Biscuit's datalog expressiveness for a small fixed set of typed caveats and a
  much smaller audit surface, and adds the explicit two-way splice binding, the
  per-request PoP, and the third-party human-approval caveat.
- **vs UCAN:** Muhuri stays linear in bytes (≈258/hop) instead of nesting a full
  JWT per hop, and fixes the cipher suite rather than negotiating it.

## 4. Map to the authority-drift taxonomy (the six families)

This is the honest scorecard against the authority-drift taxonomy this work came
out of: six gap-families across the dimensions of delegation (Purpose, Trajectory,
Lifetime, Principal, Provenance, Attenuation). The companion paper is unpublished;
the families are summarized inline below so this doc stands alone. It's the part
that matters most: Muhuri is a sharp answer to *one* family and is explicit about
not addressing the others.

| Family | Gap | Muhuri | Why |
|---|---|---|---|
| **F — Attenuation** | multi-hop delegation doesn't enforce monotonic narrowing with lineage | **YES** | caveats only ever ADD; verifier ANDs all hops; lineage is the signed chain; splice binding pins each hop to its exact parent. This is the rubric's *YES* shape (macaroons/UCAN), done with public keys. |
| **C — Lifetime** | authority outlives the task, not just the clock | **PARTIAL** | windows intersect down the chain and TTLs are short, but expiry is wall-clock, not task-completion. The rubric calls wall-clock-only the *wrong shape* for C. `requires_approval` is a per-action gate, not a completion signal. |
| **A — Purpose** | credential says what, never what-for | **NO** | caveats are capability/scope predicates, not purpose. Muhuri cannot tell an in-scope action taken for the wrong purpose from a right one. |
| **B — Trajectory** | each action passes; the sequence violates intent | **NO** | the gate is per-request and stateless across requests. No trajectory primitive, by design. |
| **D — Principal** | no isolation between principals sharing a process | **NO** | the D gap is *isolation*. Muhuri anchors every chain to a named principal and keys every hop, which is *attribution* (a different, already-well-served dimension); it says nothing about in-process context isolation. |
| **E — Provenance** | data/instruction origin is laundered before the auth decision | **NO** | `meta` is signed delegation-actor provenance (who delegated, with what code digest), not data-flow provenance of the content an agent reads. It addresses neither E1 (value-to-source trail) nor E2 (instruction-flow typing). |

The takeaway for any reader: Muhuri closes **F** cleanly, gives partial and honest
coverage of **C** (real lifetime controls, but wall-clock not task-completion), and
is explicitly *not* an answer to **A, B, D, or E**. It is not a purpose, trajectory,
isolation, or content-provenance mechanism, and no claim it makes should be read as
one. Those families are open across the entire surveyed field, which is the larger
research story the paper tells.

## 5. What it would take to interoperate or go upstream

Concrete, in rough order of effort:

1. **CBOR field alignment.** Reconcile Muhuri's link body (`dgr/dge/prev/cav/...`)
   with the field names in `draft-niyikiza` and the CBOR Web Token (RFC 8392)
   conventions, so a Muhuri link can be read as a profiled CWT rather than a bespoke
   structure. Lowest-friction path to "this is a profile, not a fork."
2. **Caveat registry.** The typed caveats (`op_in`, `resource_prefix`, `max_amount`,
   `arg_in`, `requires_approval`) need a registry and a fail-closed rule for unknown
   types (Muhuri already fails closed; the registry is what makes it interoperable).
3. **Audience as a first-class claim.** Align the PoP `audience` with RFC 8707
   Resource Indicators so cross-server relay protection composes with existing
   audience semantics (this is also NEXT_STEPS P1.5: make audience the default).
4. **Revocation status format.** A signed, short-TTL status list at `link_id`
   granularity that lines up with OpenID Shared Signals / CAEP, so the pre-expiry
   revocation window has a standard shape (NEXT_STEPS P1.6).
5. **Test vectors as the conformance artifact.** `tests/vectors.json` is already
   the cross-implementation contract. Publishing it alongside a draft is the cheapest
   way to make "splice-proof + holder-of-key + monotonic-scope" checkable by others
   rather than asserted.

## 6. Non-goals

Unchanged from `SPEC.md`: no instant global offline revocation, no defense against
a fully compromised leaf that also holds its key (blast radius is bounded, not
zero), and no judgment about whether a permitted action is a good idea. Muhuri
enforces the authorization boundary. Purpose, trajectory, and the semantic layer
above it are out of scope here and open in the field.
