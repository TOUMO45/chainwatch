# Multi-chain scope — Solana / Rust

> **Research document. No detection code was written for this, and none should be
> until the open questions below are answered.** Chainwatch today is
> Solidity/EVM only, and this file exists so that "multi-chain" is a costed
> proposal rather than a word on a slide.

Scoped 2026-08-17. Ecosystem chosen: **Solana (Rust / Anchor)** — the largest
non-EVM smart-contract ecosystem, and the only one where the tooling questions
below have real answers to research rather than a flat "nothing exists".

---

## The question that actually decides portability

Chainwatch's claim is **WHEN a security control broke, and whether that broken
version is LIVE on-chain.** That decomposes into three capabilities, and they
port very differently:

| capability | EVM today | Solana | portable? |
|---|---|---|---|
| walk history, pair commits, reconstruct per-commit build env | git + solc-select | git + cargo/Anchor toolchains | **yes, largely as-is** |
| structural diff of a security control between two commits | Slither AST/IR | see below | **partly — needs a new rule layer** |
| is the broken version the deployed one | `eth_getCode` + bytecode hash | verified builds / program hash | **yes, and arguably cleaner** |

The trajectory *machinery* is the portable part. The *rules* are not portable at
all — they are Solidity-AST-specific by construction, and every one would need
rewriting against a different language and a different security model.

---

## 1. Is there a Slither equivalent?

**Not really — nothing with Slither's maturity, IR, or data-dependency
analysis.** What exists is a younger and thinner set:

- **[L3X](https://github.com/VulnPlanet/l3x)** — AI-driven static analyzer
  covering Rust/Solana and Solidity. The AI-driven part is a problem for
  Chainwatch specifically: CHARTER rule 2 requires deterministic checks to
  decide findings, with the model confined to explaining them. An LLM-backed
  analyzer cannot sit in the decision path without inverting that.
- **[Solana Static Analyzer](https://github.com/scab24/Solana_Static_Analyzer)**
  and **[eloizer](https://github.com/Inversive-Labs/eloizer)** — detector-style
  analyzers for Solana/Anchor. Both are early-stage relative to Slither.

**The gap that matters is not detector count, it is IR.** Chainwatch does not
consume Slither's *detectors* — it uses Slither's **AST, IR and data-dependency
graph** to ask its own questions (`is_dependent`, `all_state_variables_written`,
forward-CFG reachability). A Solana equivalent would need to expose comparable
primitives over Rust/Anchor. On present evidence none does, which means the
realistic substrate is `syn`/`rust-analyzer` on the Rust AST — i.e. **building
the analysis layer, not adopting one.**

## 2. Is there a storage-layout equivalent?

**No, and the concept does not transfer.** Rule 3c compares `solc
--storage-layout` between commits because EVM proxies delegate into a shared
storage slot space, so a reordered variable silently reinterprets live state.

Solana has no delegatecall and no shared slot space. Program state lives in
**accounts**, deserialized by the program itself (Borsh/Anchor). The analogous
regression is a **change to an account struct's layout or discriminator** while
existing accounts on-chain still hold the old encoding. That is a real and
comparable bug class — but it is a different check with different evidence, not
a port of 3c.

## 3. Is there a liveness equivalent?

**Yes, and it is arguably better than the EVM one.** Solana has first-class
[verified builds](https://solana.com/docs/programs/verified-builds): the
[solana-verify](https://github.com/solana-foundation/solana-verifiable-build)
CLI deterministically rebuilds a program in Docker and compares the hash of the
resulting executable against the on-chain program, with
`solana-verify get-program-hash` exposing exactly the comparison capability 11
performs. Verification metadata — repo URL, **commit hash**, build params — is
stored on-chain in a PDA owned by the Otter Verify program.

**That last point is significant for Chainwatch specifically:** the on-chain
record already contains the *commit hash*. On EVM, mapping deployed bytecode
back to a commit is the hard part and the reason capability 11 returns UNKNOWN
so often. On Solana, for a verified program, that link is published. The
decisive gate is *easier* here, not harder.

Caveats, stated rather than glossed: verification is opt-in, so unverified
programs give nothing; the build must be reproducible; and the mechanism has
had [documented weaknesses](https://accretion.xyz/blog/verified-builds).

## 4. What would Rule 1 (access control) look like?

Solidity Rule 1 asks: did a function lose a `msg.sender`-dependent guard?

Solana has no `msg.sender`. Authorization is **account-constraint based**: a
handler asserts that a passed-in account is a signer, and that it is the
expected authority. In Anchor this is declarative:

```rust
#[derive(Accounts)]
pub struct SetAdmin<'info> {
    #[account(mut, has_one = admin)]      // <-- the control
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,             // <-- and this
}
```

**The Solana analogue of Rule 1 is therefore: a handler's account-constraint set
lost `Signer` on the authority account, or lost a `has_one`/`constraint =`
binding it to stored authority.** Structurally this is closer to Rule 10 than to
Rule 1 — it is a property of the *entry point's declared surface*, not of a
guard node inside the body. Chainwatch's Rule 10 experience (invert the matching
direction, key on the external surface) is directly relevant.

The nastier variant, and the one worth building for: the constraint moves from
the declarative `#[derive(Accounts)]` block into a hand-written `require!` in the
body, or vice versa. That is exactly the RC-RENAME1 shape — responsibility
migrating between entry points — and a naive per-field diff would report it as a
removal.

## 5. OWASP-equivalent mapping

There is no Solana equivalent of the OWASP Smart Contract Top 10 with the same
standing. The closest anchors are community vulnerability taxonomies (missing
signer check, missing ownership check, account confusion / type cosine,
arbitrary CPI, PDA seed collisions). **Chainwatch's OWASP mapping would not
carry over**, and inventing a mapping is a credibility risk, not a feature.

---

## Effort estimate — honest

**Weeks, not days. Realistically 6–10 weeks of focused work for a v1 covering
one rule and the liveness gate**, and that assumes the analysis layer is built
rather than adopted.

| workstream | estimate | notes |
|---|---|---|
| Rust/Anchor AST layer + per-commit build reconstruction | 2–3 weeks | cargo/Anchor version pinning is the solc-select problem again, and Anchor's version churn is worse |
| One rule (signer/authority constraint regression) + fixtures | 2–3 weeks | fixture set from scratch, both directions, same discipline as Rule 10 |
| Liveness via solana-verify / program hash | 1 week | genuinely the easy part |
| Account-layout regression (the 3c analogue) | 2–3 weeks | new evidence model |

Roughly **60% of Chainwatch's existing code — history walking, env
reconstruction, verdict model, agent layer, coverage accounting — is
chain-agnostic and would be reused**. The other 40% (all nine rules, the storage
extractor, the OWASP mapping) is Solidity-specific and would be rewritten.

## Recommendation

**Do not start this until the EVM side's known gaps are closed.** Rule 10 has
one real-world data point; ERC20 value-holding migrations are still missed
(RULES.md 10.7); Rule 3c cannot run on older pragmas; HIST-L1 dependency
reconstruction fails on a meaningful fraction of real commits — measured again
in the Step 5 pilots, where one target was environment-infeasible outright.
Adding a second chain multiplies that surface rather than diversifying it.

The honest framing for any submission: **Chainwatch is EVM-only, the trajectory
machinery is chain-agnostic, and Solana is a costed future project with a
clearer liveness story than EVM — not a checkbox.**

---

## Sources

- [crytic/slither](https://github.com/crytic/slither)
- [VulnPlanet/l3x](https://github.com/VulnPlanet/l3x)
- [scab24/Solana_Static_Analyzer](https://github.com/scab24/Solana_Static_Analyzer)
- [Inversive-Labs/eloizer](https://github.com/Inversive-Labs/eloizer)
- [Solana verified builds](https://solana.com/docs/programs/verified-builds)
- [solana-foundation/solana-verifiable-build](https://github.com/solana-foundation/solana-verifiable-build)
- [How to Verify a Program](https://solana.com/developers/guides/advanced/verified-builds)
- [How We Hacked Solana Verified Builds — Accretion](https://accretion.xyz/blog/verified-builds)
