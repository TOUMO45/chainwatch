# Chainwatch — submission notes

Claims made about this project in public material must match what was actually
measured. This file records the one place where the project's own success
criteria and the real world did not line up, and what was done about it.

---

## CHARTER criterion #6 — a scope finding, not a satisfied checkbox

**Criterion as written:** *"At least one CONFIRMED finding on a real,
independent public repository, hand-verified by the human against the actual
diff and the actual deployed bytecode."*

**Status: NOT SATISFIED, and recorded as unsatisfiable within responsible-
disclosure constraints rather than quietly dropped or worked around.**

### Why

Two constraints intersect, and the intersection is empty:

1. **CONFIRMED requires `liveness == LIVE`** (RULES.md, one of six required
   evidence fields). A regression that is live on-chain and not yet fixed is an
   undisclosed vulnerability on a funded contract — not something to put in a
   public hackathon submission.
2. **Responsible targets are already patched**, so their liveness verdict is
   `PATCHED` and their verdict caps at CANDIDATE by design.

So the only targets that could produce a public CONFIRMED are exactly the
targets it would be irresponsible to publish. That is the verdict model and the
disclosure policy both working, pulling in opposite directions.

### What was searched, and rejected

A deliberate search of the disclosed-incident corpus for Chainwatch's exact
shape — a control removed from a **same-named, same-signature** function on a
fund-critical write path, publicly disclosed and patched. Every candidate was
checked rather than assumed:

| Candidate | Verdict | Reason |
|---|---|---|
| Sense Finance `onSwap()` | reject | Immunefi states the guard was *"absent from the start"* — never a regression |
| OpenZeppelin `TimelockController.executeBatch()` | reject | Same name and signature across versions, but a pre-existing design flaw (`isOperationReady` ordered after execution), not removed by any commit |
| Audius governance/staking | reject | Storage collision between the **proxy's** slot 0 and the **implementation's** slot 0 — two different contracts, present from the original design. Rule 3c compares one contract across two commits, so it is also the wrong shape |
| 88mph `NFT.sol` | reject (measured) | A genuine regression, but constructor -> unguarded `init()` — the rename/migration class. Chainwatch is structurally blind to it; see LIMITATIONS.md §RC-RENAME1 |
| Nomad Bridge `Replica` | reject | Initialisation **value** change (trusted root set to `0x00`), not a removed guard; no rule of the nine triggers on it |

**Finding, stated plainly:** the famous-incident corpus skews heavily toward
controls that were *never present* and toward migration mistakes. Neither is
what Chainwatch detects. This is a genuine scope observation about the tool's
addressable surface, and it is why RC-RENAME1 matters more than it first looked.

### What is used instead

**Reserve Protocol — `ActFacet.revenueOverview(IRevenueTrader)`, commit
`e27227b2`, `contracts/facade/facets/ActFacet.sol`, lines 117-118.**

A real, public repository. A real commit. A `try/catch` removed from a function
that kept its **name and its signature** across the change — precisely the shape
Chainwatch claims to detect. Fully attributed by the engine, unedited:

```
CANDIDATE rule 5  contracts/facade/facets/ActFacet.sol
                  ActFacet.revenueOverview  line 117  range 117-118
  try/catch removed around the high call to price() on an unresolved
  destination; a failure now passes silently
  evidence: visibility_after=external, writes_state_after=FALSE
  why not confirmed: missing evidence: reachability, liveness
```

**The CANDIDATE cap is the point, not a shortfall.** Required evidence field 4
is *"externally callable **and** state-changing"*. `revenueOverview` is external
but writes no state, so field 4 is not established and the verdict model refuses
to promote it. No rule was changed and no exception was written to produce that
answer — it falls out of the model. A regression on a read-only function can
never reach CONFIRMED in Chainwatch, by construction.

This also means the finding carries no fund-safety sensitivity: the removed
control degrades availability of a facade view, not funds. It is safe to feature
publicly, which is the second reason it was chosen.

### The honest one-line claim

> Chainwatch located the exact commit that removed a control in a real public
> protocol, attributed it to the function and line, and then **declined to call
> it CONFIRMED** because one of its six required evidence fields was not
> established.

Not: *"Chainwatch found a confirmed vulnerability."* It did not, and the
distinction is the product.

### Criterion #6's disposition

Recorded as a **scope finding against the charter**, not a pass. To satisfy it
as literally written, a future run needs a target whose regression is genuinely
live on-chain and whose disclosure status makes publication appropriate — most
likely a coordinated-disclosure engagement, not a hackathon artifact. The
machinery is in place and proven end-to-end (capability 11 returns LIVE on real
mainnet bytecode — see LIMITATIONS.md §Capability 11 and the 88mph measurement);
what is missing is an appropriate target, not a capability.
