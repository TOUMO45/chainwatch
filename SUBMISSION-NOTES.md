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
| 88mph `NFT.sol` | **stale — see note below** | Originally rejected as the rename/migration class Chainwatch was "structurally blind to". That was true when this table was written; it stopped being true once Rule 10 shipped (LIMITATIONS.md §RC-RENAME1, closed) and, as of 2026-08-30, once §LIVE-L1 closed the remaining liveness gate too. Left in this table rather than deleted, with the correction below, per this file's own "claims must match what was measured" charter |
| Nomad Bridge `Replica` | reject | Initialisation **value** change (trusted root set to `0x00`), not a removed guard; no rule of the nine triggers on it |

**Finding, stated plainly:** the famous-incident corpus skews heavily toward
controls that were *never present* and toward migration mistakes. Neither is
what Chainwatch detects. This is a genuine scope observation about the tool's
addressable surface, and it is why RC-RENAME1 matters more than it first looked.

### 2026-08-30 update — the 88mph row above is now factually wrong, corrected in place

Re-run through the real, unmodified pipeline on 2026-08-30, on explicit
request, after §LIVE-L1's liveness-gate fix (LIMITATIONS.md): the exact pair
cited in this table (`5f52a2ea..a4c48d61`, address `0xDe71B24F...`) now
produces **`1 finding, 1 CONFIRMED, 0 CANDIDATE`** — every one of the six
required evidence fields present, liveness `LIVE`, and independently a
read-only `eth_call` (capability 14) showing `init()` still does not revert
against the live deployed bytecode. This is measured, not projected; see
`README.md`'s "Try it yourself" section for the exact reproducible command and
its full output.

**This changes the premise of the "Why" section above, and that is a decision
for a human, not something resolved unilaterally here.** The argument that
criterion #6 is unsatisfiable rests on "the only targets that could produce a
public CONFIRMED are exactly the targets it would be irresponsible to
publish" — 88mph does not fit that trade-off: it is a five-year-old, publicly
disclosed (Immunefi, iosiro, Quadriga — all cited in README), already-settled
incident whose specific pools were emptied to treasury within 24 hours of
disclosure, so publishing it discloses nothing new and endangers no funds. If
that reasoning holds, 88mph is a real candidate for satisfying criterion #6 as
written, and the "Status: NOT SATISFIED" line at the top of this document may
no longer be accurate. Left as-is pending that call; the fact recorded here is
independent of what gets decided with it.

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

---

## Devpost registration — track and pitch

**Track: "The Taskmaster."** Confirmed as the correct fit, and the reason is the
architecture rather than the topic: the submission is an autonomous agent that
*acts* on a finished analysis — triaging findings, pulling evidence, reading the
real diff, drafting, mechanically verifying its own output, revising, and saving
an artifact — rather than a chat interface over a security tool. The 30%
*architectural discipline* weight is where this project is strongest, and the
boundary it is built on (a deterministic engine decides; the model only explains)
is the thing worth judging.

### Pitch — revised 2026-08-16

The earlier pitch was drafted when Chainwatch was an engine with no agent, no web
app, no container and a read-only claim that turned out to be inaccurate. All
four of those changed, so the sentence changed with them.

> **Chainwatch finds the exact commit where a smart contract's security control
> was removed, proves whether that broken version is the bytecode live on-chain,
> and hands a Gemini agent a finished verdict to write up — an agent that can
> read the evidence but cannot decide what counts as a finding, and whose every
> claim is mechanically checked against the engine's record before it is saved.**

If a shorter line is needed:

> **Every other tool tells you a contract is vulnerable now. Chainwatch tells you
> which commit made it vulnerable, whether that code is live on-chain, and — when
> the evidence is incomplete — refuses to call it confirmed.**

### What must not drift in submission copy

Three claims are load-bearing and all three are easy to accidentally inflate:

1. **No CONFIRMED finding exists.** The real-world demonstration is a CANDIDATE,
   and the cap is the point. Never write "found a vulnerability".
2. **LIVE means bytecode identity, not exploitability.** `LIVE_CAVEAT` travels
   with every LIVE verdict, including in a video frame.
3. **Coverage is repo-dependent.** 100% on a modern window; 6.9% of file
   comparisons on an older 25-pair walk. Quote the number that matches the run
   being shown.

### Status of the submission checklist

| Item | State |
|---|---|
| Track selected | The Taskmaster — confirmed |
| Pitch | revised above for current scope |
| Working product | engine + CLI + web app + agent, all locally verified |
| Container | built and smoke-tested locally |
| Cloud Run deploy | **pending** — needs a GCP project and credentials |
| Demo video | script drafted (`DEMO-SCRIPT.md`), **not recorded** |
| Devpost form submitted | **not submitted** — requires the human |

**Chainwatch cannot register itself.** Devpost account actions — creating the
submission, selecting the track, uploading the video, clicking submit — are the
human's to perform. Everything above is prepared so that step is filling a form,
not writing copy under deadline.
