# Chainwatch — measured results

> Every number here was produced by a harness in this repository, over a public
> corpus, and the raw per-case JSON is committed alongside. Where a number is
> weak, or measures something narrower than it appears to, that is said in the
> row rather than in a footnote.

Re-run anything below from `src/nextgen/deephunt/bench_*.py`. Corpora are
gitignored checkouts under `realworld-test/`.

---

## The short version

| Corpus | What it asks | Result |
|---|---|---|
| **DVBench** (90 real DeFi exploits, blind) | Can it name the root cause from source alone? | **micro recall 0.443** (43/97 reference findings), 65/72 compiled |
| **DeFiHackLabs** (855 incidents) | Same, at 10× the scale | **50.8%** class-matched (32/63 scoreable), 122 modelled |
| **SmartBugs-curated** (143, line-level truth) | Classic 2016–18 bug classes | 128/131 compiled, **27.3%** right-category |
| **Web3Bugs** (102 code4rena contests) | Does the narrow oracle misfire? | **3 fires, all on the one vulnerable contract, 0 false positives** |
| **Sanctuary** (mainnet contracts) | What does it say about ordinary code? | **0** high-confidence findings and **0** oracle fires in 147 |

### The one-line claim, and what it does not say

> **Chainwatch identifies the correct failure mechanism in 50.8% of scoreable
> real-world exploits (32/63, DeFiHackLabs), with 0 high-confidence false
> positives per 1,000 ordinary mainnet contracts (147 scanned).**

Three caveats that belong in the same breath, not in an appendix:

- **63, not 855.** The denominator is incidents that reached the engine *and*
  carry a mechanism to score against — verified source exists (134), it compiles
  (122), and the root cause is not the unscoreable `BUSINESS_LOGIC`/`OTHER`
  (63). Every step of that funnel is printed above. Quoting 50.8% against 855
  would be false.
- **"Mechanism matched", not "found the bug".** The scorer asks whether the
  finding class matches the incident class. That is a real signal and a coarse
  one; it is not a human confirming the specific defect.
- **The FP figure is per contract, not per commit pair,** and on a corpus that
  is ordinary rather than known-clean. See Pass 3.

**Across every corpus: `CONFIRMED` = 0.** That is the correct result, not a
disappointment — a source-only run has no deployment proof and no reproducer,
so the evidence chain cannot close and every finding stays `UNKNOWN`. The
number to watch is whether it is ever non-zero without execution grounding.

---

## Two real bugs, found blind, verified against ground truth

Neither was pointed at: no contract name, no function, no bug class was
supplied to the engine.

**1. Ambire — signature replay across identities.**
Deep Hunt reported `QuickAccManager.send` / `sendTransfer` / `sendTxns`, party
`identity`. That is code4rena 2021-10 finding **H-03, "Signature replay attacks
for different identities (nonce on wrong party)" — confirmed and patched by the
Ambire team** (Web3Bugs label S2-3). It is now the repo's top-ranked finding.

**2. FireToken — pair-balance theft + forced reserve sync.**
Deep Hunt reported `FireToken._transfer`. DVBench's reference finding for that
case reads *"Sell path illegally burns tokens from the Uniswap pair balance and
forcibly syncs reserves"* — the same defect, independently described.

---

## Pass 1 — Detection (DeFiHackLabs)

`src/nextgen/deephunt/bench_dfhl.py` · raw: `.dfhl-detection.json`

The goal asked to check out each protocol's commit before the attack. Almost
none of these incidents map to a public repo, so the harness uses something
strictly better: **the verified source of the contract that was actually
exploited, at the pre-attack fork block the PoC itself names.** That is the
vulnerable code, not a guess at which commit produced it.

```
incidents in corpus     855
out of scope              8   key compromise 2 / rug 5 / social 1
IN SCOPE                847

verified source found   134   (15.8% of attempted - Sourcify only)
modelled (compiled)     122   (91.0% of source-available)
produced >=1 finding      92   (75.4% of modelled)
reached CONFIRMED          0   (correct: source-only cannot close the chain)
errors                     0
```

**Detection rate, scored on mechanism.** "Produced a finding" is not a
detection rate — it only says the tool spoke. The real question is whether the
finding describes the *same mechanism* the incident was, so each incident's
root-cause class is matched against the finding types Chainwatch emitted:

| Root-cause class | matched | rate |
|---|---:|---:|
| INPUT_VALIDATION | 7/8 | 87.5% |
| REENTRANCY | 6/9 | 66.7% |
| PRICE_MANIPULATION | 15/24 | 62.5% |
| SIGNATURE_REPLAY | 1/3 | 33.3% |
| ACCOUNTING_MATH | 1/3 | 33.3% |
| **ACCESS_CONTROL** | **2/14** | **14.3%** |
| ARBITRARY_EXTERNAL_CALL | 0/2 | 0.0% |
| **total** | **32/63** | **50.8%** |

59 further modelled incidents are `BUSINESS_LOGIC` or `OTHER`. Those labels name
no mechanism, so no finding type can be said to match them; they are excluded
from the denominator rather than scored arbitrarily. (44 of the 59 did produce
findings, which is suggestive and nothing more.)

**The ACCESS_CONTROL row is the most useful number here** — it is the class
Chainwatch should own, and it is the worst. The cause is structural and is
written up under *What limits these numbers*.

### Root-cause distribution — 855 incidents

This is the demand signal the rule-mining pass was written from.

| Class | n | % | Covered by the 10 regression rules? |
|---|---:|---:|---|
| OTHER | 202 | 23.6% | no |
| BUSINESS_LOGIC | 174 | 20.4% | no |
| PRICE_MANIPULATION | 150 | 17.5% | **no** |
| ACCESS_CONTROL | 98 | 11.5% | yes — rules 1, 10 |
| ACCOUNTING_MATH | 66 | 7.7% | partly — rule 4 is overflow only |
| INPUT_VALIDATION | 57 | 6.7% | yes — rule 6 |
| REENTRANCY | 56 | 6.5% | yes — rules 2a, 2b |
| ARBITRARY_EXTERNAL_CALL | 35 | 4.1% | partly — rule 5 checks returns only |
| SIGNATURE_REPLAY | 13 | 1.5% | **no** |
| UNPROTECTED_INIT_UPGRADE | 4 | 0.5% | yes — rules 3a, 3b |

**63.0% of real incidents fall in classes no existing rule covers.**

---

## Pass 2 — Rule mining

Rules written from that table, not from intuition. Each ships with its
near-miss cases as tests, because a detector that fires on correct code is
worse than no detector.

| # | Rule | Demand | Ground truth it reproduces |
|---|---|---:|---|
| **11** | AMM pair-balance manipulation + forced `sync()` | 14 skim/reserve incidents + 17 fee/reflection tokens | FireToken (DVBench reference finding) |
| **12** | Credited amount ≠ amount actually received | 17 fee-on-transfer / reflection incidents | the mechanism behind all 17 |
| **(prior)** | Signature scope — nonce on the wrong party | 13 signature-replay incidents | Ambire H-03 |

Price manipulation (150 incidents, the largest gap) was already covered by
`cat_oracle_assumption`, which scores recall 1.0 on DVBench's HYDT case — so it
did not need a new rule, and none was written for it.

### Why these two, mechanically

**Rule 11.** A correct ERC-20 never debits an address that is neither the
sender nor the recipient. The third-party balance write is therefore the signal;
`sync()` raises strength but never fires the rule alone, because calling `sync()`
without touching a balance is merely unusual.

**Rule 12.** The correct version of the code measures
`balanceOf(address(this))` before and after. That marker's presence clears the
function outright, which gives the rule a crisp boundary instead of a threshold.
Two false positives were found by testing the near misses and are regression-
locked: a `transferFrom` that *pushes* out, and a `-=` debit whose `=` the
credit regex had matched.

---

## Pass 3 — Precision

`src/nextgen/deephunt/bench_precision.py` · raw: `.precision-run.json`

**A unit correction, stated rather than glossed.** The goal asked for false
positives per 1,000 *commit pairs*. Sanctuary contracts have no git history, so
that unit does not exist for this corpus; the number below is per 1,000
**contracts scanned**. The commit-pair figure is a different measurement over
repositories with history and is not conflated with it.

**And a claim this harness refuses to make.** Sanctuary is a scrape of ordinary
Etherscan-verified mainnet contracts — it is *not* a known-clean corpus. Some of
it is genuinely buggy and some is outright malicious, so a finding there is not
automatically a false positive, and the harness never calls one that. What it
measures instead is the `CONFIRMED` rate, which on a source-only run must be
exactly zero, and it records every narrow-oracle fire individually so each can
be adjudicated by hand.

```
contracts sampled       250      (deterministic sample, seed 20260830)
modelled (compiled)     147      (58.8%)
errors                    0

per 1,000 contracts scanned:
  CONFIRMED               0.0     (0 absolute)
  high-confidence         0.0     (0 absolute)
  signature-scope fires   0.0     (0 contracts, 0 fires)

any finding at all       91      (61.9% of modelled)
```

**Zero high-confidence findings and zero narrow-oracle fires across 147
ordinary mainnet contracts.** The 91 contracts that produced *something* are all
at `CANDIDATE`/`UNKNOWN` — the level that says "this is worth a look", not
"this is a bug" — and on a corpus that genuinely contains buggy and malicious
code, that is the expected shape rather than a defect.

### The precision result that is already solid

The signature-scope oracle swept **all 102 code4rena contests in Web3Bugs**
(53 compiled, `.sigscope-sweep.json`):

```
fires = 3      all three on contest 38 (Ambire)      false positives = 0
```

Three fires on the one codebase that has the bug, silence on the other 52 real
protocol codebases. The decisive precision test is permanent: OpenZeppelin's
`ERC20Permit.permit` — the most-deployed signature-consuming function in DeFi —
is asserted **modelled first**, then asserted not flagged, so the silence cannot
be vacuous.

---

## What limits these numbers

Ranked by how much fixing each would move them.

1. **The ACCESS_CONTROL blind spot (2/14).** `cat_authorization` establishes
   that a variable is privileged by finding a *guarded sibling* that writes it.
   A contract where **nothing** guards the owner setter has no sibling — so the
   most severe case of all is the one it cannot see. A rule to close this was
   written, measured, and **rejected**: it recovered 2 of the 12 missed
   incidents and both were false positives (OpenZeppelin's deliberately
   permissionless `renounceRole`, and a `_balances` variable that reached
   `guard_vars` by sharing a guard with a real auth check). The hole is real and
   still open; the fix needs a sounder notion of "authority state" than either
   naming or guard co-occurrence provides.
2. **Compile rate, everywhere.** An uncompiled bundle contributes exactly zero.
   Fixing verified-bundle import resolution took DVBench from 38/72 to 65/72
   compiled and recall 0.247 → 0.443 **with no new detector**. This remains the
   cheapest available gain.
3. **Verified-source availability.** Only 134 of 847 in-scope DeFiHackLabs
   targets have Sourcify-verified source; the rest are Etherscan-only. An
   Etherscan API key would roughly triple the detection denominator.
4. **No execution grounding without an RPC per chain.** Only chains with an
   endpoint configured can be forked, so everything else is capped at
   `UNKNOWN` by construction. `bench_dvbench.rpc_for_chain` reads per-chain
   env vars, so this lifts with configuration, not code.
5. **Scoring proxies are not the real judges.** DVBench's own scorer is an LLM
   judge; ours is a deterministic root-cause-overlap heuristic, documented as
   approximate. The DeFiHackLabs class-match scorer is coarser still — it asks
   whether the *mechanism* matches, and `BUSINESS_LOGIC` / `OTHER` carry no
   mechanism, so they are excluded from that denominator rather than scored
   arbitrarily.

---

## Reproducing

```bash
git clone https://github.com/SunWeb3Sec/DeFiHackLabs        realworld-test/dfhl
git clone https://github.com/smartbugs/smartbugs-curated    realworld-test/sbcur
git clone https://github.com/Cecuro/defi-vuln-benchmark     realworld-test/dvbench
git clone https://github.com/ZhangZhuoSJTU/Web3Bugs         realworld-test/web3bugs
```

Source is fetched keylessly from Sourcify and cached, so a second run is
offline. `solc-select` needs the 0.4.x series installed for SmartBugs.
