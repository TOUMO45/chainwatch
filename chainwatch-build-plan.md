# Chainwatch — Project Charter & Build Loop
(Fork of Ratchet's detection engine, retargeted at smart contracts. Ratchet stays untouched.)

---

## Phase 0 — Sanity check before writing code

- [ ] Prior art scan: search "git history smart contract regression detector",
      "Slither diff analysis", "Forta agent access control regression". Distinguish
      "this exists" (pivot the angle) from "adjacent but different problem" (name the
      difference — this becomes your pitch line).
- [ ] Confirm your own Solidity depth honestly: have you audited a real contract before,
      or is this from-scratch? If from-scratch, budget Phase 2 (ground truth) as a
      *learning* phase — you personally re-derive why each historical exploit worked
      before labeling it, not just copy the postmortem's conclusion.
- [ ] One-sentence differentiator, written down now:
      "Where Slither/Mythril report the current state of a contract, Chainwatch reports
      the trajectory — which commit weakened a control, and whether that weakened
      version is what's actually live on-chain."

**Gate 0:** differentiator sentence written, prior art distinguished.

---

## Phase 1 — Charter (fill this in, then paste to Claude Code as CHARTER.md)

### What Chainwatch is
A git-history regression detector for Solidity/Vyper repos that finds the exact
commit where a security control (access control, reentrancy guard, checks-effects-
interactions ordering, overflow protection, oracle validation) was weakened or
removed, links it to the causal commit, and checks whether the weakened version is
the one currently deployed on-chain.

### The one sentence
> Every other tool tells you a contract's current state is vulnerable.
> Chainwatch tells you *which commit* made it vulnerable and *whether that's live*.

### Scope table — mapped to OWASP Smart Contract Top 10 : 2026 (official, source: owasp.org)

Each OWASP category tagged honestly by whether a git-diff/AST rule can catch a
**regression** in it deterministically, or whether it structurally needs judgment
(business-logic and economic categories can't be reduced to a diff pattern — an
LLM or a human has to reason about intent). This table is the real scope-cut ladder:
build top-to-bottom, and don't promise 0-FP on anything tagged needs-judgment.

| # | OWASP Cat. | Regression pattern to detect | Type | Priority |
|---|---|---|---|---|
| 1 | SC01 Access Control | `onlyOwner`/role modifier removed or loosened on a previously-protected function | deterministic (AST diff) | critical |
| 2 | SC08 Reentrancy | `nonReentrant` guard removed, or checks-effects-interactions order broken (external call moved before state write) | deterministic (AST + CFG diff) | critical |
| 3 | SC10 Proxy & Upgradeability | who can call `upgradeTo`/`_authorizeUpgrade` changed; initializer re-callable; storage-slot collision introduced | deterministic (AST diff + storage layout compare) | critical — **decisive gate candidate, see below** |
| 4 | SC09 Integer Overflow/Underflow | `unchecked{}` added around previously-checked arithmetic; SafeMath import/usage removed | deterministic (AST diff) | high |
| 5 | SC06 Unchecked External Calls | return value of `.call()`/`.send()` no longer checked; try/catch removed around external call | deterministic (AST diff) | high |
| 6 | SC05 Lack of Input Validation | a `require()`/bounds check on a parameter removed between commits | deterministic (AST diff) | high |
| 7 | SC07 Arithmetic Errors | rounding direction changed in share/interest math, precision constant altered | deterministic, but higher FP risk — needs a human-reviewed trap set | medium |
| 8 | SC03 Price Oracle Manipulation | staleness check or deviation bound on an oracle read removed/loosened | **needs-judgment** (LLM-assisted, not pure diff) | medium |
| 9 | SC02 Business Logic | reward/lending/governance math changed in a way that breaks an invariant | **needs-judgment** — likely out of v1 scope entirely | low / defer |
| 10 | SC04 Flash Loan–Facilitated | N/A as a standalone rule — this is a *chaining* risk (SC02+SC03+SC07 combined in one tx), not a single-commit regression | **not a git-diff-detectable category** — note only, don't build a rule for it | — |
| 11 | Liveness check | is the regressed commit's code what's actually deployed (bytecode hash compare via RPC) | deterministic (RPC) | **decisive gate** |
| 12 | LLM report layer | vuln/impact/scenario/recommendation writeup, post-confirmation only | needs-judgment, gated (see capability #7 below) | medium |

**Revised decisive gate:** #3 (Proxy/Upgradeability) or #11 (liveness) — whichever
you build first, prove it end-to-end before touching anything tagged needs-judgment.
SC10 is new for 2026 and ranked in the top 3 by 2025 loss data, so it's both high-
value and a strong differentiator if your competitors' fixtures haven't caught up
to it yet.

**Honest framing for "how deep can this realistically go":** rules #1-#6 are where
you can credibly chase 0 FP with AST diffing — they're syntactic, mechanical
regressions. #7 is borderline. #8-#10 are where <cite index="18-1">2026's threat
landscape is attackers chaining vulnerabilities together rather than relying on
single code bugs</cite> — meaning these categories are fundamentally about *economic
intent*, not a diffable pattern, and belong in the LLM report layer's judgment, not
the deterministic core. Don't build v1 rules for #9/#10 — defer them explicitly and
say so in your submission, which reads as maturity, not a gap.

### Non-negotiable engineering rules
1. `fixtures/` is read-only after you sign off on it. Failing test = fix the logic, never the fixture.
2. Deterministic AST-diff checks (Slither's output, not raw regex) before anything needing judgment.
3. No new dependency without asking first — pin Slither/solc versions explicitly.
4. Read-only on any external target — this tool never writes to a repo or a chain, ever.
5. Commit after every green gate.

### Stack (pin now, don't renegotiate mid-build)
- Slither (AST + control-flow analysis) as the parsing backbone — do not hand-roll Solidity parsing.
- Python (matches Slither's own tooling and API).
- web3.py + a public RPC (Infura/Alchemy free tier) for the liveness check.
- Git for history walking (same core as Ratchet).

### Anti-goals
- Not a fuzzer. Not a symbolic executor. Not trying to find *novel* bugs — it finds
  *regressions*, i.e. things that used to be safe and no longer are.
- Not a general Slither wrapper — Slither already reports current state; Chainwatch's
  value is entirely in the "which commit, is it live" layer on top.

**Gate 1:** open a fresh Claude Code session with only this charter. Ask it to
summarize the product, the decisive gate, and the one rule it thinks matters most.
If it drifts, fix the charter — not the agent.

---

## Phase 2 — Ground truth (you do this, not the agent)

Build `fixtures/` with real, labeled cases:

**Known positives (real exploits, real commits):**
- The DAO reentrancy pattern (find the actual pre-fix commit in a reconstructable repo)
- Parity multisig — `initWallet` access-control gap
- 2-3 recent Immunefi/Code4rena disclosed findings with public commit history
  (search "Immunefi disclosed report access control 2025/2026" for ones with public repos)

**Known negatives (traps — things that LOOK like a regression but aren't):**
- A modifier renamed but logic identical (should NOT trigger)
- A `require()` moved to a different function but still enforced upstream (should NOT trigger)
- Access control loosened *temporarily* in a test/mock contract only, never in prod path
- `unchecked{}` added around a loop counter that provably can't overflow (a real
  pattern auditors accept — this is the trap that will hurt you most if missed)

Read every single one yourself — diffs, not the agent's summary. This is the step
that makes every number downstream meaningful.

**Gate 2:** `guard.sh check` reports OK, scorer reports 0/N on an empty detector
(proves the scorer can fail).

---

## Phase 3 — Integrity guard
Reuse Ratchet's `guard.sh` pattern, retarget hashes at `fixtures/` and `scorer.py`.
**Gate 3:** deliberately edit a frozen fixture, confirm the guard blocks it, revert.

---

## Phase 4 — Loop-driven build (one capability per loop, verified, committed)

**Loop order:** #1 (access control) → #2 (reentrancy) → #6 (liveness, the decisive
gate) → #5 (proxy admin) → #3 (overflow) → #4 (oracle, hardest, cut first if short on time).

Liveness (#6) gets pulled forward because it's the decisive gate — if RPC-based
bytecode comparison doesn't work reliably, the whole "trajectory + live" pitch
collapses to "Slither with extra steps."

**Scope-cut ladder if time runs short (write this down now):**
1st cut: #4 oracle validation (needs-judgment, hardest to keep 0-FP)
2nd cut: #3 overflow (least novel — Slither already flags this well)
Never cut: #1, #2, #6.

---

## Capability #7 — LLM report layer (added after your last request)

**Where it sits:** strictly downstream of a CONFIRMED finding (deterministic rule
fired + liveness check passed). The LLM never sees unconfirmed candidates and never
decides positive/negative — that stays 100% deterministic. This is the same
discipline as the charter's rule #2 ("deterministic before judgment"), just made
explicit for this capability.

**Why this boundary matters:** if the LLM can talk itself (or you) into treating a
non-finding as a finding, you've quietly reintroduced the false-positive problem
you spent Phases 2-5 eliminating. The LLM's job is explanation, not detection.

**Scope table update:**

| # | Capability | Type | Priority |
|---|---|---|---|
| 7 | LLM writeup: vuln description, impact, exploit scenario, recommendation, report | needs-judgment, **post-confirmation only** | medium |

**Input contract (what the LLM is allowed to see):**
- The specific rule that fired (e.g. "#1 access-control removed")
- The diff (before/after code, the causal commit)
- The liveness result (LIVE / PATCHED / UNKNOWN, with the contract address if LIVE)
- Nothing else — no raw repo access, no ability to re-query fixtures or flip the label

**Output contract (structured, so it's parseable and consistent across findings):**
```
## Vulnerability
<what control broke, in plain terms>

## Root Cause Commit
<hash, author, date, one-line diff summary>

## Impact
<what an attacker can actually do — funds at risk, scope of affected users/contracts>

## Exploit Scenario
<step-by-step, conceptual only — no working exploit code/calldata>

## Liveness
<LIVE / PATCHED / UNKNOWN, with the evidence>

## Recommendation
<the specific fix — usually "revert to the pre-regression logic" or equivalent>

## Confidence
<HIGH — deterministic rule + liveness confirmed. This is always HIGH by construction,
since low-confidence candidates never reach this layer.>
```

**Guardrails specific to this layer:**
- Ethical boundary from your own methodology: exploit scenario stays conceptual —
  no calldata, no working PoC transaction, no payload ready to fire at mainnet.
  That's the same line you already hold as a bug bounty hunter — impact and risk,
  not a weapon.
- If the finding is LIVE on a real contract with funds at risk, this report is a
  *disclosure draft*, not a public artifact. Same rule as Phase 6: responsible
  disclosure is your call to make deliberately, never auto-published.
- Log every LLM report next to its deterministic finding in the fixture repo, so a
  human (you) can audit LLM output quality over time the same way you audit
  detection accuracy.

**Claude Code prompt for this capability:**
```
Implement capability #7: after a finding passes the liveness check (capability #6)
with status CONFIRMED, call the LLM with ONLY: the rule that fired, the diff, and
the liveness result. Use the structured output contract in CHARTER.md capability #7.
The LLM must not have access to re-run detection or alter the CONFIRMED label — it
only explains a finding that already exists. No exploit calldata or working PoC in
the "Exploit Scenario" section — conceptual description only. Show me one full
sample report end-to-end before wiring this into the main pipeline.
```

---

## Claude Code prompts (paste one at a time, in order)

**Prompt 1 — scaffold + charter check:**
```
Read CHARTER.md fully. Summarize in 3 bullets: (1) the one-sentence product
definition, (2) the decisive gate, (3) the single engineering rule you consider
most important. Do not write any code yet. Wait for my confirmation before Phase 2.
```

**Prompt 2 — ground truth scaffolding (you still hand-review every case):**
```
Create fixtures/manifest.json with placeholder entries for the known-positive and
known-negative cases listed in CHARTER.md Phase 2. For each, include: repo URL,
commit hash, one-line description, and label (positive/negative). Do not invent
commit hashes — leave them blank with a TODO for me to fill in from real research.
```

**Prompt 3 — capability #1 (access control), one rule only:**
```
Implement ONLY capability #1 from the scope table: detect when an access-control
modifier (onlyOwner, role-based check) is removed or loosened between two commits,
using Slither's AST output — not regex on raw source. Write scorer.py to run this
rule against fixtures/ and report precision/recall. Do not touch any other
capability. Run guard.sh check before and after. Stop and show me the raw
precision/recall output — do not summarize it as "looks good."
```

**Prompt 4 — decisive gate (#6, liveness):**
```
Implement capability #6: given a flagged commit and a contract address, fetch the
deployed bytecode via RPC (web3.py) and compare its hash against the bytecode
compiled from the flagged commit vs. the current HEAD. Report LIVE / PATCHED /
UNKNOWN. Include a negative control: run this against a contract you know is
already patched and confirm it correctly reports PATCHED, not LIVE.
```

Repeat the same shape (implement ONE capability, run scorer, show raw output,
integrity check before/after) for #5, #3, #4.

---

## Phase 5 — Real-world verification (never skip)
Run against 10-15 real, independent contract repos (not ones chosen because they
look promising). Hand-verify every hit against the actual diff and, where possible,
the actual deployed bytecode. Every false positive becomes a permanent fixture case.

**Gate 5:** at least one hand-verified real finding, at least one documented and
fixed false positive.

---

## Phase 6 — When you're ready to show this to anyone
Do this only after Gate 5. If you find a live, exploitable regression on a *real*
deployed contract with funds at risk, this becomes a responsible-disclosure
decision — Immunefi/program-specific, never public — and that call is yours to make
deliberately, not something to automate or rush for a demo.
