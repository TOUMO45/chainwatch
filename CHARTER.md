# Chainwatch — Project Charter

> Claude Code reads this file at the start of every session. It is the contract.
> If a request conflicts with this file, stop and ask the human. Do not resolve it yourself.

## What Chainwatch is

A git-history regression detector for Solidity repositories. It finds the exact commit
where a security control was weakened or removed, links it to its causal commit, and
verifies whether that weakened version is what is currently deployed on-chain.

## The one sentence that defines the product

> Every other tool reports whether a contract is vulnerable now.
> Chainwatch reports **which commit made it vulnerable, and whether that commit is live on-chain.**

If a feature does not serve that sentence, it is out of scope regardless of how good
it sounds.

## Why this exists (evidence, not opinion)

- The OWASP Smart Contract Top 10 : 2026 is anchored to 122 deduplicated 2025 incidents
  representing ~$905.4M in smart-contract-only losses. Access Control (SC01) ranks #1;
  Proxy & Upgradeability (SC10) is newly added for 2026.
- Existing tooling covers **state**, not **trajectory**:
  - Slither / Aderyn / Mythril: is this contract vulnerable *right now*
  - OpenZeppelin Defender: does deployed bytecode match the *audited* build artifact
    (and Defender is now in maintenance mode, with users pushed toward OpenZeppelin Monitor)
  - Forta: real-time *transaction* anomaly detection on-chain
- None of them answer: *which commit introduced this weakness, what caused it, and is
  that exact version the one holding funds today.* That gap is the entire product.

## Success definition (non-negotiable)

The project is DONE when **all 7** are true:

1. `./guard.sh check` reports `INTEGRITY OK` on a clean tree.
2. `python scorer.py --all` reports **precision = 1.00** across every shipped rule
   against `fixtures/`, with recall reported per rule (recall ≥ 0.70 per shipped rule).
3. `python scorer.py --empty-detector` reports `0/N` — proving the scorer can actually
   fail. A scorer that passes with no logic behind it is worthless.
4. `python chainwatch.py --repo <url> --address <addr>` walks full commit history and
   emits CONFIRMED / CANDIDATE / DISCARDED verdicts with all six evidence fields populated.
5. The liveness check (`capability #11`) returns correct LIVE / PATCHED / UNKNOWN on a
   **negative control**: a contract known to be already patched must report PATCHED,
   not LIVE.
6. At least one CONFIRMED finding on a real, independent public repository, hand-verified
   by the human against the actual diff and the actual deployed bytecode.
7. At least one false positive found during real-world testing, root-caused, fixed, and
   added to `fixtures/` as a permanent negative case.

Adjectives are not success criteria. Every item above is a command whose raw output the
human reads.

## Scope table

Full rule specifications live in `RULES.md`. That file is authoritative for trigger
conditions and exclusion sets. This table is the build order and priority only.

| # | OWASP | Capability | Type | Priority |
|---|---|---|---|---|
| 1 | SC01 | Access control modifier removed/loosened | deterministic | critical |
| 2 | SC08 | Reentrancy guard removed / CEI ordering broken | deterministic | critical |
| 3 | SC10 | Proxy: upgrade auth weakened, initializer re-callable, storage collision | deterministic | critical |
| 4 | SC09 | Overflow protection removed (`unchecked{}`, SafeMath) | deterministic | high |
| 5 | SC06 | External call return value no longer checked | deterministic | high |
| 6 | SC05 | Input validation `require()` removed | deterministic | high |
| 11 | — | **On-chain liveness (bytecode hash compare via RPC)** | deterministic | **DECISIVE GATE** |
| 12 | — | LLM report layer (post-CONFIRMED only) | needs-judgment | medium |

**Build order:** 3 → 11 → 1 → 2 → 6 → 5 → 4 → 12.
Rule 3 first because SC10 is new for 2026 and least covered by existing fixtures.
Capability 11 second because it is the decisive gate.

**Decisive gate:** capability 11. If deployed-bytecode liveness comparison does not work
reliably, Chainwatch reduces to "Slither with extra steps" and the product has no reason
to exist. If gate 11 is not green by the 60% mark of available time, cut everything else
and put all remaining effort there.

**Scope-cut ladder (pre-declared, in cut order):**
1. Capability 12 (LLM report layer)
2. Rule 4 (overflow — Slither already covers this well)
3. Rule 5 (unchecked external calls)
4. Rule 6 (input validation)

**Never cut:** `fixtures/`, `guard.sh`, Rule 3, Capability 11.

## Non-negotiable engineering rules

1. `fixtures/` is READ-ONLY after human sign-off. If a check fails, fix the logic,
   never the test.
2. Deterministic checks before anything requiring judgment or an LLM call. The LLM
   never sees a CANDIDATE or DISCARDED verdict — only CONFIRMED. It explains findings;
   it never decides them.
3. No new dependency without asking the human first. Pin Slither and solc versions
   explicitly.
4. No invented APIs. If unsure how Slither's API works, read the actual installed
   library source. Do not guess method names.
5. **Read-only on every external target.** Never write to, push to, commit to, or
   authenticate beyond public-read on any repository or chain this project analyzes.
   Never send a transaction. Ever.

   > *Provenance (historical record, not a carve-out):* verified via **WALK-L6**.
   > An earlier implementation created git worktree metadata in the target's
   > `.git/`; this was identified and fixed by routing all git operations through
   > a scratch mirror clone (`history.mirror_clone()`). Confirmed **absent**, not
   > merely unchanged, on a read-only-mounted target.
6. Commit after every green gate.
7. Run `./guard.sh check` before AND after every work session. If it reports TAMPERED,
   **stop and show the diff — never silently revert, never work around it.** Do not run
   `git checkout HEAD -- <protected paths>` to silence a warning; that destroys
   legitimate uncommitted work as easily as it discards a real tamper. Diagnose first.
8. Never report "it works" without pasting the raw command output. Summaries of test
   results are not test results.

## Stack (fixed — do not renegotiate mid-build)

- **Python 3.11+** — matches Slither's own tooling
- **Slither** (pinned version) — AST, IR, and control-flow analysis backbone.
  Do NOT hand-roll Solidity parsing. Do NOT regex on source text for any rule.
- **solc-select** — per-commit compiler version management (repos change pragma over
  their history; this is mandatory, not optional)
- **`solc --storage-layout`** — Rule 3c storage collision comparison
- **GitPython** or plain `git` subprocess — history walking
- **web3.py** + public RPC (Infura/Alchemy free tier) — capability 11 liveness
- **pytest** — scorer harness

## Anti-goals

Chainwatch deliberately does **not**:

- Fuzz, symbolically execute, or formally verify. Not competing with Echidna/Foundry/Certora.
- Detect *novel* vulnerabilities. It detects **regressions** — controls that existed and
  no longer do. A contract that was never safe is out of scope by definition.
- Wrap Slither's existing state detectors and call that a product. Slither already
  reports current state; all of Chainwatch's value is the "which commit / is it live" layer.
- Build rules for SC02 (Business Logic), SC04 (Flash Loan), or SC07 (Arithmetic Errors)
  in v1. These require economic-intent reasoning, not diff patterns. Deferred explicitly
  and documented as deferred — stating this is maturity, not a gap.
- Generate exploit code, calldata, or working proof-of-concept transactions. Impact and
  risk are described conceptually. This holds even in the LLM report layer.
- Auto-publish or auto-disclose anything. If a CONFIRMED finding is LIVE on a real
  contract with funds at risk, that is a responsible-disclosure decision the human makes
  deliberately, through the appropriate program. Never automated, never rushed for a demo.
