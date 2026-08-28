"""The Counterfactual Protocol Twin (spec: the 10-phase architecture).

A trace-driven complement to the source/git-history-driven next-gen pipeline.
Where `nextgen/pipeline.py` reasons from CODE (walk commits, discover invariants
from the AST, reproduce with a generated test), the Twin reasons from REAL
ON-CHAIN BEHAVIOUR:

    1  collect   real transactions for a target address (calldata, sender,
                 value, block, ordering, success/revert, logs, token transfers,
                 proxy implementation) - deep call traces + state diffs come
                 from re-executing on a local Anvil fork, not a paid RPC.
    2  fingerprint   per function: accepted vs rejected inputs, callers,
                 state transitions, asset flows, emitted events, cross-contract
                 calls.
    3  boundaries   MINE conservation / authorization / accounting /
                 state-machine / replay / collateral / withdrawal / oracle-
                 freshness / governance constraints from behaviour. Inference,
                 never proof.
    4  diverge   compare fingerprints + boundaries across historical
                 implementation versions.
    5  mutate    counterfactual variants of REAL traces (actor substitution,
                 boundary values, repetition, reorder, delay, callback insert,
                 state timing, oracle state, permission change, cross-contract
                 call variation) - prioritised near changed code.
    6  replay    execute candidates in an isolated Anvil fork at the exact
                 historical state. Never broadcast.
    7  check     invariant violation / unauthorized transition / asset
                 conservation / unexpected balance gain / unexpected loss /
                 unexpected success / revert-boundary bypass.
    8  minimize  the smallest real transaction sequence that reproduces it.
    9  provenance   git commit -> build -> bytecode -> implementation -> proxy
                 -> live deployment  (reuses nextgen/provenance + deployment).
    10 validate  independent Hunter / Skeptic / Reproducer (reuses
                 nextgen/adversarial). Only then CONFIRMED; else REJECTED /
                 UNKNOWN.

Charter carve-out (2026-08-28 amendment) applies throughout: local fork only,
no broadcast, no weaponised artifact, no auto-disclosure.
"""

from __future__ import annotations
