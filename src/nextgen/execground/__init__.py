"""The execution-grounding layer (spec §5, §6, §14, §15, §21).

CHARTER carve-out (2026-08-28 amendment): everything here runs against a LOCAL
forked EVM only. No transaction is ever broadcast to a real network; no
weaponised / reusable exploit artifact is produced; nothing is auto-disclosed.
A reproducer demonstrates an invariant violation and then is discarded.

    foundry.py    the toolchain adapter - native `forge`/`anvil` if on PATH,
                  else WSL. Degrades to "unavailable" cleanly.
    project.py    scaffold a throwaway Foundry project in a Linux tmp dir
    reproducer.py (§15) generate + run a minimal fork reproducer for a
                  §3 SearchTarget objective -> REPRODUCED / NOT_REPRODUCED
    economics.py  (§14) rough economic-feasibility estimate -> a gate signal
    sequences.py  (§5) stateful multi-tx search + minimisation  [Phase 5b]
    hybrid.py     (§6) static -> constraint sketch -> concrete run  [Phase 5b]
    regfuzz.py    (§21) behavioural-divergence fuzzing between two commits [5b]

With no toolchain reachable, every entry point returns a PENDING/UNKNOWN
result and the `reproducer` / `state_reachable` / `invariant_violated` gates
stay PENDING - never PASS. Same discipline as `liveness.py` without an RPC.
"""

from __future__ import annotations
