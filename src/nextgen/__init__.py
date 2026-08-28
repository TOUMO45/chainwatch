"""The next-generation, execution-grounded proof pipeline (NEXTGEN.md).

ADDITIVE AND OPT-IN. Nothing in this package is imported by `src/scan.py`,
`src/verdict.py`, `src/rules/`, or the classic CLI/web paths unless the
`CHAINWATCH_NEXTGEN` flag is set (later phases wire that in). Phase 0 ships the
substrate only:

    state.py           the explicit finding state machine (spec §17), the gate
                       model, and UNKNOWN as a first-class outcome (spec §24)
    evidence_graph.py  findings stored as typed evidence nodes + relationships,
                       so every report statement is traceable (spec §18)
    proofscore.py      the deterministic +/- score (spec §16) AND the hard
                       gates the score can never override

WHY A SEPARATE PACKAGE. The classic pipeline's precision discipline
(`precision = 1.00` on 14 fixture sets, 346 tests, `guard.sh`) is the product's
credibility. The upgrade must not put a crack in it while it is being built, so
the new machinery grows beside it and a next-gen CONFIRMED is required to clear
the CLASSIC gate first and then a stricter chain on top - it can only ever be
more conservative, never less.
"""

from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}


def enabled() -> bool:
    """Whether the next-gen pipeline is switched on for this process.

    A function, not a module constant, so a test (or a later `--nextgen` flag
    that sets the env var before import side effects matter) sees the current
    value rather than whatever it was at first import.
    """
    return os.environ.get("CHAINWATCH_NEXTGEN", "").strip().lower() in _TRUTHY


__all__ = ["enabled"]
