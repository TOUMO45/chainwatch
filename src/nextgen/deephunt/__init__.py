"""Deep Hunt Engine - Chainwatch 2.0 (the "DEEP PROTOCOL SECURITY ENGINE" spec).

ADDITIVE AND OPT-IN. A THIRD pipeline, beside the classic regression scanner
(`src/scan.py` -> `src/verdict.py`) and the `src/nextgen/` regression + Twin
pipelines. It answers a DIFFERENT question:

    "Can the currently deployed protocol be driven into a state that violates a
     security property?"  - with NO requirement that a Git commit introduced it.

A vulnerability does not need a regression: a bug that shipped with the original
2024 deployment has no vulnerable commit, yet the contract is exploitable today.
The regression engine correctly says NO REGRESSION; this engine can still find
the LIVE VULNERABILITY.

WHAT IT REUSES (unchanged): the `src/nextgen/` substrate - the finding state
machine and gate model (`state.py`), the evidence graph (`evidence_graph.py`),
the deterministic proof score + hard gates (`proofscore.py`), the Foundry/anvil
adapter (`execground/foundry.py`), the economic model (`execground/economics.py`),
the Skeptic and blinded Reproducer (`adversarial/`), the invariant lifecycle
types (`invariants/model.py`), and the Twin's trace machinery (`twin/`).

DISCIPLINE (identical to the rest of Chainwatch): no deterministic, independently
reproduced proof -> no CONFIRMED. `UNKNOWN` over a guess. An LLM may propose
hypotheses; it never decides a verdict (spec sections 18, 22, 33).

Nothing in this package is imported on the classic path, the `src/nextgen`
pipeline, or the CLI unless `CHAINWATCH_DEEPHUNT` is set - the `--deep-hunt`
flag sets it before importing `deephunt.hunt`.
"""

from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}


def enabled() -> bool:
    """Whether the Deep Hunt engine is switched on for this process.

    A function, not a module constant, so a test (or the `--deep-hunt` flag
    setting the env var before `deephunt.hunt` is imported) sees the current
    value rather than whatever it was at first import. Mirrors
    `src.nextgen.enabled()`.
    """
    return os.environ.get("CHAINWATCH_DEEPHUNT", "").strip().lower() in _TRUTHY


__all__ = ["enabled"]
