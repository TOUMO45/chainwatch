"""Adversarial validation (spec §7, §8).

Three independent roles over one candidate:

  hunter.py      assembles the POSITIVE evidence chain (runs the Phase 1-3
                 analyzers, sets gates toward PASS). "Agent A."
  skeptic.py     independently runs the REJECTION sweep - actively tries to
                 disprove the Hunter: compensating control, deployment
                 mismatch, unreachable path, build-env drift, no live
                 regression, duplicate, economic infeasibility. "Agent B."
  reproducer.py  gets ONLY the technical target + proposed invariant (never the
                 Hunter's explanation) and independently attempts to reproduce
                 the behaviour. "Agent C." Execution lands in Phase 5; Phase 4
                 ships the blinded interface and a PENDING result.

A candidate survives only if HUNTER = proof AND SKEPTIC = failed to disprove
AND (Phase 5) REPRODUCER = agreement. None of these three can DECLARE
CONFIRMED - they set gates, and `state.classify` decides (spec §22).
"""

from __future__ import annotations
