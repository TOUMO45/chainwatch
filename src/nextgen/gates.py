"""Bridge analysis outputs onto a `state.FindingState`'s gates.

Each `apply_*` helper takes a FindingState and one analysis result and sets the
gate(s) that result speaks to - PASS / FAIL / UNKNOWN - carrying an
`evidence_ref` (an EvidenceGraph node id) when one is available. Nothing here
decides a verdict: `state.classify` does that, mechanically, from the gates
these helpers set. Keeping the mapping in one small module means every phase
sets gates the same way and a reviewer has one place to check.
"""

from __future__ import annotations

from typing import Optional

from . import buildenv as BE
from . import state as S
from . import timemachine as TM


def apply_timeline(fs: S.FindingState, tl: TM.PropertyTimeline, *,
                   evidence_ref: Optional[str] = None) -> None:
    """Set `regression_commit` and `security_invariant` from a property timeline.

      * ABSENT at HEAD with a REMOVED that was never restored -> regression_commit PASS
      * PRESENT at HEAD (the control is in force now)          -> regression_commit FAIL
        (no live regression; a candidate here has insufficient evidence of one)
      * UNKNOWN / no events                                    -> regression_commit UNKNOWN
    """
    reg = tl.regression_commit
    if reg is not None:
        fs.set_gate("regression_commit", S.PASS,
                    note=f"{reg.at_short} {reg.kind} \"{reg.subject}\" "
                         f"({reg.date}, {reg.author})",
                    evidence_ref=evidence_ref)
    elif tl.current_state == TM.PRESENT:
        fs.set_gate("regression_commit", S.FAIL,
                    note="the security property is in force at HEAD - there is "
                         "no live regression to confirm")
    else:
        fs.set_gate("regression_commit", S.GATE_UNKNOWN,
                    note=f"timeline current_state={tl.current_state}; "
                         f"{len(tl.events)} event(s)")

    if tl.title and tl.events:
        fs.set_gate("security_invariant", S.PASS,
                    note=f"{tl.kind}: {tl.title}", evidence_ref=evidence_ref)
    else:
        fs.set_gate("security_invariant", S.GATE_UNKNOWN,
                    note="no named property / no measured change in history")


def apply_buildenv(fs: S.FindingState, rep: BE.BuildEnvReport, *,
                   evidence_ref: Optional[str] = None) -> None:
    """Set `build_environment` from a §19 report (its `gate` is already
    PASS / FAIL / UNKNOWN)."""
    fs.set_gate("build_environment", rep.gate, note=rep.rationale,
                evidence_ref=evidence_ref)


def apply_invariant_regressions(fs: S.FindingState, regressions: list, *,
                                evidence_ref: Optional[str] = None) -> None:
    """Set `security_invariant` from a §3 invariant-set diff.

    A non-empty list means a VALIDATED invariant of the old version is gone or
    weakened in the new one -> `security_invariant` PASS. The
    `invariant_violated` gate stays PENDING: identifying the regression is not
    the same as observing the violation, which needs execution (a later phase).
    An empty list leaves `security_invariant` UNKNOWN - no *validated* invariant
    regressed (which is not the same as "the code is fine").
    """
    if regressions:
        top = regressions[0]
        stmt = getattr(top, "statement", "") or (
            top.get("statement", "") if isinstance(top, dict) else "")
        fs.set_gate("security_invariant", S.PASS,
                    note=f"{len(regressions)} validated invariant regression(s); "
                         f"e.g. {stmt}",
                    evidence_ref=evidence_ref)
    else:
        fs.set_gate("security_invariant", S.GATE_UNKNOWN,
                    note="no validated invariant regressed between the two "
                         "versions examined")


def apply_attackgraph(fs: S.FindingState, paths: list, *,
                      evidence_ref: Optional[str] = None) -> None:
    """Set `reachable_path` from an attack-path search (spec §4).

      * an UNPRIVILEGED path to the sink exists  -> PASS
      * paths exist but every one traverses a guard -> FAIL (UNREACHABLE):
        the sink is reachable only by a trusted role
      * no path reaches the sink                 -> FAIL (UNREACHABLE)

    `state_reachable` and `invariant_violated` are NOT set here - proving the
    path's preconditions can be met, and that running it violates the
    invariant, are execution questions (Phase 5).
    """
    unpriv = [p for p in paths if getattr(p, "unprivileged", False)]
    if unpriv:
        p = unpriv[0]
        xc = " (cross-contract)" if getattr(p, "crosses_contracts", False) else ""
        fs.set_gate("reachable_path", S.PASS,
                    note=f"unprivileged path{xc} of {len(p.nodes)} node(s), "
                         f"edges {p.edge_kinds}", evidence_ref=evidence_ref)
    elif paths:
        fs.set_gate("reachable_path", S.FAIL,
                    note="the sink is reachable only via a msg.sender-guarded "
                         "edge - a trusted role, not an unprivileged attacker",
                    evidence_ref=evidence_ref)
    else:
        fs.set_gate("reachable_path", S.FAIL,
                    note="no path from an unprivileged EOA reaches the "
                         "security-sensitive sink", evidence_ref=evidence_ref)
