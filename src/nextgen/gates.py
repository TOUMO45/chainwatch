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


def apply_compensating(fs: S.FindingState, rep, *,
                       evidence_ref: Optional[str] = None) -> None:
    """Set `no_compensating_control` from a §11 report.

    A control FOUND fails the gate (FAIL -> the finding is REJECTED as a
    FALSE_POSITIVE - the removed guard is replaced by an equivalent mechanism).
    None found -> PASS. `rep.gate` is already S.PASS / S.FAIL / S.GATE_UNKNOWN.
    """
    gate = getattr(rep, "gate", S.GATE_UNKNOWN)
    fs.set_gate("no_compensating_control", gate,
                note=getattr(rep, "rationale", ""), evidence_ref=evidence_ref)


def apply_provenance(fs: S.FindingState, chain, *,
                     evidence_ref: Optional[str] = None) -> None:
    """Set `bytecode_provenance` from a §9 provenance chain (PASS on MATCH,
    FAIL -> DEPLOYMENT_MISMATCH on MISMATCH, UNKNOWN when incomplete)."""
    fs.set_gate("bytecode_provenance", getattr(chain, "gate", S.GATE_UNKNOWN),
                note=getattr(chain, "rationale", ""), evidence_ref=evidence_ref)


def apply_deployment(fs: S.FindingState, facts, *,
                     evidence_ref: Optional[str] = None) -> None:
    """Set `target_live` from a §10 deployment assessment (PASS when the
    address serves the vulnerable implementation, FAIL -> PATCHED when it does
    not, UNKNOWN when unresolved)."""
    fs.set_gate("target_live", getattr(facts, "gate", S.GATE_UNKNOWN),
                note=getattr(facts, "rationale", ""), evidence_ref=evidence_ref)


_SKEPTIC_MIN_CHECKS = 3


def apply_skeptic(fs: S.FindingState, report, *,
                  evidence_ref: Optional[str] = None) -> None:
    """Fold a §7 Skeptic sweep into the gates.

    Each DISPROVED challenge FAILS its mapped gate (the Skeptic overrides a
    Hunter PASS - disproving is the point). `independent_validation` reaches
    PASS only when the sweep is clean over >= 3 checks AND the blinded
    reproducer already agrees (`reproducer` == PASS); otherwise it is UNKNOWN.
    The Skeptic never PASSES any other gate.
    """
    from .adversarial import skeptic as SK

    for c in getattr(report, "challenges", []):
        if c.outcome == SK.DISPROVED and c.gate:
            fs.set_gate(c.gate, S.FAIL,
                        note=f"Skeptic: {c.detail or c.name}",
                        evidence_ref=evidence_ref)

    ran = len(getattr(report, "ran", []))
    if getattr(report, "disproved", False):
        fs.set_gate("independent_validation", S.FAIL,
                    note="Skeptic disproved the candidate", evidence_ref=evidence_ref)
    elif ran >= _SKEPTIC_MIN_CHECKS and fs.gates.get("reproducer") == S.PASS:
        fs.set_gate("independent_validation", S.PASS,
                    note=f"Skeptic sweep clean over {ran} checks; blinded "
                         f"reproducer agrees", evidence_ref=evidence_ref)
    elif ran >= _SKEPTIC_MIN_CHECKS:
        fs.set_gate("independent_validation", S.GATE_UNKNOWN,
                    note=f"Skeptic sweep clean over {ran} checks; awaiting "
                         f"independent reproduction")
    else:
        fs.set_gate("independent_validation", S.GATE_UNKNOWN,
                    note=f"insufficient Skeptic coverage: only {ran} check(s) "
                         f"had inputs")


def apply_reproducer(fs: S.FindingState, result, *,
                     evidence_ref: Optional[str] = None) -> None:
    """Fold a §8 blinded-Reproducer result into the gates.

    REPRODUCED -> `reproducer` PASS, and (the run observed it) `invariant_violated`
    and `state_reachable` PASS. NOT_REPRODUCED -> `reproducer` FAIL. PENDING /
    ERROR -> `reproducer` stays PENDING (the attempt is recorded in history).
    """
    from .adversarial import reproducer as RP

    status = getattr(result, "status", RP.PENDING)
    detail = getattr(result, "detail", "")
    if status == RP.REPRODUCED:
        fs.set_gate("reproducer", S.PASS, note=detail, evidence_ref=evidence_ref)
        fs.set_gate("invariant_violated", S.PASS,
                    note="observed during the local-fork reproduction",
                    evidence_ref=evidence_ref)
        fs.set_gate("state_reachable", S.PASS,
                    note="the required state was constructed in the reproducer",
                    evidence_ref=evidence_ref)
    elif status == RP.NOT_REPRODUCED:
        fs.set_gate("reproducer", S.FAIL,
                    note=detail or "the reproduction did not trigger the "
                                   "invariant violation", evidence_ref=evidence_ref)
    else:
        fs.set_gate("reproducer", S.PENDING,
                    note=f"reproduction {status}: {detail}",
                    evidence_ref=evidence_ref)
