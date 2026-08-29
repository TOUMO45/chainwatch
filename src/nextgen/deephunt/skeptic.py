"""Phase 8 - the Skeptic, extended for LIVE findings (spec section 16).

The Deep Hunt Skeptic does NOT rewrite `adversarial/skeptic.py` (the Twin and
the regression pipeline depend on it unchanged). It:

  * runs the existing `adversarial.skeptic.sweep(...)` for every shared check it
    can feed (compensating control, deployment relevance, bytecode provenance,
    economic feasibility, duplicate);
  * appends its own LIVE-hunt challenges, each of which tries to DESTROY the
    candidate from a fresh angle (spec section 16's questions):

      dh_actor_unprivileged   - is the "unprivileged" path secretly a
                                role-holder-only step?
      dh_state_realistic      - would a setup step itself revert for the attacker?
      dh_entitlement          - is the apparent profit a legitimate entitlement?
      dh_unrelated_manipulation - does it need manipulating an out-of-scope
                                external protocol?
      dh_invariant_applies    - did the threatened invariant survive validation?

`apply(fs, report)` folds a DISPROVED challenge into the mapped gate (and a
DISPROVED of ANY kind fails `independent_validation`). It never PASSES a gate on
its own - a clean sweep only lets positive evidence stand, and
`independent_validation` reaches PASS only when the sweep is clean over enough
checks AND the blinded Reproducer already agrees (mirrors
`gates.apply_skeptic`).
"""

from __future__ import annotations

from typing import Optional

from .. import state as S
from ..adversarial import skeptic as SK
from . import assetflow as AF
from . import invariants as INV

DISPROVED = SK.DISPROVED
NOT_DISPROVED = SK.NOT_DISPROVED
INAPPLICABLE = SK.INAPPLICABLE

# deep-hunt challenge name -> the gate a DISPROVED outcome fails
EXTRA_GATE_FOR = {
    "dh_actor_unprivileged": "reachable_path",
    "dh_state_realistic": "state_reachable",
    "dh_entitlement": "invariant_violated",
    "dh_unrelated_manipulation": "state_reachable",
    "dh_invariant_applies": "security_invariant",
}

_MIN_CHECKS = 3


def sweep(*, base: Optional[dict] = None, model=None, invariant=None,
          sequence=None, asset_flow: Optional[AF.AssetFlow] = None,
          deposits: Optional[list] = None,
          unreachable_setup: Optional[bool] = None,
          out_of_scope_deps: tuple[str, ...] = ()) -> SK.SkepticReport:
    """`base` is forwarded verbatim to `adversarial.skeptic.sweep`. The rest
    drive the deep-hunt challenges; an absent input yields INAPPLICABLE."""
    rep = SK.sweep(**(base or {}))

    def add(name: str, outcome: str, detail: str = "") -> None:
        rep.challenges.append(SK.Challenge(name, outcome, detail))

    # 1. actor really unprivileged?
    if sequence is not None and model is not None and getattr(model, "compiled", False):
        guarded_steps = []
        for st in getattr(sequence, "steps", []):
            fm = model.function(st.contract, st.function)
            if fm is not None and fm.access_controlled and st.caller == "attacker":
                guarded_steps.append(f"{st.contract}.{st.function}")
        if guarded_steps:
            add("dh_actor_unprivileged", DISPROVED,
                f"the sequence needs {guarded_steps} - a caller-identity-gated "
                f"step the attacker cannot perform")
        else:
            add("dh_actor_unprivileged", NOT_DISPROVED,
                "every step is callable without a role")
    else:
        add("dh_actor_unprivileged", INAPPLICABLE)

    # 2. is the required state realistic?
    if unreachable_setup is not None:
        add("dh_state_realistic",
            DISPROVED if unreachable_setup else NOT_DISPROVED,
            "a setup step reverts for the attacker - the precondition is "
            "unreachable" if unreachable_setup else
            "setup steps execute for the attacker")
    else:
        add("dh_state_realistic", INAPPLICABLE)

    # 3. is the apparent gain a legitimate entitlement?
    if asset_flow is not None:
        unearned, why = AF.is_unearned_extraction(asset_flow, deposits or [])
        if not unearned:
            add("dh_entitlement", DISPROVED,
                f"the apparent gain is not unearned extraction: {why}")
        else:
            add("dh_entitlement", NOT_DISPROVED, why)
    else:
        add("dh_entitlement", INAPPLICABLE)

    # 4. does it need manipulating an unrelated / out-of-scope protocol?
    recipe = ((invariant.predicate or {}).get("test_recipe", {})
              if invariant is not None else {})
    hint = str(recipe.get("oracle_hint", "")).lower()
    needs_manip = bool(recipe.get("oracle_manipulation")) or hint
    if needs_manip and out_of_scope_deps:
        if any(d.lower() in hint or hint in d.lower() for d in out_of_scope_deps):
            add("dh_unrelated_manipulation", DISPROVED,
                f"the attack requires manipulating {hint!r}, which is declared "
                f"out of scope / not attacker-manipulable")
        else:
            add("dh_unrelated_manipulation", NOT_DISPROVED,
                "the manipulated dependency is an in-scope liquid market")
    elif needs_manip:
        add("dh_unrelated_manipulation", NOT_DISPROVED,
            "spot-price manipulation of the priced pair is in scope")
    else:
        add("dh_unrelated_manipulation", INAPPLICABLE)

    # 5. did the threatened invariant survive validation?
    if invariant is not None:
        st = getattr(invariant, "status", "")
        if st == INV.IM.REJECTED:
            add("dh_invariant_applies", DISPROVED,
                f"the threatened invariant was REJECTED in validation: "
                f"{getattr(invariant, 'contradiction', '') or 'no reason recorded'}")
        elif st == INV.IM.INFERRED and getattr(invariant, "contradiction", ""):
            add("dh_invariant_applies", NOT_DISPROVED,
                f"invariant still only INFERRED, with a noted contradiction: "
                f"{invariant.contradiction}")
        else:
            add("dh_invariant_applies", NOT_DISPROVED,
                f"invariant status {st or 'unknown'}")
    else:
        add("dh_invariant_applies", INAPPLICABLE)

    return rep


def apply(fs: S.FindingState, report: SK.SkepticReport, *,
          evidence_ref: Optional[str] = None) -> None:
    """Fold a (base + deep-hunt) Skeptic sweep into the gates.

    A DISPROVED challenge FAILs its mapped gate - from `SK._GATE_FOR` for the
    shared checks, `EXTRA_GATE_FOR` for the deep-hunt ones. Any DISPROVED at all
    FAILs `independent_validation`. A clean sweep over >= 3 checks with the
    blinded reproducer already PASS -> `independent_validation` PASS; clean but
    no reproducer yet -> UNKNOWN.
    """
    gate_for = {**SK._GATE_FOR, **EXTRA_GATE_FOR}
    for c in report.challenges:
        if c.outcome == SK.DISPROVED:
            g = gate_for.get(c.name)
            if g:
                fs.set_gate(g, S.FAIL, note=f"Skeptic: {c.detail or c.name}",
                            evidence_ref=evidence_ref)

    ran = len(report.ran)
    if report.disproved:
        fs.set_gate("independent_validation", S.FAIL,
                    note="Skeptic disproved the candidate",
                    evidence_ref=evidence_ref)
    elif ran >= _MIN_CHECKS and fs.gates.get("reproducer") == S.PASS:
        fs.set_gate("independent_validation", S.PASS,
                    note=f"Skeptic sweep clean over {ran} checks; blinded "
                         f"reproducer agrees", evidence_ref=evidence_ref)
    elif ran >= _MIN_CHECKS:
        fs.set_gate("independent_validation", S.GATE_UNKNOWN,
                    note=f"Skeptic sweep clean over {ran} checks; awaiting "
                         f"independent reproduction")
    else:
        fs.set_gate("independent_validation", S.GATE_UNKNOWN,
                    note=f"insufficient Skeptic coverage: only {ran} check(s)")


def summarize(report: SK.SkepticReport) -> str:
    return report.render_text()
