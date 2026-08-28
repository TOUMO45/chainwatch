"""The Skeptic (spec §7) - an independent, deterministic rejection sweep.

The Skeptic assumes the candidate is FALSE and tries to destroy the claim. It
does not re-use the Hunter's conclusions; it re-derives, with opposite intent,
from the same analyzer outputs. Every check has one of three outcomes:

    DISPROVED       the Skeptic found a concrete reason the candidate is not a
                    finding  -> the mapped gate is FAILED  -> classify() rejects
    NOT_DISPROVED   the Skeptic tried and could not disprove it
    INAPPLICABLE    no input for this check on this candidate

The Skeptic never PASSES a gate. "Failed to disprove" is not proof - it only
lets the positive evidence stand. `independent_validation` reaches PASS only
when the Skeptic sweep is clean AND the (Phase 5) blinded Reproducer agrees.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .. import state as S

DISPROVED = "DISPROVED"
NOT_DISPROVED = "NOT_DISPROVED"
INAPPLICABLE = "INAPPLICABLE"

# check name -> the gate a DISPROVED outcome fails
_GATE_FOR = {
    "compensating_control": "no_compensating_control",
    "deployment_relevance": "target_live",
    "bytecode_provenance": "bytecode_provenance",
    "build_environment": "build_environment",
    "path_reachability": "reachable_path",
    "live_regression": "regression_commit",
    "state_possible": "state_reachable",
    "not_duplicate": "not_duplicate",
    "economic_feasibility": "economically_feasible",
}


@dataclass
class Challenge:
    name: str
    outcome: str
    detail: str = ""

    @property
    def gate(self) -> Optional[str]:
        return _GATE_FOR.get(self.name)

    def as_dict(self) -> dict:
        return {"name": self.name, "outcome": self.outcome,
                "detail": self.detail, "gate": self.gate}


@dataclass
class SkepticReport:
    challenges: list[Challenge] = field(default_factory=list)

    @property
    def disproved(self) -> bool:
        return any(c.outcome == DISPROVED for c in self.challenges)

    @property
    def ran(self) -> list[Challenge]:
        return [c for c in self.challenges if c.outcome != INAPPLICABLE]

    def as_dict(self) -> dict:
        return {"disproved": self.disproved,
                "ran": len(self.ran),
                "challenges": [c.as_dict() for c in self.challenges]}

    def render_text(self) -> str:
        lines = ["SKEPTIC SWEEP (spec §7)", "=" * 22, ""]
        for c in self.challenges:
            lines.append(f"  [{c.outcome:<13}] {c.name}"
                         + (f"  - {c.detail}" if c.detail else ""))
        lines.append("")
        lines.append("  VERDICT: "
                     + ("candidate DISPROVED" if self.disproved
                        else f"failed to disprove ({len(self.ran)} check(s) ran)"))
        return "\n".join(lines)


def _gate_outcome(gate_val: Optional[str], *, fail_is_disproof: bool = True
                  ) -> tuple[str, str]:
    if gate_val == S.FAIL:
        return (DISPROVED, "the check's gate FAILED") if fail_is_disproof else (
            NOT_DISPROVED, "gate failed but not treated as disproof")
    if gate_val in (S.PASS, S.GATE_UNKNOWN, S.PENDING, S.SKIPPED, None):
        return NOT_DISPROVED, f"gate={gate_val}"
    return NOT_DISPROVED, f"gate={gate_val}"


def sweep(*, compensating_report=None, deployment_facts=None,
          provenance_chain=None, buildenv_report=None, attack_paths=None,
          timeline=None, corpus_duplicate: Optional[bool] = None,
          economic_infeasible: Optional[bool] = None,
          state_impossible: Optional[bool] = None) -> SkepticReport:
    """Every argument is optional; an absent one yields INAPPLICABLE."""
    rep = SkepticReport()

    def add(name, outcome, detail=""):
        rep.challenges.append(Challenge(name, outcome, detail))

    # 1. compensating control (§11)
    if compensating_report is not None:
        g = getattr(compensating_report, "gate", None)
        if g == S.FAIL:
            add("compensating_control", DISPROVED,
                getattr(compensating_report, "rationale", "an equivalent "
                        "mechanism replaces the removed guard"))
        else:
            add("compensating_control", NOT_DISPROVED,
                "no compensating control found")
    else:
        add("compensating_control", INAPPLICABLE)

    # 2. deployment relevance (§10)
    if deployment_facts is not None:
        g = getattr(deployment_facts, "gate", None)
        if g == S.FAIL:
            add("deployment_relevance", DISPROVED,
                getattr(deployment_facts, "rationale", "the vulnerable code is "
                        "not what is deployed"))
        else:
            add("deployment_relevance", NOT_DISPROVED,
                getattr(deployment_facts, "rationale", ""))
    else:
        add("deployment_relevance", INAPPLICABLE)

    # 3. bytecode provenance (§9)
    if provenance_chain is not None:
        g = getattr(provenance_chain, "gate", None)
        if g == S.FAIL:
            add("bytecode_provenance", DISPROVED,
                getattr(provenance_chain, "rationale", "on-chain bytecode does "
                        "not match the vulnerable build"))
        else:
            add("bytecode_provenance", NOT_DISPROVED, "")
    else:
        add("bytecode_provenance", INAPPLICABLE)

    # 4. build environment (§19)
    if buildenv_report is not None:
        g = getattr(buildenv_report, "gate", None)
        if g == S.FAIL:
            add("build_environment", DISPROVED,
                getattr(buildenv_report, "rationale", "a blocking build-env "
                        "risk invalidates the analysis"))
        else:
            add("build_environment", NOT_DISPROVED, "")
    else:
        add("build_environment", INAPPLICABLE)

    # 5. path reachability (§4)
    if attack_paths is not None:
        unpriv = [p for p in attack_paths if getattr(p, "unprivileged", False)]
        if not unpriv:
            add("path_reachability", DISPROVED,
                "no unprivileged path reaches the sink"
                if not attack_paths else
                "the sink is reachable only by a trusted role")
        else:
            add("path_reachability", NOT_DISPROVED,
                f"{len(unpriv)} unprivileged path(s)")
    else:
        add("path_reachability", INAPPLICABLE)

    # 6. live regression (§1)
    if timeline is not None:
        cur = getattr(timeline, "current_state", None)
        if cur == "PRESENT":
            add("live_regression", DISPROVED,
                "the security property is in force at HEAD - no live regression")
        elif cur == "ABSENT":
            add("live_regression", NOT_DISPROVED,
                "the property is absent at HEAD")
        else:
            add("live_regression", NOT_DISPROVED, f"timeline state {cur}")
    else:
        add("live_regression", INAPPLICABLE)

    # 7. state possible (§5 - Phase 5 usually)
    if state_impossible is not None:
        add("state_possible", DISPROVED if state_impossible else NOT_DISPROVED,
            "the required state cannot exist" if state_impossible else "")
    else:
        add("state_possible", INAPPLICABLE)

    # 8. duplicate / known issue (corpus)
    if corpus_duplicate is not None:
        add("not_duplicate", DISPROVED if corpus_duplicate else NOT_DISPROVED,
            "this exact finding is already recorded" if corpus_duplicate else "")
    else:
        add("not_duplicate", INAPPLICABLE)

    # 9. economic feasibility (§14 - Phase 5)
    if economic_infeasible is not None:
        add("economic_feasibility",
            DISPROVED if economic_infeasible else NOT_DISPROVED,
            "the attack is not economically worthwhile" if economic_infeasible
            else "")
    else:
        add("economic_feasibility", INAPPLICABLE)

    return rep
