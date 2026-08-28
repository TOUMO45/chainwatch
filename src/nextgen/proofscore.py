"""The proof-quality score (spec §16) - AND the hard gates it may never override.

The score is a deterministic tally that describes how much evidence a candidate
has accumulated. It is a *communication* device: "+95, missing only the
independent validator" is easier to read at a glance than a gate table. It is
NOT a decision device.

    THE SCORE CANNOT PROMOTE A FINDING.

`state.classify()` owns the verdict. A +120 score with a failed hard gate is
still not CONFIRMED - `permits_confirmed` returns False - and this module exists
partly to make that impossible to forget: the score and the gate check live in
one place and the score function refuses to imply a verdict.

Positive and negative weights are copied verbatim from spec §16. The hard gates
are copied verbatim from spec §16's "Define hard gates" block.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import state as S

# --------------------------------------------------------------------------- #
# Spec §16 weight table. `key` is a signal the caller sets True/False/None.
#   True  -> the points apply
#   False -> for a NEGATIVE row, the penalty applies; for a POSITIVE row, 0
#   None  -> not yet determined, contributes 0 and is listed as "open"
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Weight:
    key: str
    points: int
    label: str


POSITIVE: tuple[Weight, ...] = (
    Weight("regression_commit_identified", +20, "regression commit identified"),
    Weight("security_invariant_identified", +15, "security invariant identified"),
    Weight("path_proven_reachable", +15, "vulnerable path proven reachable"),
    Weight("fork_reproducer_succeeds", +15, "local fork reproducer succeeds"),
    Weight("invariant_violation_observed", +10, "invariant violation observed"),
    Weight("deployed_bytecode_matches", +10, "deployed bytecode matches"),
    Weight("attacker_is_unprivileged", +5, "attacker is unprivileged"),
    Weight("economic_exploitability_proven", +5, "economic exploitability proven"),
    Weight("independent_validator_agrees", +5, "independent validator agrees"),
)

NEGATIVE: tuple[Weight, ...] = (
    Weight("unreachable_path", -30, "unreachable path"),
    Weight("compensating_control_exists", -30, "compensating control exists"),
    Weight("deployment_mismatch", -30, "deployment mismatch"),
    Weight("impossible_state", -20, "impossible state"),
    Weight("invalid_build_reproduction", -20, "invalid compiler/build reproduction"),
    Weight("duplicate_or_known", -20, "duplicate / known finding"),
)

ALL_WEIGHTS: tuple[Weight, ...] = POSITIVE + NEGATIVE
_WEIGHT_BY_KEY = {w.key: w for w in ALL_WEIGHTS}

# --------------------------------------------------------------------------- #
# Spec §16 hard gates. Each maps a signal state to the reason CONFIRMED is
# blocked. A gate "fails" when its predicate below is True.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class HardGate:
    name: str
    reason: str                     # shown when it blocks
    # which signal(s), and the value that trips the gate
    trips_when: tuple[tuple[str, object], ...]


HARD_GATES: tuple[HardGate, ...] = (
    HardGate("reproducer_required", "no reproducer -> NOT CONFIRMED",
             (("fork_reproducer_succeeds", False), ("fork_reproducer_succeeds", None))),
    HardGate("reachable_path_required", "no reachable attack path -> NOT CONFIRMED",
             (("path_proven_reachable", False), ("path_proven_reachable", None),
              ("unreachable_path", True))),
    HardGate("no_deployment_mismatch", "deployment mismatch -> NOT LIVE",
             (("deployment_mismatch", True),)),
    HardGate("no_compensating_control", "compensating control exists -> REJECT",
             (("compensating_control_exists", True),)),
    HardGate("independent_validation_required",
             "independent validation failure -> NOT CONFIRMED",
             (("independent_validator_agrees", False),
              ("independent_validator_agrees", None))),
)


@dataclass
class ProofScore:
    total: int
    breakdown: list[tuple[str, int]] = field(default_factory=list)
    open_signals: list[str] = field(default_factory=list)
    hard_gate_failures: list[str] = field(default_factory=list)

    @property
    def permits_confirmed(self) -> bool:
        """False whenever ANY hard gate fails, regardless of `total`.

        This is the property that makes the score safe to publish next to a
        verdict: a reader cannot infer CONFIRMED from a high number, because a
        high number with `permits_confirmed == False` is a normal, expected
        state (e.g. "+90, but no address so no reproducer")."""
        return not self.hard_gate_failures

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "breakdown": [{"signal": k, "points": p} for k, p in self.breakdown],
            "open_signals": list(self.open_signals),
            "hard_gate_failures": list(self.hard_gate_failures),
            "permits_confirmed": self.permits_confirmed,
            "note": ("the score is advisory; state.classify() decides the "
                     "verdict and the score can never lift a REJECT or UNKNOWN"),
        }


def score(signals: dict[str, Optional[bool]]) -> ProofScore:
    """Tally spec §16 and evaluate the hard gates.

    `signals` maps a weight/gate key to True / False / None. Unknown keys are
    ignored (a later phase may add signals; an old caller must not break).
    """
    total = 0
    breakdown: list[tuple[str, int]] = []
    open_signals: list[str] = []

    for w in ALL_WEIGHTS:
        v = signals.get(w.key, None)
        if v is None:
            open_signals.append(w.key)
            continue
        # A positive row scores when its signal is True. A negative row (the
        # key names the bad condition, e.g. `unreachable_path`) penalises when
        # its signal is True. Either way: the points apply iff `v is True`.
        if v is True:
            total += w.points
            breakdown.append((w.key, w.points))

    failures: list[str] = []
    for g in HARD_GATES:
        for key, trip_val in g.trips_when:
            if signals.get(key, None) == trip_val:
                failures.append(g.reason)
                break

    return ProofScore(total=total, breakdown=breakdown,
                      open_signals=open_signals, hard_gate_failures=failures)


# --------------------------------------------------------------------------- #
# Bridge: derive the §16 signal dict from a `state.FindingState`'s gates, so the
# two representations cannot drift. The score is then purely a view of the
# gates that `state.classify` already read.
# --------------------------------------------------------------------------- #

_GATE_TO_POSITIVE: dict[str, str] = {
    "regression_commit": "regression_commit_identified",
    "security_invariant": "security_invariant_identified",
    "reachable_path": "path_proven_reachable",
    "reproducer": "fork_reproducer_succeeds",
    "invariant_violated": "invariant_violation_observed",
    "bytecode_provenance": "deployed_bytecode_matches",
    "independent_validation": "independent_validator_agrees",
    "economically_feasible": "economic_exploitability_proven",
}


def signals_from_gates(gates: dict[str, str],
                       extra: Optional[dict[str, Optional[bool]]] = None
                       ) -> dict[str, Optional[bool]]:
    """Translate gate results into §16 signals.

    PASS -> True, FAIL -> False, anything else (UNKNOWN/PENDING/SKIPPED) -> None.
    `extra` lets a caller add signals the gate model does not carry
    (`attacker_is_unprivileged`, `duplicate_or_known`, ...).
    """
    def tri(name: str) -> Optional[bool]:
        r = gates.get(name)
        if r == S.PASS:
            return True
        if r == S.FAIL:
            return False
        return None

    out: dict[str, Optional[bool]] = {}
    for gate_name, sig in _GATE_TO_POSITIVE.items():
        out[sig] = tri(gate_name)

    # Negative signals derived from a FAILED gate.
    out["unreachable_path"] = (gates.get("reachable_path") == S.FAIL) or None
    out["compensating_control_exists"] = (
        gates.get("no_compensating_control") == S.FAIL) or None
    out["deployment_mismatch"] = (
        gates.get("bytecode_provenance") == S.FAIL) or None
    out["impossible_state"] = (gates.get("state_reachable") == S.FAIL) or None
    out["duplicate_or_known"] = (gates.get("not_duplicate") == S.FAIL) or None

    if extra:
        out.update(extra)
    return out
