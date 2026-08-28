"""Phase 0 - the proof-quality score and its hard gates (src/nextgen/proofscore.py, spec §16).

Fast - pure arithmetic. The single most important property here: a big score
never implies CONFIRMED. `permits_confirmed` is driven by the hard gates alone.

Run:  python -m pytest tests/test_nextgen_proofscore.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import proofscore as P  # noqa: E402
from src.nextgen import state as S  # noqa: E402


def _full_positive() -> dict:
    return {
        "regression_commit_identified": True,
        "security_invariant_identified": True,
        "path_proven_reachable": True,
        "fork_reproducer_succeeds": True,
        "invariant_violation_observed": True,
        "deployed_bytecode_matches": True,
        "attacker_is_unprivileged": True,
        "economic_exploitability_proven": True,
        "independent_validator_agrees": True,
    }


def test_full_positive_totals_the_spec_table():
    s = P.score(_full_positive())
    # 20+15+15+15+10+10+5+5+5
    assert s.total == 100
    assert s.permits_confirmed is True
    assert s.hard_gate_failures == []


def test_negative_signals_subtract():
    sig = _full_positive()
    sig["duplicate_or_known"] = True          # -20
    sig["invalid_build_reproduction"] = True  # -20
    s = P.score(sig)
    assert s.total == 60


def test_open_signal_is_listed_not_scored():
    sig = _full_positive()
    sig["independent_validator_agrees"] = None
    s = P.score(sig)
    assert "independent_validator_agrees" in s.open_signals
    assert s.total == 95


# --------------------------------------------------------------------------- #
# the point of the module: score cannot override a hard gate
# --------------------------------------------------------------------------- #

def test_high_score_with_missing_reproducer_does_not_permit_confirmed():
    sig = _full_positive()
    sig["fork_reproducer_succeeds"] = None    # not run
    s = P.score(sig)
    assert s.total == 85
    assert s.permits_confirmed is False
    assert any("reproducer" in r for r in s.hard_gate_failures)


def test_reproducer_explicitly_failed_also_blocks():
    sig = _full_positive()
    sig["fork_reproducer_succeeds"] = False
    s = P.score(sig)
    assert s.permits_confirmed is False


def test_unreachable_path_blocks_even_at_high_score():
    sig = _full_positive()
    sig["unreachable_path"] = True
    s = P.score(sig)
    assert s.permits_confirmed is False
    assert any("reachable" in r for r in s.hard_gate_failures)


def test_deployment_mismatch_blocks():
    sig = _full_positive()
    sig["deployment_mismatch"] = True
    assert P.score(sig).permits_confirmed is False


def test_compensating_control_blocks():
    sig = _full_positive()
    sig["compensating_control_exists"] = True
    assert P.score(sig).permits_confirmed is False


def test_independent_validation_missing_blocks():
    sig = _full_positive()
    sig["independent_validator_agrees"] = None
    assert P.score(sig).permits_confirmed is False


def test_as_dict_carries_the_disclaimer_and_gate_state():
    d = P.score(_full_positive()).as_dict()
    assert d["permits_confirmed"] is True
    assert "advisory" in d["note"]
    assert d["total"] == 100


def test_unknown_signal_keys_are_ignored_for_forward_compat():
    sig = _full_positive()
    sig["some_future_signal_phase_9"] = True
    s = P.score(sig)          # must not raise
    assert s.total == 100


# --------------------------------------------------------------------------- #
# bridge: gates -> signals stays consistent with state.classify
# --------------------------------------------------------------------------- #

def test_signals_from_gates_maps_pass_fail_and_unresolved():
    gates = {g.name: S.PASS for g in S.GATES}
    gates["reproducer"] = S.PENDING
    gates["no_compensating_control"] = S.FAIL
    sig = P.signals_from_gates(gates)
    assert sig["fork_reproducer_succeeds"] is None
    assert sig["compensating_control_exists"] is True
    assert sig["regression_commit_identified"] is True


def test_confirmed_gates_produce_a_score_that_permits_confirmed():
    gates = {g.name: S.PASS for g in S.GATES}
    fine, verdict, _ = S.classify(gates)
    sig = P.signals_from_gates(gates, extra={"attacker_is_unprivileged": True})
    s = P.score(sig)
    assert verdict == S.VERDICT_CONFIRMED
    assert s.permits_confirmed is True


def test_unknown_verdict_produces_a_score_that_forbids_confirmed():
    gates = {g.name: S.PASS for g in S.GATES}
    gates["independent_validation"] = S.GATE_UNKNOWN
    fine, verdict, _ = S.classify(gates)
    s = P.score(P.signals_from_gates(gates))
    assert verdict == S.VERDICT_UNKNOWN
    assert s.permits_confirmed is False
