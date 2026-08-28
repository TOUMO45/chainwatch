"""Phase 0 - the next-gen finding state machine (src/nextgen/state.py, spec §17/§24).

Fast - pure data, no git, no compile, no chain. These pin the one decision the
module makes: gates -> (fine state, coarse verdict). The whole false-positive
defence of the next-gen pipeline rests on "the easiest outcome is REJECT and
CONFIRMED is hard", so it must not drift.

Run:  python -m pytest tests/test_nextgen_state.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import state as S  # noqa: E402


def _all(result: str) -> dict:
    return {g.name: result for g in S.GATES}


# --------------------------------------------------------------------------- #
# classify() - the mechanical verdict
# --------------------------------------------------------------------------- #

def test_all_gates_pass_is_confirmed():
    fine, verdict, reasons = S.classify(_all(S.PASS))
    assert fine == S.CONFIRMED
    assert verdict == S.VERDICT_CONFIRMED


def test_one_pending_gate_is_unknown_not_rejected():
    gates = _all(S.PASS)
    gates["reproducer"] = S.PENDING
    fine, verdict, reasons = S.classify(gates)
    assert verdict == S.VERDICT_UNKNOWN
    assert fine == S.UNKNOWN
    assert any("reproducer" in r for r in reasons)


def test_one_gate_unknown_is_unknown():
    gates = _all(S.PASS)
    gates["independent_validation"] = S.GATE_UNKNOWN
    _, verdict, _ = S.classify(gates)
    assert verdict == S.VERDICT_UNKNOWN


def test_a_single_fail_beats_everything_else_passing():
    gates = _all(S.PASS)
    gates["no_compensating_control"] = S.FAIL
    fine, verdict, reasons = S.classify(gates)
    assert verdict == S.VERDICT_REJECTED
    assert fine == S.FALSE_POSITIVE
    assert any("no_compensating_control" in r for r in reasons)


def test_fail_takes_priority_over_unknown():
    gates = _all(S.GATE_UNKNOWN)
    gates["bytecode_provenance"] = S.FAIL
    fine, verdict, _ = S.classify(gates)
    assert verdict == S.VERDICT_REJECTED
    assert fine == S.DEPLOYMENT_MISMATCH   # bytecode_provenance.on_fail


def test_first_failing_gate_in_evidence_order_names_the_state():
    gates = _all(S.PASS)
    # reachable_path is earlier in GATES than not_duplicate
    gates["reachable_path"] = S.FAIL
    gates["not_duplicate"] = S.FAIL
    fine, verdict, reasons = S.classify(gates)
    assert verdict == S.VERDICT_REJECTED
    assert fine == S.UNREACHABLE
    # both failures still reported
    assert sum("FAILED" in r for r in reasons) == 2


def test_default_gate_state_is_pending_so_a_bare_finding_is_unknown():
    fs = S.FindingState("f1")
    assert fs.verdict() == S.VERDICT_UNKNOWN
    assert all(v == S.PENDING for v in fs.gates.values())


def test_skipped_blocking_gate_yields_unknown_not_confirmed():
    gates = _all(S.PASS)
    gates["bytecode_provenance"] = S.SKIPPED   # e.g. no address supplied
    gates["target_live"] = S.SKIPPED
    _, verdict, _ = S.classify(gates)
    assert verdict == S.VERDICT_UNKNOWN


def test_skipped_is_pass_only_for_na_is_pass_gates():
    spec = S.GATE_BY_NAME["economically_feasible"]
    assert spec.na_is_pass is True
    gates = _all(S.PASS)
    gates["economically_feasible"] = S.SKIPPED   # not a value finding
    _, verdict, _ = S.classify(gates)
    assert verdict == S.VERDICT_CONFIRMED


def test_economically_infeasible_is_a_rejection_not_unknown():
    gates = _all(S.PASS)
    gates["economically_feasible"] = S.FAIL
    fine, verdict, _ = S.classify(gates)
    assert verdict == S.VERDICT_REJECTED
    assert fine == S.ECONOMICALLY_INFEASIBLE


# --------------------------------------------------------------------------- #
# transitions - append-only, monotone
# --------------------------------------------------------------------------- #

def test_forward_transition_records_history_and_evidence_ref():
    fs = S.FindingState("f1")
    fs.advance(S.HYPOTHESIS, note="llm proposed", evidence_ref="hyp-1")
    fs.advance(S.STATICALLY_SUPPORTED, evidence_ref="commit-abc")
    assert fs.state == S.STATICALLY_SUPPORTED
    assert fs.history[-1].evidence_ref == "commit-abc"
    assert fs.history[-1].frm == S.HYPOTHESIS


def test_backward_transition_raises():
    fs = S.FindingState("f1")
    fs.advance(S.STATICALLY_SUPPORTED)
    with pytest.raises(S.IllegalTransition):
        fs.advance(S.HYPOTHESIS)


def test_cannot_advance_out_of_a_terminal_state():
    fs = S.FindingState("f1")
    fs.reject(S.PATCHED, note="already fixed upstream")
    with pytest.raises(S.IllegalTransition):
        fs.advance(S.HYPOTHESIS)
    with pytest.raises(S.IllegalTransition):
        fs.to_unknown()


def test_reject_requires_a_real_rejection_state():
    fs = S.FindingState("f1")
    with pytest.raises(S.IllegalTransition):
        fs.reject("NOT_A_STATE")
    with pytest.raises(S.IllegalTransition):
        fs.reject(S.CONFIRMED)   # not a rejection


def test_to_unknown_is_terminal():
    fs = S.FindingState("f1")
    fs.to_unknown(note="no address, cannot verify deployment")
    assert fs.state == S.UNKNOWN
    with pytest.raises(S.IllegalTransition):
        fs.advance(S.HYPOTHESIS)


def test_set_gate_rejects_unknown_gate_and_bad_result():
    fs = S.FindingState("f1")
    with pytest.raises(KeyError):
        fs.set_gate("no_such_gate", S.PASS)
    with pytest.raises(ValueError):
        fs.set_gate("reproducer", "MAYBE")


def test_set_gate_is_logged_in_history():
    fs = S.FindingState("f1")
    fs.set_gate("regression_commit", S.PASS, note="8f72a9c", evidence_ref="c-1")
    last = fs.history[-1]
    assert "gate regression_commit=PASS" in last.note
    assert last.evidence_ref == "c-1"


# --------------------------------------------------------------------------- #
# derived views
# --------------------------------------------------------------------------- #

def test_derive_pipeline_state_tracks_passed_gates():
    gates = {g.name: S.PENDING for g in S.GATES}
    assert S.derive_pipeline_state(gates) == S.DISCOVERED
    gates["regression_commit"] = S.PASS
    assert S.derive_pipeline_state(gates) == S.STATICALLY_SUPPORTED
    gates["reachable_path"] = S.PASS
    assert S.derive_pipeline_state(gates) == S.REACHABILITY_TESTED


def test_derive_pipeline_state_is_confirmed_only_when_verdict_is():
    gates = {g.name: S.PASS for g in S.GATES}
    assert S.derive_pipeline_state(gates) == S.CONFIRMED
    gates["reproducer"] = S.PENDING
    assert S.derive_pipeline_state(gates) != S.CONFIRMED


def test_as_dict_round_trips_the_essentials():
    fs = S.FindingState("f1")
    fs.advance(S.HYPOTHESIS)
    fs.set_gate("regression_commit", S.PASS)
    d = fs.as_dict()
    assert d["finding_id"] == "f1"
    assert d["state"] == S.HYPOTHESIS
    assert d["verdict"] == S.VERDICT_UNKNOWN
    assert d["gates"]["regression_commit"] == S.PASS
    assert isinstance(d["history"], list) and d["history"]


def test_gate_specs_cover_the_spec_chain_and_map_to_rejections():
    # every gate's on_fail is a real rejection state (spec §17)
    for g in S.GATES:
        assert g.on_fail in S.REJECTIONS
    # the five spec §16 hard-gate concepts are all represented
    names = {g.name for g in S.GATES}
    for required in ("reproducer", "reachable_path", "bytecode_provenance",
                     "no_compensating_control", "independent_validation"):
        assert required in names
