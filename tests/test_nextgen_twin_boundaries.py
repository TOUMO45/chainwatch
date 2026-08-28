"""Counterfactual Twin - Phase 3 boundary mining (src/nextgen/twin/boundaries.py).

Pure, synthetic fingerprints/traces - no network, no fork.

Run:  python -m pytest tests/test_nextgen_twin_boundaries.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.twin import boundaries as B, model as M  # noqa: E402


def _fp(sel="0x11111111", n_success=0, n_revert=0, callers_success=None,
        callers_revert=None, transfers_in=0, transfers_out=0,
        storage_slots=None, external_targets=None) -> M.FunctionFingerprint:
    fp = M.FunctionFingerprint(address="0xdead", selector=sel)
    fp.n_total = n_success + n_revert
    fp.n_success, fp.n_revert = n_success, n_revert
    fp.callers_success = set(callers_success or [])
    fp.callers_revert = set(callers_revert or [])
    fp.transfers_in, fp.transfers_out = transfers_in, transfers_out
    fp.storage_slots_written = set(storage_slots or [])
    fp.external_call_targets = set(external_targets or [])
    fp.example_success = [f"0x{i:064x}" for i in range(n_success)][:5]
    fp.example_revert = [f"0x{i+50:064x}" for i in range(n_revert)][:5]
    return fp


def test_authorization_mined_from_exclusive_callers():
    fp = _fp(n_success=4, callers_success=["0xowner"])
    out = B._mine_authorization({"0x11111111": fp})
    assert len(out) == 1
    b = out[0]
    assert b.kind == M.AUTHORIZATION
    assert b.status == M.TESTED           # n_success >= _MIN_SAMPLES
    assert b.detail["callers"] == ["0xowner"]


def test_authorization_not_mined_without_exclusive_callers():
    fp = _fp(n_success=4, callers_success=[f"0x{i:040x}" for i in range(9)])
    assert B._mine_authorization({"0x1": fp}) == []


def test_conservation_flags_one_sided_flow():
    fp = _fp(n_success=3, transfers_out=3, transfers_in=0)
    out = B._mine_conservation({"0x1": fp}, transfers=[])
    assert len(out) == 1 and out[0].kind == M.CONSERVATION
    assert out[0].detail["one_sided"] is True


def test_conservation_skips_functions_that_never_move_tokens():
    fp = _fp(n_success=5)
    assert B._mine_conservation({"0x1": fp}, transfers=[]) == []


def test_accounting_needs_both_storage_and_transfer():
    fp_both = _fp(n_success=3, transfers_out=3, storage_slots=["0xslot1"])
    fp_storage_only = _fp(n_success=3, storage_slots=["0xslot1"])
    out = B._mine_accounting({"a": fp_both, "b": fp_storage_only}, traces={})
    assert len(out) == 1
    assert out[0].kind == M.ACCOUNTING


def test_governance_needs_shared_exclusive_caller_across_multiple_selectors():
    fp1 = _fp(sel="0x1", n_success=3, callers_success=["0xmultisig"])
    fp2 = _fp(sel="0x2", n_success=3, callers_success=["0xmultisig"])
    fp_alone = _fp(sel="0x3", n_success=3, callers_success=["0xowner"])
    out = B._mine_governance({"0x1": fp1, "0x2": fp2, "0x3": fp_alone})
    assert len(out) == 1
    assert sorted(out[0].detail["selectors"]) == ["0x1", "0x2"]


def test_governance_absent_for_a_single_gated_selector():
    fp = _fp(n_success=3, callers_success=["0xowner"])
    assert B._mine_governance({"0x1": fp}) == []


def test_state_machine_needs_shared_caller_on_both_sides_and_no_exclusivity():
    fp = _fp(n_success=3, n_revert=3, callers_success={"0xa"}, callers_revert={"0xa"})
    out = B._mine_state_machine({"0x1": fp}, traces={})
    assert len(out) == 1 and out[0].kind == M.STATE_MACHINE


def test_state_machine_skips_when_authorization_already_explains_it():
    fp = _fp(n_success=3, n_revert=3, callers_success={"0xowner"},
            callers_revert={"0xattacker"})
    assert B._mine_state_machine({"0x1": fp}, traces={}) == []


def test_oracle_freshness_mined_from_chainlink_shaped_external_call():
    fp = _fp(n_success=2, external_targets={("0xfeed", "0x50d25bcd")})
    out = B._mine_oracle_freshness({"0x1": fp}, traces={})
    assert len(out) == 1 and out[0].kind == M.ORACLE_FRESHNESS
    assert out[0].status == M.INFERRED    # never TESTED - staleness itself unobservable


def test_collateral_vs_withdrawal_classification():
    withdraw_only = _fp(n_success=3, transfers_out=3)
    collateral = _fp(n_success=3, transfers_out=3, transfers_in=3)
    out = B._mine_collateral_withdrawal({"w": withdraw_only, "c": collateral})
    kinds = {b.selector: b.kind for b in out}
    # selectors collide (both default "0x11111111") in this helper's shape,
    # so assert on the returned kinds set instead of per-selector lookup.
    assert {b.kind for b in out} == {M.WITHDRAWAL, M.COLLATERAL}


def test_mine_boundaries_runs_every_miner_without_raising_on_empty_input():
    assert B.mine_boundaries({}, [], {}) == []


def test_summarize_is_readable_and_groups_by_kind():
    fp = _fp(n_success=4, callers_success=["0xowner"])
    out = B.mine_boundaries({"0x11111111": fp}, [], {})
    text = B.summarize(out)
    assert "AUTHORIZATION" in text
    assert "TESTED" in text
