"""Counterfactual Twin - Phase 7 violation checks (src/nextgen/twin/checks.py).

Pure - synthetic ReplayResult/Mutation/Boundary/Trace objects, no network.

Run:  python -m pytest tests/test_nextgen_twin_checks.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.twin import checks as CH, model as M  # noqa: E402

_SENDER = "0x2222222222222222222222222222222222222222"
_TARGET = "0x" + "d" * 40


def _tx(status=True, to=_TARGET, sender=_SENDER) -> M.TxRecord:
    return M.TxRecord(hash="0x" + "b" * 64, block=100, tx_index=0, sender=sender,
                      to=to, value=0, input="0x12345678", selector="0x12345678",
                      status=status)


def _rr(mutation, *, executed=True, status=True, before=None, after=None
       ) -> M.ReplayResult:
    trace = M.Trace(tx=_tx(status=status), source="anvil-reexec")
    return M.ReplayResult(mutation=mutation, executed=executed, trace=trace,
                          all_traces=[trace],
                          balances_before=before or {}, balances_after=after or {})


def _mut(kind, calls=None, detail=None) -> M.Mutation:
    return M.Mutation(kind=kind, base_tx="0x" + "b" * 64, selector="0x12345678",
                      statement="s", calls=calls or [{"from": _SENDER, "to": _TARGET,
                                                      "value": 0, "data": "0x12345678"}],
                      detail=detail or {})


def test_no_violation_when_replay_did_not_execute():
    mut = _mut(M.ACTOR_SUBSTITUTION)
    rr = _rr(mut, executed=False)
    assert CH.check_violations(None, rr, []) == []


def test_authorization_bypass_when_unauthorized_caller_succeeds():
    mut = _mut(M.ACTOR_SUBSTITUTION)
    rr = _rr(mut, status=True)
    b = M.Boundary(kind=M.AUTHORIZATION, statement="only owner", selector="0x12345678",
                   status=M.TESTED, detail={"callers": ["0xowner"]})
    out = CH._authorization_bypass(mut, rr, [b], succeeded=True)
    assert len(out) == 1 and out[0].kind == M.V_UNAUTHORIZED_TRANSITION


def test_no_authorization_bypass_when_probe_address_is_already_authorized():
    mut = _mut(M.ACTOR_SUBSTITUTION,
              calls=[{"from": _SENDER, "to": _TARGET, "value": 0, "data": "0x1"}])
    rr = _rr(mut, status=True)
    b = M.Boundary(kind=M.AUTHORIZATION, statement="x", selector="0x12345678",
                   status=M.TESTED, detail={"callers": [_SENDER]})
    assert CH._authorization_bypass(mut, rr, [b], succeeded=True) == []


def test_no_authorization_bypass_when_call_reverted():
    mut = _mut(M.ACTOR_SUBSTITUTION)
    b = M.Boundary(kind=M.AUTHORIZATION, statement="x", selector="0x12345678",
                   status=M.TESTED, detail={"callers": ["0xowner"]})
    assert CH._authorization_bypass(mut, _rr(mut), [b], succeeded=False) == []


def test_balance_gain_flags_net_positive_ether_gain():
    mut = _mut(M.ACTOR_SUBSTITUTION)
    rr = _rr(mut, before={_SENDER: 100}, after={_SENDER: 1000})
    out = CH._balance_gain(mut, rr, succeeded=True)
    assert len(out) == 1 and out[0].evidence["gain_wei"] == 900


def test_balance_gain_absent_when_balance_did_not_increase():
    mut = _mut(M.ACTOR_SUBSTITUTION)
    rr = _rr(mut, before={_SENDER: 1000}, after={_SENDER: 900})
    assert CH._balance_gain(mut, rr, succeeded=True) == []


def test_balance_gain_only_applies_to_attack_shaped_mutations():
    mut = _mut(M.REPETITION)      # not in _ATTACK_SHAPED
    rr = _rr(mut, before={_SENDER: 100}, after={_SENDER: 1000})
    assert CH._balance_gain(mut, rr, succeeded=True) == []


def test_protocol_loss_flags_target_balance_drop():
    mut = _mut(M.PERMISSION_CHANGE)
    rr = _rr(mut, before={_TARGET: 10 ** 18}, after={_TARGET: 0})
    out = CH._protocol_loss(mut, rr, baseline=None, succeeded=True)
    assert len(out) == 1 and out[0].evidence["loss_wei"] == 10 ** 18


def test_protocol_loss_absent_when_target_had_no_balance():
    mut = _mut(M.PERMISSION_CHANGE)
    rr = _rr(mut, before={_TARGET: 0}, after={_TARGET: 0})
    assert CH._protocol_loss(mut, rr, baseline=None, succeeded=True) == []


def test_protocol_loss_absent_when_target_is_also_the_sender():
    """A genuine self-call transaction (from == to) has its balance
    pre-funded by replay()'s own synthetic BIG_BALANCE before sampling -
    the resulting drop is ordinary gas cost against a fake baseline, not a
    real loss. Measured directly against a real Uniswap V3 pool interaction
    (a self-calling router tx) before this guard existed: 651330042304960
    wei of pure gas cost against a 10**24-wei synthetic balance read as a
    false UNEXPECTED_PROTOCOL_LOSS."""
    self_addr = "0xe7d0dc39f2aad5ec69fe784b683ddd9941a6f724"
    mut = _mut(M.BOUNDARY_VALUE,
              calls=[{"from": self_addr, "to": self_addr, "value": 0,
                     "data": "0x12345678"}])
    rr = _rr(mut, before={self_addr: 10 ** 24},
            after={self_addr: 10 ** 24 - 651330042304960})
    assert CH._protocol_loss(mut, rr, baseline=None, succeeded=True) == []


def test_unexpected_success_needs_a_tested_boundary_of_the_right_kind():
    mut = _mut(M.BOUNDARY_VALUE)
    rr = _rr(mut, status=True)
    inferred_only = [M.Boundary(kind=M.STATE_MACHINE, statement="x",
                                selector="0x12345678", status=M.INFERRED)]
    assert CH._unexpected_success(mut, rr, inferred_only, succeeded=True) == []
    tested = [M.Boundary(kind=M.STATE_MACHINE, statement="x", selector="0x12345678",
                         status=M.TESTED)]
    out = CH._unexpected_success(mut, rr, tested, succeeded=True)
    assert len(out) == 1 and out[0].kind == M.V_UNEXPECTED_SUCCESS


def test_replay_bypass_only_for_state_timing_against_replay_protection():
    mut = _mut(M.STATE_TIMING, detail={"slot": "0xslot"})
    rr = _rr(mut, status=True)
    b = M.Boundary(kind=M.REPLAY_PROTECTION, statement="x", selector="0x12345678",
                   detail={"slot": "0xslot"})
    out = CH._replay_bypass(mut, rr, [b], succeeded=True)
    assert len(out) == 1 and out[0].kind == M.V_REVERT_BYPASS


def test_replay_bypass_absent_for_other_mutation_kinds():
    mut = _mut(M.ACTOR_SUBSTITUTION)
    b = M.Boundary(kind=M.REPLAY_PROTECTION, statement="x", selector="0x12345678",
                   detail={"slot": "0xslot"})
    assert CH._replay_bypass(mut, _rr(mut), [b], succeeded=True) == []


def test_check_violations_aggregates_multiple_sub_checks():
    mut = _mut(M.ACTOR_SUBSTITUTION)
    rr = _rr(mut, status=True, before={_SENDER: 0, _TARGET: 10 ** 18},
            after={_SENDER: 10 ** 17, _TARGET: 9 * 10 ** 17})
    bounds = [M.Boundary(kind=M.AUTHORIZATION, statement="x", selector="0x12345678",
                         status=M.TESTED, detail={"callers": ["0xowner"]})]
    out = CH.check_violations(None, rr, bounds)
    kinds = {v.kind for v in out}
    assert M.V_UNAUTHORIZED_TRANSITION in kinds
    assert M.V_BALANCE_GAIN in kinds
    assert M.V_PROTOCOL_LOSS in kinds


def test_summarize_reports_none_found_when_empty():
    assert "none" in CH.summarize([])
