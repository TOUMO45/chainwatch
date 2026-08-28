"""Counterfactual Twin - Phase 5 counterfactual mutations (src/nextgen/twin/mutate.py).

Run:  python -m pytest tests/test_nextgen_twin_mutate.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.twin import mutate as MU, model as M  # noqa: E402
from src.nextgen.twin.rpc import EIP1967_ADMIN  # noqa: E402


def _tx(sender="0x" + "1" * 40, selector="0x12345678", value=0,
       input_words=1, block=100) -> M.TxRecord:
    # a non-zero, non-boundary trailing word so BOUNDARY_VALUE's "skip if
    # already equal to the target" check does not silently drop a case here
    word = "00" * 31 + "2a"
    data = selector + word * input_words
    return M.TxRecord(hash="0x" + "a" * 64, block=block, tx_index=0, sender=sender,
                      to="0x" + "d" * 40, value=value, input=data, selector=selector,
                      status=True)


def test_actor_substitution_swaps_the_sender_only():
    tx = _tx()
    out = MU._actor_substitution(tx, near=False)
    assert len(out) == 1
    m = out[0]
    assert m.calls[0]["from"] == MU._UNPRIVILEGED
    assert m.calls[0]["to"] == tx.to
    assert m.calls[0]["data"] == tx.input


def test_actor_substitution_skipped_when_sender_already_is_the_probe():
    tx = _tx(sender=MU._UNPRIVILEGED)
    assert MU._actor_substitution(tx, near=False) == []


def test_boundary_value_mutates_trailing_word_only():
    tx = _tx(input_words=1)
    out = MU._boundary_value(tx, [], near=False)
    assert len(out) == 3      # zero, max, one
    for m in out:
        assert m.calls[0]["data"].startswith(tx.input[:10])
        assert m.calls[0]["data"] != tx.input


def test_boundary_value_skipped_for_calldata_too_short():
    tx = _tx()
    tx.input = tx.selector      # no trailing word at all
    assert MU._boundary_value(tx, [], near=False) == []


def test_repetition_calls_twice_same_sender():
    tx = _tx()
    out = MU._repetition(tx, near=False)
    assert len(out) == 1
    assert len(out[0].calls) == 2
    assert out[0].calls[0] == out[0].calls[1]


def test_reorder_needs_a_related_tx():
    tx = _tx(block=100)
    assert MU._reorder(tx, [], near=False) == []
    other = _tx(block=99)
    other.hash = "0x" + "b" * 64
    out = MU._reorder(tx, [other], near=False)
    assert len(out) == 1
    assert out[0].detail["other_tx"] == other.hash


def test_delay_carries_a_positive_second_count():
    tx = _tx()
    out = MU._delay(tx, near=False)
    assert out[0].detail["delay_seconds"] > 0


def test_callback_insert_needs_external_calls_in_the_trace():
    tx = _tx()
    assert MU._callback_insert(tx, None, near=False) == []
    empty_trace = M.Trace(tx=tx, call_tree=None)
    assert MU._callback_insert(tx, empty_trace, near=False) == []
    root = M.TraceCall(tx.sender, tx.to, "CALL", tx.input, depth=0)
    root.children.append(M.TraceCall(tx.to, "0x" + "e" * 40, "CALL", "0xabcdef00", depth=1))
    trace = M.Trace(tx=tx, call_tree=root)
    out = MU._callback_insert(tx, trace, near=False)
    assert len(out) == 1 and len(out[0].calls) == 2


def test_state_timing_only_for_replay_protection_boundary_on_same_selector():
    tx = _tx()
    b_wrong_kind = M.Boundary(kind=M.CONSERVATION, statement="x", selector=tx.selector,
                              detail={"slot": "0xslot"})
    assert MU._state_timing(tx, [b_wrong_kind], near=False) == []
    b = M.Boundary(kind=M.REPLAY_PROTECTION, statement="x", selector=tx.selector,
                   detail={"slot": "0xslot"})
    out = MU._state_timing(tx, [b], near=False)
    assert len(out) == 1
    assert out[0].state_overrides == {tx.to: {"0xslot": "0x" + "0" * 64}}


def test_oracle_state_only_for_oracle_freshness_boundary():
    tx = _tx()
    b = M.Boundary(kind=M.ORACLE_FRESHNESS, statement="x", selector=tx.selector,
                   detail={"oracle_like_targets": ["0xfeed:0x50d25bcd"]})
    out = MU._oracle_state(tx, [b], near=False)
    assert len(out) == 1
    assert out[0].detail["delay_seconds"] == 86400 * 7


def test_permission_change_targets_eip1967_admin_slot():
    tx = _tx()
    out = MU._permission_change(tx, [], near=False)
    assert len(out) == 1
    assert EIP1967_ADMIN in out[0].state_overrides[tx.to]
    assert out[0].calls[0]["from"] == MU._UNPRIVILEGED


def test_cross_contract_variation_needs_an_external_call_target():
    tx = _tx()
    assert MU._cross_contract_variation(tx, None, near=False) == []
    root = M.TraceCall(tx.sender, tx.to, "CALL", tx.input, depth=0)
    root.children.append(M.TraceCall(tx.to, "0x" + "f" * 40, "CALL", "0x11223344", depth=1))
    trace = M.Trace(tx=tx, call_tree=root)
    out = MU._cross_contract_variation(tx, trace, near=False)
    assert len(out) == 1
    assert out[0].detail["dependency"] == "0x" + "f" * 40


def test_near_change_doubles_weight():
    tx = _tx()
    far = MU._actor_substitution(tx, near=False)[0]
    near = MU._actor_substitution(tx, near=True)[0]
    assert near.weight == far.weight * 2


def test_generate_mutations_runs_every_kind_without_raising():
    tx = _tx()
    out = MU.generate_mutations(tx, trace=None, ctx=None, changed_selectors=None)
    assert isinstance(out, list)
    kinds = {m.kind for m in out}
    # at minimum the trace-independent, boundary-independent kinds always fire
    assert M.ACTOR_SUBSTITUTION in kinds
    assert M.BOUNDARY_VALUE in kinds
    assert M.REPETITION in kinds
    assert M.DELAY in kinds
    assert M.PERMISSION_CHANGE in kinds


def test_summarize_orders_by_weight_descending():
    tx = _tx()
    out = MU.generate_mutations(tx, trace=None)
    text = MU.summarize(out)
    assert "COUNTERFACTUAL MUTATIONS" in text
