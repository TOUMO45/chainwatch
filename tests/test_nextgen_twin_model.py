"""Counterfactual Twin - data model (src/nextgen/twin/model.py).

Pure. Pins the small derived properties Phase 3/4 rely on.

Run:  python -m pytest tests/test_nextgen_twin_model.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.twin import model as M  # noqa: E402


def _tx(h="0x" + "a" * 64, block=100, idx=0, sender="0x" + "1" * 40,
        to="0x" + "d" * 40, value=0, selector="0x12345678", status=True):
    return M.TxRecord(hash=h, block=block, tx_index=idx, sender=sender, to=to,
                      value=value, input=selector + "00" * 32, selector=selector,
                      status=status)


def test_tracecall_flatten_is_depth_first():
    root = M.TraceCall("a", "b", "CALL", "0x", depth=0)
    c1 = M.TraceCall("b", "c", "CALL", "0x", depth=1)
    c2 = M.TraceCall("b", "d", "STATICCALL", "0x", depth=1)
    c1.children.append(M.TraceCall("c", "e", "DELEGATECALL", "0x", depth=2))
    root.children += [c1, c2]
    flat = root.flatten()
    assert [n.to for n in flat] == ["b", "c", "e", "d"]


def test_trace_external_calls_dedupes_and_skips_depth0():
    root = M.TraceCall("eoa", "vault", "CALL", "0xaabbccdd", depth=0)
    root.children.append(M.TraceCall("vault", "oracle", "STATICCALL", "0x50d25bcd11", depth=1))
    root.children.append(M.TraceCall("vault", "oracle", "STATICCALL", "0x50d25bcd11", depth=1))
    tr = M.Trace(tx=_tx(), call_tree=root)
    assert tr.external_calls() == [("oracle", "0x50d25bcd")]


def test_collection_upgrades_detects_impl_changes():
    col = M.Collection(address="0xp", chain_id=1, from_block=1, to_block=100)
    col.impl_samples = [(1, "0xaaa"), (25, "0xaaa"), (50, "0xbbb"),
                        (75, "0xbbb"), (100, "0xccc")]
    assert col.upgrades == [(50, "0xbbb"), (100, "0xccc")]


def test_fingerprint_revert_rate_and_exclusive_callers():
    fp = M.FunctionFingerprint(address="0xd", selector="0x1")
    fp.n_total, fp.n_success, fp.n_revert = 10, 8, 2
    fp.callers_success = {"0xowner"}
    fp.callers_revert = {"0xattacker"}
    assert fp.revert_rate == 0.2
    assert fp.caller_exclusive == {"0xowner"}


def test_exclusive_callers_none_when_caller_set_large_or_unrestricted():
    fp = M.FunctionFingerprint(address="0xd", selector="0x1")
    fp.callers_success = {f"0x{i:040x}" for i in range(9)}
    assert fp.caller_exclusive is None
    fp2 = M.FunctionFingerprint(address="0xd", selector="0x2")
    fp2.callers_success = {"0xa"}
    fp2.callers_revert = {"0xa"}
    fp2.n_revert = 1
    assert fp2.caller_exclusive is None       # same address also reverts -> not a boundary


def test_boundary_rejects_unknown_kind():
    with pytest.raises(ValueError):
        M.Boundary(kind="WISHFUL", statement="x")
    b = M.Boundary(kind=M.AUTHORIZATION, statement="only owner")
    assert b.usable is False
    b.status = M.VALIDATED
    assert b.usable is True


def test_records_are_json_safe():
    import json
    col = M.Collection(address="0xp", chain_id=1, from_block=1, to_block=9)
    col.txs = [_tx()]
    col.transfers = [M.TransferEvent("0xt", M.ERC20, "0xa", "0xb", 5, tx_hash="0xh")]
    json.dumps(col.as_dict())
    json.dumps(M.Trace(tx=_tx()).as_dict())
    json.dumps(M.FunctionFingerprint(address="0xd", selector="0x1").as_dict())
