"""Deep Hunt Phase 6 - the Historical Behaviour Engine
(src/nextgen/deephunt/behavior.py, spec sections 6, 7, 8).

`contrast` / `_revert_boundaries` / `priority_bumps` are pure and tested with
synthetic fingerprints. `learn` is RPC-gated; the no-RPC path is asserted here.

Run:  python -m pytest tests/test_nextgen_deephunt_behavior.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen.deephunt import behavior as BH  # noqa: E402
from src.nextgen.deephunt import invariants as INV  # noqa: E402
from src.nextgen.deephunt import protocolmodel as PM  # noqa: E402
from src.nextgen.twin import model as TM  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")


TOKEN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;
    constructor() { owner = msg.sender; }
    // open: no caller-identity guard, moves supply -> risk
    function distribute(address to, uint256 amt) external {
        balanceOf[to] += amt; totalSupply += amt;
    }
    function transfer(address to, uint256 amt) external {
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt;
    }
}
"""


@pytest.fixture(scope="module")
def model():
    m = PM.build_from_sources(TOKEN, target="T")
    assert m.compiled, m.reason
    return m


def _fp(selector, *, n_total, n_success, n_revert, callers_success=()):
    fp = TM.FunctionFingerprint(address="0xdead", selector=selector)
    fp.n_total, fp.n_success, fp.n_revert = n_total, n_success, n_revert
    fp.callers_success = set(callers_success)
    return fp


def test_no_rpc_learn_degrades():
    lb = BH.learn("0xabc", "", from_block=1, to_block=2)
    assert lb.available is False
    assert "RPC" in lb.reason
    assert BH.contrast(None, [], lb) == []


def test_revert_boundaries_filters():
    fps = {
        "0xaaaaaaaa": _fp("0xaaaaaaaa", n_total=10, n_success=2, n_revert=8),
        "0xbbbbbbbb": _fp("0xbbbbbbbb", n_total=20, n_success=19, n_revert=1),
    }
    rb = BH._revert_boundaries(fps)
    assert [s for s, _r, _n in rb] == ["0xaaaaaaaa"]


def test_contrast_flags_historically_restricted_open_function(model):
    dist = model.function("T", "distribute")
    assert dist is not None and dist.access_controlled is False
    # history: distribute() only ever succeeded for one caller
    fp = _fp(dist.selector, n_total=40, n_success=40, n_revert=0,
             callers_success=["0x1111111111111111111111111111111111111111"])
    b = TM.Boundary(kind=TM.AUTHORIZATION,
                    statement="only 0x1111... ever called distribute() successfully",
                    selector=dist.selector, status=TM.TESTED)
    lb = BH.LearnedBehavior(address="0xdead", available=True,
                            fingerprints={dist.selector: fp}, boundaries=[b])
    sigs = BH.contrast(model, INV.discover(model), lb)
    kinds = {s.kind for s in sigs}
    assert BH.HISTORICALLY_RESTRICTED_NOW_OPEN in kinds
    hit = next(s for s in sigs if s.kind == BH.HISTORICALLY_RESTRICTED_NOW_OPEN)
    assert hit.function == "T.distribute" and hit.priority_bump >= 3


def test_contrast_flags_never_exercised_entry_point(model):
    dist = model.function("T", "distribute")
    lb = BH.LearnedBehavior(address="0xdead", available=True,
                            fingerprints={}, boundaries=[])   # nothing called
    sigs = BH.contrast(model, INV.discover(model), lb)
    ne = [s for s in sigs if s.kind == BH.NEVER_EXERCISED]
    assert any(s.function == "T.distribute" for s in ne)


def test_priority_bumps_accumulate():
    sigs = [BH.BehaviorSignal(BH.DEFENSIVE_LIMIT, "0xabcd1234", "T.f", "x", 1),
            BH.BehaviorSignal(BH.NEVER_EXERCISED, "0xabcd1234", "T.f", "y", 2)]
    assert BH.priority_bumps(sigs) == {"0xabcd1234": 3}


def test_summarize_handles_unavailable():
    lb = BH.LearnedBehavior(address="0xabc", available=False, reason="no RPC")
    assert "not available" in BH.summarize(lb, [])
