"""Deep Hunt Phase 4 - prioritized bounded state exploration
(src/nextgen/deephunt/stateexplorer.py, spec sections 9, 21).

Pure: no Foundry needed for planning / ranking / minimize logic.

Run:  python -m pytest tests/test_nextgen_deephunt_stateexplorer.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen.deephunt import invariants as INV  # noqa: E402
from src.nextgen.deephunt import llm_hypotheses as LLM  # noqa: E402
from src.nextgen.deephunt import protocolmodel as PM  # noqa: E402
from src.nextgen.deephunt import stateexplorer as SE  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")


LENDING = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IOracle { function latestAnswer() external view returns (uint256); }
contract Pool {
    IOracle public oracle;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalDebt;
    function deposit() external payable { collateral[msg.sender] += msg.value; }
    function _price() internal view returns (uint256) { return oracle.latestAnswer(); }
    function borrow(uint256 amount) external {
        uint256 max = (collateral[msg.sender] * _price()) / 1e18;
        require(debt[msg.sender] + amount <= max, "ltv");
        debt[msg.sender] += amount; totalDebt += amount;
        payable(msg.sender).transfer(amount);
    }
    function repay() external payable { debt[msg.sender] -= msg.value; totalDebt -= msg.value; }
    function name() external pure returns (string memory) { return "Pool"; }
}
"""


@pytest.fixture(scope="module")
def scene():
    m = PM.build_from_sources(LENDING, target="Pool")
    assert m.compiled, m.reason
    invs = INV.discover(m)
    return m, invs


def test_rank_targets_is_deterministic_and_prioritised(scene):
    m, invs = scene
    a = SE.rank_targets(m, invs)
    b = SE.rank_targets(m, invs)
    assert [t.as_dict() for t in a] == [t.as_dict() for t in b]
    assert a, "expected exploration targets"
    ranked = [t.function for t in a]
    # a value-moving / oracle-priced entry must outrank the trivial view fn
    assert "borrow" in ranked
    assert "name" not in ranked or ranked.index("borrow") < ranked.index("name")
    assert a[0].priority >= a[-1].priority


def test_plan_sequences_targets_the_objective_and_is_bounded(scene):
    m, invs = scene
    seqs = SE.plan_sequences(m, invs, budget=10)
    assert 0 < len(seqs) <= 10
    for s in seqs:
        assert s.steps[-1].function in {t.function for t in SE.rank_targets(m, invs)}
        assert s.objective.get("type") in INV.RECIPE_TYPES
    # at least one multi-step sequence (a setup prefix was found)
    assert any(len(s.steps) >= 2 for s in seqs)
    # deposit is a natural setup prefix for borrow
    borrow_seqs = [s for s in seqs if s.steps[-1].function == "borrow"]
    assert any("deposit" in [st.function for st in s.steps] for s in borrow_seqs)


def test_default_args_maps_types(scene):
    m, _invs = scene
    fm = m.function("Pool", "borrow")
    assert SE._default_args(fm) == "1000000000000000000"
    assert SE._default_args(m.function("Pool", "name")) == ""


def test_minimize_keeps_the_objective_step(scene):
    m, invs = scene
    seqs = SE.plan_sequences(m, invs, budget=10)
    multi = next(s for s in seqs if len(s.steps) >= 2)
    obj = multi.steps[-1]
    # a verifier that only accepts sequences still ending in the objective
    got = SE.minimize(multi, lambda s: s.steps[-1].function == obj.function)
    assert got.steps[-1].function == obj.function
    assert len(got.steps) == 1                     # everything else droppable


def test_llm_hook_gated(monkeypatch, scene):
    m, invs = scene
    monkeypatch.setattr(LLM, "available", lambda: False)
    before = SE.plan_sequences(m, invs, budget=30, use_llm=False)
    after = SE.plan_sequences(m, invs, budget=30, use_llm=True)
    assert [s.as_dict() for s in before] == [s.as_dict() for s in after]


def test_uncompiled_model_plans_nothing():
    m = PM.build_from_sources("garbage")
    assert SE.plan_sequences(m, []) == []
    assert SE.rank_targets(m, []) == []


def test_summarize_safe_on_empty():
    assert "no sequences planned" in SE.summarize([])
