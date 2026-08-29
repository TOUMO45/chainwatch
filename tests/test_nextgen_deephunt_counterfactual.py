"""Deep Hunt Phase 7 - counterfactual sequence mutation
(src/nextgen/deephunt/counterfactual.py, spec section 10).

Pure: no Foundry needed - mutations are just variant CandidateSequences.

Run:  python -m pytest tests/test_nextgen_deephunt_counterfactual.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen.deephunt import counterfactual as CF  # noqa: E402
from src.nextgen.deephunt import invariants as INV  # noqa: E402
from src.nextgen.deephunt import protocolmodel as PM  # noqa: E402
from src.nextgen.deephunt import stateexplorer as SE  # noqa: E402
from src.nextgen.execground.sequences import CandidateSequence, TxStep  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")


ORACLE_POOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }
contract Pool {
    IPair public pair;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalDebt;
    function deposit() external payable { collateral[msg.sender] += msg.value; }
    function _p() internal view returns (uint256) {
        (uint112 a, uint112 b,) = pair.getReserves(); return uint256(b) * 1e18 / uint256(a);
    }
    function borrow(uint256 amount) external {
        require(debt[msg.sender] + amount <= collateral[msg.sender] * _p() / 1e18, "ltv");
        debt[msg.sender] += amount; totalDebt += amount;
        payable(msg.sender).transfer(amount);
    }
}
"""


@pytest.fixture(scope="module")
def scene():
    m = PM.build_from_sources(ORACLE_POOL, target="Pool")
    assert m.compiled, m.reason
    invs = INV.discover(m)
    seqs = SE.plan_sequences(m, invs, budget=12)
    return m, invs, seqs


def test_basic_mutations_present(scene):
    m, invs, seqs = scene
    borrow_seq = next(s for s in seqs if s.steps[-1].function == "borrow")
    muts = CF.mutate_sequence(borrow_seq, m, invs)
    kinds = {mm.kind for mm in muts}
    assert {CF.M_ACTOR, CF.M_AMOUNT, CF.M_REPETITION, CF.M_AUTH} <= kinds
    for mm in muts:
        assert mm.kind in CF.MUTATION_KINDS
        assert mm.sequence.steps[-1].function == "borrow"


def test_amount_mutation_sweeps_boundaries(scene):
    m, invs, seqs = scene
    borrow_seq = next(s for s in seqs if s.steps[-1].function == "borrow")
    muts = CF.mutate_sequence(borrow_seq, m, invs)
    amt = [mm for mm in muts if mm.kind == CF.M_AMOUNT]
    got_args = {mm.sequence.steps[-1].args for mm in amt}
    assert "0" in got_args and "1" in got_args
    assert CF._MAX_U256 in got_args


def test_actor_mutation_preserves_all_other_fields(scene):
    m, invs, seqs = scene
    borrow_seq = next(s for s in seqs if s.steps[-1].function == "borrow")
    muts = CF.mutate_sequence(borrow_seq, m, invs)
    actor = next(mm for mm in muts if mm.kind == CF.M_ACTOR)
    orig, new = borrow_seq.steps[-1], actor.sequence.steps[-1]
    assert new.caller == "victim"
    assert (new.contract, new.function, new.signature, new.args, new.value_wei) \
        == (orig.contract, orig.function, orig.signature, orig.args, orig.value_wei)
    # setup steps untouched
    assert actor.sequence.steps[:-1] == borrow_seq.steps[:-1]


def test_oracle_relevant_mutations_fire_with_timing_and_manipulation(scene):
    m, invs, seqs = scene
    borrow_seq = next(s for s in seqs if s.steps[-1].function == "borrow")
    ltv_inv = next((i for i in invs if i.source == INV.SRC_DEBT_LTV), None) \
        or next((i for i in invs if i.source == INV.SRC_ORACLE), None)
    muts = CF.mutate_sequence(borrow_seq, m, invs, target_invariant=ltv_inv)
    timing = next(mm for mm in muts if mm.kind == CF.M_TIMING)
    oracle = next(mm for mm in muts if mm.kind == CF.M_ORACLE)
    assert timing.sequence.objective.get("warp_seconds") == 86_400
    assert "flash swap" in oracle.sequence.objective.get("oracle_manipulation", "")


def test_reorder_only_when_three_steps():
    one = CandidateSequence([TxStep("C", "f", "f()", "attacker", "")],
                            {"type": INV.OBJ_CALL_SUCCEEDS}, "")
    assert not [mm for mm in CF.mutate_sequence(one, PM.ProtocolModel(compiled=True),
                                                []) if mm.kind == CF.M_REORDER]
    three = CandidateSequence(
        [TxStep("C", "a", "a()", "attacker", "", must_succeed=True),
         TxStep("C", "b", "b()", "attacker", "", must_succeed=True),
         TxStep("C", "f", "f()", "attacker", "")],
        {"type": INV.OBJ_CALL_SUCCEEDS}, "")
    reordered = [mm for mm in CF.mutate_sequence(three, PM.ProtocolModel(compiled=True), [])
                 if mm.kind == CF.M_REORDER]
    assert reordered and reordered[0].sequence.steps[0].function == "b"


def test_weight_bump_on_invariant_var_overlap(scene):
    m, invs, seqs = scene
    borrow_seq = next(s for s in seqs if s.steps[-1].function == "borrow")
    # borrow writes `debt` / `totalDebt`; craft an invariant naming those
    inv = next(i for i in invs if "debt" in " ".join(i.variables).lower()
               or i.source == INV.SRC_DEBT_LTV)
    muts = CF.mutate_sequence(borrow_seq, m, invs, target_invariant=inv)
    assert any(mm.weight == 2.0 and mm.touched_invariant == inv.id for mm in muts)
    # sorted heaviest first
    assert muts == sorted(muts, key=lambda mm: (-mm.weight, mm.kind))


def test_mutate_all_dedupes_and_bounds(scene):
    m, invs, seqs = scene
    muts = CF.mutate_all(seqs, m, invs, budget=15)
    assert len(muts) <= 15
    keys = [(mm.kind, tuple((s.function, s.args, s.caller) for s in mm.sequence.steps),
             repr(sorted((mm.sequence.objective or {}).items(), key=lambda kv: str(kv[0]))))
            for mm in muts]
    assert len(keys) == len(set(keys))


def test_empty_sequence_yields_nothing():
    assert CF.mutate_sequence(CandidateSequence([], {}, ""), None, []) == []


def test_summarize_safe():
    assert "none" in CF.summarize([]).lower()
