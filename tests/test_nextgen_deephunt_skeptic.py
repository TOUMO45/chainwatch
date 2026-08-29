"""Deep Hunt Phase 8 - the Skeptic extended for live findings
(src/nextgen/deephunt/skeptic.py, spec section 16).

Run:  python -m pytest tests/test_nextgen_deephunt_skeptic.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen import state as S  # noqa: E402
from src.nextgen.adversarial import skeptic as SK  # noqa: E402
from src.nextgen.deephunt import assetflow as AF  # noqa: E402
from src.nextgen.deephunt import invariants as INV  # noqa: E402
from src.nextgen.deephunt import protocolmodel as PM  # noqa: E402
from src.nextgen.deephunt import skeptic as DHS  # noqa: E402
from src.nextgen.execground.sequences import CandidateSequence, TxStep  # noqa: E402
from src.nextgen.invariants import model as IM  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")


GUARDED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Bank {
    address public owner;
    uint256 public rate;
    mapping(address => uint256) public bal;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
    function setRate(uint256 r) external onlyOwner { rate = r; }
    function withdraw(uint256 a) external { bal[msg.sender] -= a; payable(msg.sender).transfer(a); }
}
"""


@pytest.fixture(scope="module")
def model():
    m = PM.build_from_sources(GUARDED, target="Bank")
    assert m.compiled, m.reason
    return m


def _seq(*steps):
    return CandidateSequence(list(steps), {"type": INV.OBJ_CALL_SUCCEEDS}, "")


def test_base_sweep_is_still_run():
    class _Comp:
        gate = S.FAIL
        rationale = "a renamed modifier still checks msg.sender"
    rep = DHS.sweep(base={"compensating_report": _Comp()})
    names = {c.name for c in rep.challenges}
    assert "compensating_control" in names          # shared check ran
    assert rep.disproved is True


def test_actor_unprivileged_disproved_when_sequence_needs_a_guarded_step(model):
    seq = _seq(
        TxStep("Bank", "setRate", "setRate(uint256)", "attacker", "1", must_succeed=True),
        TxStep("Bank", "withdraw", "withdraw(uint256)", "attacker", "1"))
    rep = DHS.sweep(model=model, sequence=seq)
    c = next(c for c in rep.challenges if c.name == "dh_actor_unprivileged")
    assert c.outcome == DHS.DISPROVED
    assert "setRate" in c.detail


def test_actor_unprivileged_ok_when_all_steps_open(model):
    seq = _seq(TxStep("Bank", "withdraw", "withdraw(uint256)", "attacker", "1"))
    rep = DHS.sweep(model=model, sequence=seq)
    c = next(c for c in rep.challenges if c.name == "dh_actor_unprivileged")
    assert c.outcome == DHS.NOT_DISPROVED


def test_entitlement_disproves_a_legitimate_withdrawal():
    E = 10 ** 18
    flow = AF.from_balances(
        {(AF.ATTACKER, AF.ETH): 10 * E, (AF.PROTOCOL, AF.ETH): 1000 * E},
        {(AF.ATTACKER, AF.ETH): 10 * E, (AF.PROTOCOL, AF.ETH): 1000 * E})
    rep = DHS.sweep(asset_flow=flow, deposits=[(AF.ETH, 5 * E)])
    c = next(c for c in rep.challenges if c.name == "dh_entitlement")
    assert c.outcome == DHS.DISPROVED


def test_unrelated_manipulation_disproved_when_dep_out_of_scope():
    inv = IM.CandidateInvariant(
        id="x", kind=IM.PROTOCOL, statement="oracle", source=INV.SRC_ORACLE,
        contract="C", functions=("mint",),
        predicate={"test_recipe": {"type": INV.OBJ_ORACLE,
                                   "oracle_hint": "getAdminPrice"}})
    rep = DHS.sweep(invariant=inv, out_of_scope_deps=("getAdminPrice",))
    c = next(c for c in rep.challenges if c.name == "dh_unrelated_manipulation")
    assert c.outcome == DHS.DISPROVED


def test_invariant_applies_disproved_when_rejected():
    inv = IM.CandidateInvariant(id="y", kind=IM.ACCESS_CONTROL, statement="z",
                                source=INV.SRC_AUTH_REACH, contract="C",
                                functions=("f",))
    inv.reject("no unguarded writer after all")
    rep = DHS.sweep(invariant=inv)
    c = next(c for c in rep.challenges if c.name == "dh_invariant_applies")
    assert c.outcome == DHS.DISPROVED


def test_apply_fails_gates_and_independent_validation():
    fs = S.FindingState("cand")
    rep = SK.SkepticReport()
    rep.challenges.append(SK.Challenge("dh_actor_unprivileged", DHS.DISPROVED, "needs setRate"))
    DHS.apply(fs, rep)
    assert fs.gates["reachable_path"] == S.FAIL
    assert fs.gates["independent_validation"] == S.FAIL
    state, verdict, _ = S.classify(fs.gates)
    assert verdict == S.VERDICT_REJECTED


def test_apply_clean_sweep_with_reproducer_passes_independent_validation():
    fs = S.FindingState("cand")
    fs.set_gate("reproducer", S.PASS, note="reproduced")
    rep = SK.SkepticReport()
    for i in range(4):
        rep.challenges.append(SK.Challenge(f"chk{i}", DHS.NOT_DISPROVED))
    DHS.apply(fs, rep)
    assert fs.gates["independent_validation"] == S.PASS


def test_apply_clean_sweep_without_reproducer_is_unknown():
    fs = S.FindingState("cand")
    rep = SK.SkepticReport()
    for i in range(4):
        rep.challenges.append(SK.Challenge(f"chk{i}", DHS.NOT_DISPROVED))
    DHS.apply(fs, rep)
    assert fs.gates["independent_validation"] == S.GATE_UNKNOWN
