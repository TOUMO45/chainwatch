"""Deep Hunt Phase 10 - orchestrator + finding taxonomy + live gate profile
(src/nextgen/deephunt/{findings,hunt}.py, spec sections 18, 26, 27, 28).

Run:  python -m pytest tests/test_nextgen_deephunt_hunt.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen import state as S  # noqa: E402
from src.nextgen.deephunt import findings as F  # noqa: E402
from src.nextgen.deephunt import hunt as H  # noqa: E402
from src.nextgen.deephunt import invariants as INV  # noqa: E402
from src.nextgen.execground import foundry as FOUNDRY  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")

_TOOLCHAIN = FOUNDRY.available()
forgegated = pytest.mark.skipif(not _TOOLCHAIN, reason="needs a Foundry toolchain")

# an unentitled ETH drain: withdraw() has no balance/entitlement check
DRAIN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Pool {
    mapping(address => uint256) public deposits;
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
"""

BENIGN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Pool {
    mapping(address => uint256) public deposits;
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
"""


# --------------------------------------------------------------------------- #
# findings.py - pure
# --------------------------------------------------------------------------- #

def test_classify_live_makes_regression_gates_nonblocking():
    fs = S.FindingState("x")
    for name in ("security_invariant", "reachable_path", "state_reachable",
                 "no_compensating_control", "invariant_violated", "reproducer",
                 "bytecode_provenance", "target_live", "independent_validation",
                 "not_duplicate"):
        fs.set_gate(name, S.PASS)
    fs.set_gate("economically_feasible", S.SKIPPED)
    # regression_commit + build_environment left PENDING
    state, verdict, _ = F.classify_live(fs.gates)
    assert verdict == S.VERDICT_CONFIRMED
    # and the stock classifier would NOT confirm this (git gates pending)
    assert S.classify(fs.gates)[1] == S.VERDICT_UNKNOWN


def test_classify_live_still_rejects_on_a_real_fail():
    fs = S.FindingState("x")
    fs.set_gate("no_compensating_control", S.FAIL)
    state, verdict, _ = F.classify_live(fs.gates)
    assert verdict == S.VERDICT_REJECTED
    assert state == S.FALSE_POSITIVE


def test_finding_type_mapping():
    def _inv(src, kind=INV.IM.ACCOUNTING):
        return type("I", (), {"source": src, "kind": kind})()
    assert F.finding_type_for(_inv(INV.SRC_ORACLE)) == F.ORACLE
    assert F.finding_type_for(_inv(INV.SRC_ENTITLEMENT)) == F.ACCOUNTING
    assert F.finding_type_for(_inv(INV.SRC_AUTH_REACH, INV.IM.ACCESS_CONTROL)) == F.ACCESS_CONTROL
    assert F.finding_type_for(_inv(INV.SRC_AUTH_REACH, INV.IM.CROSS_CONTRACT)) == F.CROSS_CONTRACT
    assert F.finding_type_for(_inv(INV.SRC_PROTOCOL + ":llm")) == F.PROTOCOL_INVARIANT


def test_confidence_and_severity_ladder():
    assert F.confidence_for(S.VERDICT_REJECTED, {}) == F.REJECTED
    assert F.confidence_for(S.VERDICT_CONFIRMED, {}) == F.CONFIRMED
    likely = F.confidence_for(S.VERDICT_UNKNOWN,
                              {"reproducer": S.PASS, "invariant_violated": S.PASS})
    assert likely == F.LIKELY
    cand = F.confidence_for(S.VERDICT_UNKNOWN,
                            {"security_invariant": S.PASS, "reachable_path": S.PASS})
    assert cand == F.CANDIDATE
    assert F.severity_for(F.UNKNOWN, F.ACCOUNTING) == "unknown"
    assert F.severity_for(F.CONFIRMED, F.ACCOUNTING, 500_000) == "critical"


def test_deepfinding_render_and_dict_roundtrip():
    fnd = F.DeepFinding(finding_id="DH-1", finding_type=F.ACCOUNTING,
                        title="t", confidence=F.CANDIDATE, contract="Pool",
                        function="withdraw", security_property="p",
                        lines=[F.fact("a"), F.inference("b"), F.assumption("c")])
    txt = fnd.render()
    assert "CANDIDATE ACCOUNTING" in txt and "[FACT" in txt and "[ASSUMPTION" in txt
    import json
    json.dumps(fnd.as_dict())
    with pytest.raises(ValueError):
        F.DeepFinding(finding_id="x", finding_type="NONSENSE", title="t")


# --------------------------------------------------------------------------- #
# hunt.run - end to end
# --------------------------------------------------------------------------- #

def test_uncompiled_source_is_unknown_not_a_crash():
    res = H.run(H.HuntInputs(source="not solidity"))
    assert res.verdict == S.VERDICT_UNKNOWN
    assert "did not compile" in res.report_text


def test_hunt_populates_model_invariants_and_coverage():
    res = H.run(H.HuntInputs(source=DRAIN, target_contract="Pool",
                             budget_findings=4))
    assert res.model.compiled
    assert res.coverage["contracts_modeled"] >= 1
    assert res.coverage["invariants_discovered"] >= 1
    assert res.coverage["sequences_planned"] >= 1
    assert res.coverage["candidates_generated"] >= 1
    assert "DEEP COVERAGE" in res.report_text
    # every finding carries a valid taxonomy type and a non-binary confidence
    for f in res.findings:
        assert f.finding_type in F.FINDING_TYPES
        assert f.confidence in (F.CONFIRMED, F.LIKELY, F.CANDIDATE, F.UNKNOWN,
                                F.REJECTED)


def test_hunt_is_deterministic_without_llm_or_toolchain(monkeypatch):
    monkeypatch.setattr(FOUNDRY, "resolve", lambda *a, **k: None)
    a = H.run(H.HuntInputs(source=DRAIN, target_contract="Pool"))
    b = H.run(H.HuntInputs(source=DRAIN, target_contract="Pool"))
    assert [f.as_dict() for f in a.findings] == [f.as_dict() for f in b.findings]
    # source-only, no toolchain -> nothing can be CONFIRMED
    assert a.verdict in (S.VERDICT_UNKNOWN, S.VERDICT_REJECTED)
    assert a.coverage["confirmed_findings"] == 0


@forgegated
def test_hunt_reproduces_the_unentitled_drain():
    res = H.run(H.HuntInputs(source=DRAIN, target_contract="Pool",
                             budget_findings=6))
    assert res.coverage["candidates_reproduced"] >= 1, res.report_text
    repro = [f for f in res.findings if f.gates.get("reproducer") == S.PASS]
    assert repro
    f = repro[0]
    assert f.confidence in (F.LIKELY, F.CONFIRMED)   # observed on a local fork
    assert f.finding_type == F.ACCOUNTING
    assert f.min_sequence
    assert "violation" in f.execution_proof.lower()
    assert f.gates["invariant_violated"] == S.PASS
    assert f.gates["security_invariant"] == S.PASS   # grounded by the reproduction
    # source-only -> deployment not verified -> not CONFIRMED (correct discipline)
    assert f.gates["target_live"] == S.GATE_UNKNOWN


@forgegated
def test_hunt_does_not_reproduce_a_benign_protocol():
    res = H.run(H.HuntInputs(source=BENIGN, target_contract="Pool",
                             budget_findings=6))
    assert res.coverage["confirmed_findings"] == 0
    assert res.coverage["candidates_reproduced"] == 0
    assert res.verdict in (S.VERDICT_UNKNOWN, S.VERDICT_REJECTED)
