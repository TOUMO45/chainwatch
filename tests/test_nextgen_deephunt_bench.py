"""Deep Hunt Phase 11 - the blind DVBench harness
(src/nextgen/deephunt/bench_dvbench.py, spec section 29).

Runs against a checked-in miniature benchmark (2 ready cases + 1 draft, inline
Etherscan-cache source). forge-gated cases still assert the discipline: no
CONFIRMED without a reproducer.

Run:  python -m pytest tests/test_nextgen_deephunt_bench.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen.deephunt import bench_dvbench as B  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")

MINI = str(Path(__file__).resolve().parent / "fixtures_deephunt" / "dvbench_mini")


def test_load_cases_filters_draft():
    ready = B.load_cases(MINI)
    assert {c["id"] for c in ready} == {"minidrain", "minioracle"}
    allc = B.load_cases(MINI, include_draft=True)
    assert len(allc) == 3


def test_load_source_from_cache_and_missing():
    ready = {c["id"]: c for c in B.load_cases(MINI)}
    src = B.load_source(ready["minidrain"], MINI)
    assert src is not None and "MiniDrain.sol" in src["source_files"]
    assert src["name"] == "MiniDrain"
    # a case whose cache file does not exist
    fake = dict(ready["minidrain"])
    fake["target_contract"] = "0x000000000000000000000000000000000000dEaD"
    assert B.load_source(fake, MINI) is None


def test_keyword_and_fn_extractors():
    assert "getreserves" in B._fn_names("reads IPair.getReserves() spot")
    assert "withdraw" in B._fn_names("the withdraw(uint256 amount) function")
    kw = B._keywords("instantaneous AMM reserves used as a price oracle")
    assert "oracle" in kw and "instantaneous" in kw
    assert "the" not in kw and "price" not in kw          # stopwords dropped


def test_matches_aligns_on_fn_and_focus():
    ref = {"title": "mint() prices off spot getReserves() with no TWAP",
           "content": "AMM spot reserves used as an oracle in mint()",
           "focus_areas": ["oracle_manipulation"]}
    good = [{"title": "Oracle: Minter.mint spot-priced via getReserves",
             "description": "mint() reads pair.getReserves() as a price",
             "location": "Minter.mint", "_type": B.F.ORACLE}]
    bad = [{"title": "Reentrancy in withdraw", "description": "external call",
            "location": "Other.withdraw", "_type": B.F.STATE_MACHINE}]
    assert B._matches(ref, good)[0] is True
    assert B._matches(ref, bad)[0] is False


def test_score_case_recall_math():
    dv = B.DVCaseResult("x", agent_findings=[
        {"title": "withdraw has no balance check, drains pool ETH",
         "description": "withdraw(uint256) sends ETH with no entitlement check; "
                        "deposits never decremented; funds not conserved",
         "location": "MiniDrain.withdraw", "_type": B.F.ACCOUNTING}])
    case = {"reference_findings": [
        {"title": "withdraw() performs no balance check letting anyone drain ETH",
         "content": "withdraw sends amount with no check the caller deposited it; "
                    "deposits[msg.sender] never read; protocol funds not conserved",
         "focus_areas": ["asset_management"], "auditable": True},
        {"title": "unrelated: missing event on deposit", "content": "no event",
         "focus_areas": [], "auditable": False}]}   # non-auditable -> excluded
    sc = B.score_case(dv, case)
    assert sc["reference_count"] == 1                     # only the auditable one
    assert sc["matched_count"] == 1 and sc["recall"] == 1.0


def test_run_dvbench_over_the_mini_set():
    rep = B.run_dvbench(MINI, budget_findings=6)
    assert rep.n_cases == 2
    assert rep.n_run == 2
    assert rep.n_source_unavailable == 0
    assert rep.n_compiled == 2
    assert rep.total_reference == 2                       # 1 auditable ref per case
    # the harness produced a recall number and a rendered report
    assert rep.mean_recall is not None
    d = rep.as_dict()
    assert "recall_micro" in d
    assert "DVBench" in rep.render()
    # DISCIPLINE: source-only -> nothing is CONFIRMED, so no false positives
    assert rep.cases_confirmed == 0
    assert rep.confirmed_false_positive_ratio is None
    for r in rep.results:
        for af in r.agent_findings:
            if af.get("_confidence") == B.F.CONFIRMED:
                assert af.get("_reproduced") is True     # never CONFIRMED w/o a repro


def test_missing_checkout_raises():
    with pytest.raises(FileNotFoundError):
        B.load_cases(str(Path(MINI) / "does-not-exist"))


def test_agent_snippet_is_available_as_a_string():
    assert "class ChainwatchAgent(BaseAgent)" in B.AGENT_SNIPPET
    assert "AGENTS[\"chainwatch\"]" in B.AGENT_SNIPPET
