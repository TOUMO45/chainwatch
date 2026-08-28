"""Phase 5 - economic exploitability estimate (src/nextgen/execground/economics.py, spec §14).

Pure. Pins: a $40M-capital / $2k-profit attack is INFEASIBLE; a flash-loan
funded $8M extraction for $3k cost is FEASIBLE; missing extraction estimate is
UNKNOWN. The gate can REJECT (ECONOMICALLY_INFEASIBLE) but never CONFIRM.

Run:  python -m pytest tests/test_nextgen_economics.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import state as S  # noqa: E402
from src.nextgen.execground import economics as E  # noqa: E402


def test_no_extraction_estimate_is_unknown():
    a = E.assess(E.EconomicInputs(gas_units=500_000))
    assert a.gate == S.GATE_UNKNOWN
    assert a.attacker_profit_usd is None


def test_huge_capital_without_flashloan_is_infeasible():
    a = E.assess(E.EconomicInputs(
        expected_extraction_usd=2_000, required_capital_usd=40_000_000,
        flashloan_available=False, gas_units=800_000))
    assert a.gate == S.FAIL
    assert a.feasible is False
    assert "beyond a lone attacker" in a.rationale


def test_attack_that_costs_more_than_it_extracts_is_infeasible():
    a = E.assess(E.EconomicInputs(
        expected_extraction_usd=100, gas_units=5_000_000,
        gas_price_gwei=100, eth_price_usd=3000))
    assert a.gate == S.FAIL
    assert a.attacker_profit_usd < 0


def test_tiny_profit_is_below_the_worthwhile_threshold():
    a = E.assess(E.EconomicInputs(
        expected_extraction_usd=1_200, gas_units=1_000_000,
        gas_price_gwei=20, eth_price_usd=3000))
    # cost ~ $60; profit ~ $1140 > $1000 -> PASS; nudge extraction down:
    a2 = E.assess(E.EconomicInputs(
        expected_extraction_usd=700, gas_units=1_000_000,
        gas_price_gwei=20, eth_price_usd=3000))
    assert a2.gate == S.FAIL
    assert 0 < a2.attacker_profit_usd < E.WORTHWHILE_PROFIT_USD


def test_flashloan_funded_large_extraction_is_feasible():
    a = E.assess(E.EconomicInputs(
        expected_extraction_usd=8_200_000, required_capital_usd=50_000,
        flashloan_available=True, flashloan_fee_bps=9,
        gas_units=3_000_000, gas_price_gwei=20, eth_price_usd=3000))
    assert a.gate == S.PASS
    assert a.feasible is True
    assert a.attacker_profit_usd > 8_000_000
    assert a.flashloan_fee_usd == 50_000 * 9 / 10_000


def test_apply_to_gate_never_confirms_only_rejects_or_informs():
    fs = S.FindingState("f")
    E.apply_to_gate(fs, E.assess(E.EconomicInputs(
        expected_extraction_usd=100, gas_units=5_000_000, gas_price_gwei=200)))
    assert fs.gates["economically_feasible"] == S.FAIL
    fine, verdict, _ = S.classify(fs.gates)
    assert fine == S.ECONOMICALLY_INFEASIBLE


def test_render_text():
    a = E.assess(E.EconomicInputs(expected_extraction_usd=8_200_000,
                                  required_capital_usd=50_000,
                                  flashloan_available=True, gas_units=3_000_000))
    assert "ECONOMIC EXPLOITABILITY" in a.render_text()
