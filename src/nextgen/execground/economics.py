"""Economic exploitability estimate (spec §14).

A technical bug is not automatically a profitable exploit. For a value-bearing
finding, estimate whether an attack is worth running:

    required capital · gas cost · flash-loan fee · slippage
    expected extraction · protocol loss · attacker profit

This is a ROUGH model, deliberately: it is a non-gating signal that can also
REJECT a candidate as ECONOMICALLY_INFEASIBLE (spec §16 hard-gate list). It is
pure Python with documented constants; no chain access, no pricing feed.

`assess` -> the `economically_feasible` gate: PASS when the estimated profit
clears a worthwhile threshold, FAIL when the attack loses money or needs
capital a lone attacker cannot get without a flash loan, UNKNOWN when the
inputs are incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .. import state as S

# documented defaults - override per call
ETH_PRICE_USD = 3000.0
GAS_PRICE_GWEI = 20.0
FLASHLOAN_FEE_BPS = 9              # Aave v3 = 0.09%; Balancer = 0
WORTHWHILE_PROFIT_USD = 1_000.0   # below this, not worth the effort / risk
LONE_ATTACKER_CAPITAL_CEILING_USD = 2_000_000.0


@dataclass
class EconomicInputs:
    expected_extraction_usd: Optional[float] = None
    protocol_loss_usd: Optional[float] = None
    required_capital_usd: float = 0.0
    flashloan_available: bool = False
    flashloan_fee_bps: float = FLASHLOAN_FEE_BPS
    gas_units: int = 0
    attack_txs: int = 1
    slippage_usd: float = 0.0
    eth_price_usd: float = ETH_PRICE_USD
    gas_price_gwei: float = GAS_PRICE_GWEI
    capital_ceiling_usd: float = LONE_ATTACKER_CAPITAL_CEILING_USD


@dataclass
class EconomicAssessment:
    gas_cost_usd: float
    flashloan_fee_usd: float
    attack_cost_usd: float
    attacker_profit_usd: Optional[float]
    feasible: Optional[bool]
    gate: str
    rationale: str

    def as_dict(self) -> dict:
        return {"gas_cost_usd": round(self.gas_cost_usd, 2),
                "flashloan_fee_usd": round(self.flashloan_fee_usd, 2),
                "attack_cost_usd": round(self.attack_cost_usd, 2),
                "attacker_profit_usd": (round(self.attacker_profit_usd, 2)
                                        if self.attacker_profit_usd is not None
                                        else None),
                "feasible": self.feasible, "gate": self.gate,
                "rationale": self.rationale}

    def render_text(self) -> str:
        return "\n".join([
            "ECONOMIC EXPLOITABILITY (spec §14)", "=" * 33, "",
            f"  gas cost         : ${self.gas_cost_usd:,.2f}",
            f"  flash-loan fee   : ${self.flashloan_fee_usd:,.2f}",
            f"  total attack cost: ${self.attack_cost_usd:,.2f}",
            f"  attacker profit  : "
            + (f"${self.attacker_profit_usd:,.2f}"
               if self.attacker_profit_usd is not None else "unknown"),
            "",
            f"  gate: {self.gate}  -  {self.rationale}",
        ])


def assess(inp: EconomicInputs) -> EconomicAssessment:
    gas_cost = (inp.gas_units * inp.gas_price_gwei * 1e-9 * inp.eth_price_usd)
    fee = 0.0
    if inp.flashloan_available and inp.required_capital_usd > 0:
        fee = inp.required_capital_usd * inp.flashloan_fee_bps / 10_000.0
    cost = gas_cost + fee + inp.slippage_usd

    if inp.expected_extraction_usd is None:
        return EconomicAssessment(
            gas_cost, fee, cost, None, None, S.GATE_UNKNOWN,
            "no extraction estimate - cannot judge economic feasibility")

    # capital wall: a lone attacker without a flash loan
    if (not inp.flashloan_available
            and inp.required_capital_usd > inp.capital_ceiling_usd):
        return EconomicAssessment(
            gas_cost, fee, cost, inp.expected_extraction_usd - cost, False,
            S.FAIL,
            f"requires ${inp.required_capital_usd:,.0f} of capital with no "
            f"flash-loan path - beyond a lone attacker")

    profit = inp.expected_extraction_usd - cost
    if profit <= 0:
        return EconomicAssessment(gas_cost, fee, cost, profit, False, S.FAIL,
                                  "the attack costs more than it extracts")
    if profit < WORTHWHILE_PROFIT_USD:
        return EconomicAssessment(
            gas_cost, fee, cost, profit, False, S.FAIL,
            f"estimated profit ${profit:,.0f} is below the worthwhile "
            f"threshold (${WORTHWHILE_PROFIT_USD:,.0f})")
    return EconomicAssessment(
        gas_cost, fee, cost, profit, True, S.PASS,
        f"estimated attacker profit ${profit:,.0f} on ${cost:,.0f} cost"
        + ("; flash-loan funded" if inp.flashloan_available else ""))


def apply_to_gate(fs: S.FindingState, assessment: EconomicAssessment, *,
                  evidence_ref: Optional[str] = None) -> None:
    fs.set_gate("economically_feasible", assessment.gate,
                note=assessment.rationale, evidence_ref=evidence_ref)
