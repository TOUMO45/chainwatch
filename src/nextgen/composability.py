"""Cross-protocol / composability analysis (spec §13).

When a protocol calls out to another (a vault reading an oracle, a strategy
depositing into a lending market, an accounting function trusting
`token.balanceOf(this)`), it makes ASSUMPTIONS about that dependency's
behaviour. This module identifies

    ASSUMPTION  ->  ACTUAL BEHAVIOUR  ->  MISMATCH

structurally, from how an external call's return value is consumed - it does
NOT blame the dependency, it names the assumption that no longer holds.

Best-effort and structural; this is a discovery aid (an informational section
of a report), not a gate. It never confirms a finding on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

ORACLE = "ORACLE"
DEX = "DEX"
LENDING = "LENDING"
TOKEN = "TOKEN"
BRIDGE = "BRIDGE"
UNKNOWN = "UNKNOWN"

# method name -> (dependency kind, assumption, actual behaviour, mismatch)
_PATTERNS: dict[str, tuple[str, str, str, str]] = {
    "latestanswer": (
        ORACLE, "the returned price is fresh and correct",
        "Chainlink `latestAnswer()` carries no timestamp and can be stale, or "
        "report a frozen value during an outage",
        "no freshness / min-max bound check on the consumed value"),
    "latestrounddata": (
        ORACLE, "the round is current",
        "`latestRoundData()` returns `updatedAt` / `answeredInRound`; a stale "
        "round is indistinguishable from a fresh one if those are ignored",
        "the `updatedAt` / round fields are not validated"),
    "getreserves": (
        DEX, "the pool spot price equals fair value",
        "AMM reserves are moved by any swap in the same block - a flash loan "
        "sets them to almost any ratio",
        "a spot reserve ratio is used as a valuation without a TWAP"),
    "getamountsout": (
        DEX, "the quoted amount reflects fair value",
        "`getAmountsOut` is the instantaneous curve price, manipulable within "
        "one transaction",
        "an instantaneous quote is trusted as a price"),
    "consult": (
        DEX, "the TWAP window is long enough to resist manipulation",
        "a short TWAP window is still cheap to move over a few blocks",
        "the TWAP window length is not verified to be conservative"),
    "balanceof": (
        TOKEN, "the contract's own accounting is the sole cause of its token "
        "balance changing",
        "anyone can `transfer` tokens directly to the contract; rebasing / "
        "fee-on-transfer tokens change balances outside its accounting",
        "`balanceOf(address(this))` is trusted as accounting truth"),
    "transfer": (
        TOKEN, "a failed transfer reverts",
        "USDT and other non-standard ERC20s return `false` instead of "
        "reverting; some return nothing",
        "the boolean return of `transfer` / `transferFrom` is not checked"),
    "transferfrom": (
        TOKEN, "a failed transfer reverts",
        "non-standard ERC20s return `false` or nothing on failure",
        "the boolean return of `transferFrom` is not checked"),
}


@dataclass
class ComposabilityRisk:
    dependency_kind: str
    method: str
    caller: str                       # Contract.function that makes the call
    assumption: str
    actual_behaviour: str
    mismatch: str
    return_checked: bool = False

    def as_dict(self) -> dict:
        return {"dependency_kind": self.dependency_kind, "method": self.method,
                "caller": self.caller, "assumption": self.assumption,
                "actual_behaviour": self.actual_behaviour,
                "mismatch": self.mismatch, "return_checked": self.return_checked}

    def render_text(self) -> str:
        return "\n".join([
            f"  [{self.dependency_kind}] {self.caller} -> {self.method}()",
            f"      ASSUMPTION      : {self.assumption}",
            f"      ACTUAL BEHAVIOUR: {self.actual_behaviour}",
            f"      MISMATCH        : {self.mismatch}",
        ])


@dataclass
class ComposabilityReport:
    contract: str
    risks: list[ComposabilityRisk] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"contract": self.contract,
                "risks": [r.as_dict() for r in self.risks]}

    def render_text(self) -> str:
        lines = ["CROSS-PROTOCOL / COMPOSABILITY ANALYSIS (spec §13)",
                 "=" * 50, ""]
        if not self.risks:
            lines.append("  no external-dependency assumption mismatch found")
        for r in self.risks:
            lines.append(r.render_text())
            lines.append("")
        return "\n".join(lines).rstrip()


def analyze(slither_obj, contract_name: str) -> ComposabilityReport:
    from src.rules import _shared
    from slither.slithir.operations import HighLevelCall, LowLevelCall

    rep = ComposabilityReport(contract_name)
    contract = None
    for c in getattr(slither_obj, "contracts_derived", slither_obj.contracts):
        if c.name == contract_name:
            contract = c
            break
    if contract is None:
        return rep

    for fn in contract.functions:
        if getattr(fn, "is_constructor", False):
            continue
        for node in getattr(fn, "nodes", []):
            for ir in node.irs:
                if not isinstance(ir, (HighLevelCall, LowLevelCall)):
                    continue
                name = (getattr(ir, "function_name", None)
                        or getattr(getattr(ir, "function", None), "name", None)
                        or "")
                key = str(name).lower()
                pat = _PATTERNS.get(key)
                if not pat:
                    continue
                kind, assumption, actual, mismatch = pat
                checked = _return_is_checked(fn, ir, _shared)
                # for the token-return patterns, a checked return neutralises it
                if key in ("transfer", "transferfrom") and checked:
                    continue
                rep.risks.append(ComposabilityRisk(
                    kind, str(name), f"{contract_name}.{fn.name}",
                    assumption, actual, mismatch, return_checked=checked))
    # de-dup on (method, caller)
    seen, uniq = set(), []
    for r in rep.risks:
        k = (r.method, r.caller)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    rep.risks = uniq
    return rep


def _return_is_checked(fn, ir, _shared) -> bool:
    lv = getattr(ir, "lvalue", None)
    if lv is None:
        return False
    try:
        taint = _shared.external_call_return_taint(fn)
        for node in _shared.guard_nodes(fn):
            if _shared.guard_checks_call_return(node, taint):
                return True
    except Exception:  # noqa: BLE001
        pass
    return False


def analyze_from_source(text: str, contract_name: str) -> ComposabilityReport:
    from ._solc import slither_for_source
    return analyze(slither_for_source(text), contract_name)
