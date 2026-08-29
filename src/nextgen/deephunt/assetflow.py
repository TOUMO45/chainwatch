"""Phase 5 - asset-flow graph, entitlement check, economic feed
(spec sections 13, 14, 15).

A positive attacker balance delta is NOT automatically a vulnerability. This
module records who held what before and after a candidate sequence, builds the
flow graph (protocol -> attacker, victim -> attacker, ...), and asks the
question the spec insists on:

    was the attacker ENTITLED to the value, or is it UNEARNED extraction?

`is_unearned_extraction` compares the attacker's gain against what they paid in
during the same sequence. Gain <= paid-in (within tolerance) -> legitimate,
reject. Gain > paid-in AND the protocol lost value -> an economic-violation
candidate.

`quantify` / `assess` convert the raw deltas into `execground/economics`
inputs (conservative constants, capital ceiling for a lone attacker) so the
`economically_feasible` gate is fed from real measured numbers, not a guess.

`measure_on_fork` (gated) replays raw calls on a `ForkContext` and diffs ETH +
ERC20 balances. With no fork, callers use the pure `AssetFlow` math directly.
Nothing here decides a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from src.nextgen.execground import economics as ECON

# ERC20 balanceOf(address) selector
_BALANCEOF = "0x70a08231"

ATTACKER = "attacker"
PROTOCOL = "protocol"
OTHER = "other"
ACTORS = (ATTACKER, PROTOCOL, OTHER)

ETH = "ETH"


@dataclass
class FlowEdge:
    frm: str
    to: str
    asset: str
    amount: int                       # smallest unit; direction is frm -> to

    def as_dict(self) -> dict:
        return {"from": self.frm, "to": self.to, "asset": self.asset,
                "amount": str(self.amount)}


@dataclass
class AssetFlow:
    """`before` / `after` map (actor, asset) -> integer balance (wei / unit)."""

    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    assets: dict = field(default_factory=dict)     # label -> address ("" for ETH)
    edges: list[FlowEdge] = field(default_factory=list)
    gas_used: int = 0
    note: str = ""

    # -- deltas ------------------------------------------------------------- #

    def delta(self, actor: str, asset: str) -> int:
        return int(self.after.get((actor, asset), 0)) - \
            int(self.before.get((actor, asset), 0))

    def asset_labels(self) -> list[str]:
        seen = []
        for (_a, asset) in list(self.before) + list(self.after):
            if asset not in seen:
                seen.append(asset)
        return seen

    def attacker_gain(self, asset: str) -> int:
        return max(0, self.delta(ATTACKER, asset))

    def protocol_loss(self, asset: str) -> int:
        return max(0, -self.delta(PROTOCOL, asset))

    def user_loss(self, asset: str) -> int:
        return max(0, -self.delta(OTHER, asset))

    def net(self, asset: str) -> int:
        """Sum of every actor's delta for `asset` - should be ~0 (minus gas on
        the ETH axis) if value was only moved, not created."""
        return sum(self.delta(a, asset) for a in ACTORS)

    def primary_asset(self) -> str:
        labels = self.asset_labels()
        if not labels:
            return ETH
        return max(labels, key=lambda a: abs(self.delta(PROTOCOL, a)) or
                   abs(self.delta(ATTACKER, a)))

    def derive_edges(self) -> list[FlowEdge]:
        """A crude flow graph: for each asset, if the attacker gained and the
        protocol (or a victim) lost, draw the edge."""
        out: list[FlowEdge] = []
        for asset in self.asset_labels():
            ag = self.delta(ATTACKER, asset)
            if ag <= 0:
                continue
            for src in (PROTOCOL, OTHER):
                sl = -self.delta(src, asset)
                if sl > 0:
                    out.append(FlowEdge(src, ATTACKER, asset, min(ag, sl)))
        self.edges = out
        return out

    def as_dict(self) -> dict:
        labels = self.asset_labels()
        return {
            "assets": dict(self.assets),
            "deltas": {a: {lbl: str(self.delta(a, lbl)) for lbl in labels}
                       for a in ACTORS},
            "primary_asset": self.primary_asset(),
            "net_per_asset": {lbl: str(self.net(lbl)) for lbl in labels},
            "edges": [e.as_dict() for e in (self.edges or self.derive_edges())],
            "gas_used": self.gas_used, "note": self.note,
        }


# --------------------------------------------------------------------------- #
# construction
# --------------------------------------------------------------------------- #

def from_balances(before: dict, after: dict, *, assets: Optional[dict] = None,
                  gas_used: int = 0, note: str = "") -> AssetFlow:
    fl = AssetFlow(before=dict(before), after=dict(after),
                   assets=dict(assets or {}), gas_used=gas_used, note=note)
    fl.derive_edges()
    return fl


# --------------------------------------------------------------------------- #
# entitlement (spec section 13 / 14 - "was the gain legitimate?")
# --------------------------------------------------------------------------- #

def is_unearned_extraction(flow: AssetFlow,
                           deposits: Optional[list[tuple[str, int]]] = None, *,
                           primary_asset: Optional[str] = None,
                           tolerance: float = 0.02) -> tuple[bool, str]:
    """`deposits` is [(asset_label, amount)] the attacker paid IN during the
    same sequence. Returns (unearned, reason).

      * attacker gain <= paid-in * (1 + tolerance)  -> legitimate (reject)
      * attacker gain  > paid-in AND protocol lost  -> unearned candidate
      * attacker did not gain                        -> not an extraction
    """
    asset = primary_asset or flow.primary_asset()
    gain = flow.attacker_gain(asset)
    if gain <= 0:
        return False, f"attacker did not gain {asset}"
    paid = sum(a for (lbl, a) in (deposits or []) if lbl == asset)
    ploss = flow.protocol_loss(asset)
    uloss = flow.user_loss(asset)

    if gain <= paid * (1 + tolerance):
        return False, (f"attacker gained {gain} {asset} but paid in {paid} "
                       f"{asset} - within entitlement, legitimate")
    if ploss <= 0 and uloss <= 0:
        return False, (f"attacker gained {gain - paid} {asset} net, but no "
                       f"protocol / user loss was measured - inconclusive")
    who = "the protocol" if ploss >= uloss else "other users"
    return True, (f"attacker gained {gain} {asset} having paid in {paid}; "
                  f"{who} lost {max(ploss, uloss)} {asset} - unearned extraction")


# --------------------------------------------------------------------------- #
# economic feed (spec section 14 / 15)
# --------------------------------------------------------------------------- #

def quantify(flow: AssetFlow, prices_usd: dict[str, float], *,
             gas_units: int = 250_000, attack_txs: int = 1,
             flashloan_available: bool = False,
             required_capital_units: Optional[tuple[str, int]] = None
             ) -> ECON.EconomicInputs:
    """Convert measured deltas into `economics.EconomicInputs`. `prices_usd`
    maps an asset label to USD per whole unit (e.g. {"ETH": 3000.0}); unpriced
    assets are ignored for the USD roll-up."""
    def _usd(asset: str, amount: int) -> float:
        p = prices_usd.get(asset)
        if p is None:
            return 0.0
        return (amount / 1e18) * p if asset in (ETH, "WETH") else amount * p

    extraction = sum(_usd(a, flow.attacker_gain(a)) for a in flow.asset_labels())
    ploss = sum(_usd(a, flow.protocol_loss(a)) for a in flow.asset_labels())
    cap_usd = 0.0
    if required_capital_units:
        cap_usd = _usd(required_capital_units[0], required_capital_units[1])

    return ECON.EconomicInputs(
        expected_extraction_usd=extraction or None,
        protocol_loss_usd=ploss or None,
        required_capital_usd=cap_usd,
        flashloan_available=flashloan_available,
        gas_units=gas_units * max(1, attack_txs),
        attack_txs=attack_txs,
        eth_price_usd=prices_usd.get(ETH, ECON.ETH_PRICE_USD))


def assess(flow: AssetFlow, prices_usd: dict[str, float], **kw
           ) -> ECON.EconomicAssessment:
    return ECON.assess(quantify(flow, prices_usd, **kw))


# --------------------------------------------------------------------------- #
# fork measurement (gated - needs a live ForkContext)
# --------------------------------------------------------------------------- #

def measure_on_fork(fx, raw_calls: list[dict], *, attacker: str, protocol: str,
                    others: tuple[str, ...] = (),
                    tokens: Optional[dict[str, str]] = None) -> Optional[AssetFlow]:
    """Snapshot ETH + ERC20 balances for attacker / protocol / `others`, replay
    each `raw_call` ({from,to,data,value}) via `fx.impersonate_send`, snapshot
    again, and diff. Returns None when `fx` is not available.

    `tokens` is {label: address}; ETH is always tracked. Never broadcasts - the
    fork IS the network.
    """
    if fx is None or not getattr(fx, "available", False):
        return None
    tokens = tokens or {}
    who = {ATTACKER: attacker, PROTOCOL: protocol}
    other_map = {f"{OTHER}:{i}": a for i, a in enumerate(others)}

    def _snap() -> dict:
        b: dict = {}
        for role, addr in {**who, **other_map}.items():
            key_role = OTHER if role.startswith(OTHER) else role
            v = fx.balance(addr)
            if v is not None:
                b[(key_role, ETH)] = b.get((key_role, ETH), 0) + v
            for lbl, taddr in tokens.items():
                data = _BALANCEOF + addr.lower().replace("0x", "").rjust(64, "0")
                r = fx.call(taddr, data)
                if isinstance(r, str) and r.startswith("0x"):
                    try:
                        b[(key_role, lbl)] = b.get((key_role, lbl), 0) + int(r, 16)
                    except ValueError:
                        pass
        return b

    before = _snap()
    gas = 0
    for call in raw_calls:
        rcpt = fx.impersonate_send(call)
        if isinstance(rcpt, dict):
            try:
                gas += int(rcpt.get("gasUsed", "0x0"), 16)
            except (TypeError, ValueError):
                pass
    after = _snap()
    return from_balances(before, after, assets={ETH: "", **tokens},
                         gas_used=gas, note=f"{len(raw_calls)} call(s) on fork")


# --------------------------------------------------------------------------- #

def summarize(flow: AssetFlow) -> str:
    a = flow.primary_asset()
    lines = ["ASSET FLOW", "=" * 10, "",
             f"  primary asset : {a}",
             f"  attacker      : {flow.delta(ATTACKER, a):+d} {a}",
             f"  protocol      : {flow.delta(PROTOCOL, a):+d} {a}",
             f"  other users   : {flow.delta(OTHER, a):+d} {a}",
             f"  net (should be ~0): {flow.net(a):+d} {a}"]
    for e in (flow.edges or flow.derive_edges()):
        lines.append(f"    {e.frm} -> {e.to}: {e.amount} {e.asset}")
    return "\n".join(lines)
