"""Phase 6 - the Historical Behaviour Engine (spec sections 6, 7, 8).

For a live target, learn what the deployed protocol NORMALLY allows and NORMALLY
rejects, from real on-chain history, then contrast that with the source model:

  * a state-changing entry point in the code that history has never exercised;
  * a function the code leaves open (no caller-identity guard) that history
    shows only a tiny fixed caller set ever used successfully - a boundary the
    code does not actually enforce (spec section 7);
  * a selector that reverts often historically - a candidate defensive limit
    worth testing against the current implementation.

Historical behaviour is EVIDENCE FOR HYPOTHESIS GENERATION, never proof
(spec section 6). Each signal only RAISES a candidate's exploration priority.

Composes the Twin's own machinery unchanged - `twin.collect.collect`,
`twin.fingerprint.build_fingerprints`, `twin.boundaries.mine_boundaries`,
`twin.rpc.RpcClient`. With no RPC endpoint it returns
`LearnedBehavior(available=False)` and `contrast` returns `[]`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from src.nextgen.twin import model as TM
from . import protocolmodel as PM

# signal kinds
NEVER_EXERCISED = "NEVER_EXERCISED"
HISTORICALLY_RESTRICTED_NOW_OPEN = "HISTORICALLY_RESTRICTED_NOW_OPEN"
DEFENSIVE_LIMIT = "DEFENSIVE_LIMIT"
CONFIRMS_BOUNDARY = "CONFIRMS_BOUNDARY"


@dataclass
class BehaviorSignal:
    kind: str
    selector: str
    function: str                    # "Contract.fn"
    detail: str
    priority_bump: int = 1

    def as_dict(self) -> dict:
        return {"kind": self.kind, "selector": self.selector,
                "function": self.function, "detail": self.detail,
                "priority_bump": self.priority_bump}


@dataclass
class LearnedBehavior:
    address: str
    chain_id: int = 0
    from_block: int = 0
    to_block: int = 0
    n_txs: int = 0
    n_revert: int = 0
    fingerprints: dict = field(default_factory=dict)      # selector -> FunctionFingerprint
    boundaries: list = field(default_factory=list)        # twin Boundary
    revert_boundaries: list = field(default_factory=list)  # (selector, rate, n)
    available: bool = False
    reason: str = ""

    def rejected_selectors(self, *, min_rate: float = 0.15,
                           min_n: int = 3) -> list[str]:
        return [s for s, rate, n in self.revert_boundaries
                if rate >= min_rate and n >= min_n]

    def as_dict(self) -> dict:
        return {"address": self.address, "chain_id": self.chain_id,
                "from_block": self.from_block, "to_block": self.to_block,
                "n_txs": self.n_txs, "n_revert": self.n_revert,
                "n_fingerprints": len(self.fingerprints),
                "n_boundaries": len(self.boundaries),
                "revert_boundaries": [[s, round(r, 3), n]
                                      for s, r, n in self.revert_boundaries],
                "available": self.available, "reason": self.reason}


# --------------------------------------------------------------------------- #
# learning (RPC-gated)
# --------------------------------------------------------------------------- #

def learn(address: str, rpc_url: str, *, from_block: int, to_block: int,
          max_txs: int = 250) -> LearnedBehavior:
    if not rpc_url:
        return LearnedBehavior(address=address.lower(), from_block=from_block,
                               to_block=to_block, available=False,
                               reason="no RPC endpoint for historical behaviour")
    try:
        from src.nextgen.twin.rpc import RpcClient
        from src.nextgen.twin import collect as TC
        from src.nextgen.twin import fingerprint as TF
        from src.nextgen.twin import boundaries as TB

        rpc = RpcClient(rpc_url)
        col = TC.collect(rpc, address, from_block=from_block, to_block=to_block,
                         max_txs=max_txs)
        fps = TF.build_fingerprints(col)
        bnds = TB.mine_boundaries(fps, col.transfers)
        lb = LearnedBehavior(
            address=col.address, chain_id=col.chain_id,
            from_block=from_block, to_block=to_block, n_txs=len(col.txs),
            n_revert=sum(f.n_revert for f in fps.values()),
            fingerprints=fps, boundaries=bnds, available=True,
            reason="; ".join(col.notes[-2:]) if col.notes else "")
        lb.revert_boundaries = _revert_boundaries(fps)
        return lb
    except Exception as exc:  # noqa: BLE001 - no history -> UNKNOWN, never a crash
        return LearnedBehavior(address=address.lower(), from_block=from_block,
                               to_block=to_block, available=False,
                               reason=f"{type(exc).__name__}: {exc}"[:300])


def _revert_boundaries(fps: dict) -> list[tuple[str, float, int]]:
    out: list[tuple[str, float, int]] = []
    for sel, fp in fps.items():
        if getattr(fp, "n_revert", 0) >= 3 and getattr(fp, "revert_rate", 0) >= 0.15:
            out.append((sel, fp.revert_rate, fp.n_revert))
    return sorted(out, key=lambda t: -t[2])


# --------------------------------------------------------------------------- #
# contrasting model vs history (pure)
# --------------------------------------------------------------------------- #

def contrast(model: PM.ProtocolModel, invariants: list,
             learned: LearnedBehavior) -> list[BehaviorSignal]:
    if not getattr(learned, "available", False) or not getattr(model, "compiled", False):
        return []
    out: list[BehaviorSignal] = []
    fn_by_sel = {f.selector: f for f in model.all_functions()
                 if getattr(f, "selector", "")}
    seen = set(learned.fingerprints)

    for sel, fm in fn_by_sel.items():
        if sel in seen:
            continue
        if fm.external and fm.state_changing and fm.risk >= 4:
            out.append(BehaviorSignal(
                NEVER_EXERCISED, sel, f"{fm.contract}.{fm.name}",
                "state-changing entry point never called in the sampled window "
                f"(risk {fm.risk})", priority_bump=2))

    for b in learned.boundaries:
        if getattr(b, "kind", "") != TM.AUTHORIZATION:
            continue
        fm = fn_by_sel.get(getattr(b, "selector", ""))
        if fm is not None and not fm.access_controlled and fm.state_changing:
            out.append(BehaviorSignal(
                HISTORICALLY_RESTRICTED_NOW_OPEN, b.selector,
                f"{fm.contract}.{fm.name}",
                f"history: {b.statement}; code: no caller-identity guard",
                priority_bump=4))
        elif fm is not None:
            out.append(BehaviorSignal(
                CONFIRMS_BOUNDARY, b.selector, f"{fm.contract}.{fm.name}",
                f"history and code agree: {b.statement}", priority_bump=1))

    for sel, rate, n in learned.revert_boundaries:
        fm = fn_by_sel.get(sel)
        if fm is None:
            continue
        out.append(BehaviorSignal(
            DEFENSIVE_LIMIT, sel, f"{fm.contract}.{fm.name}",
            f"reverts {int(rate * 100)}% historically ({n} sampled) - a "
            f"defensive limit worth testing against the current implementation",
            priority_bump=1))
    return out


def priority_bumps(signals: list[BehaviorSignal]) -> dict[str, int]:
    """selector -> total priority bump, for the orchestrator to fold into
    `stateexplorer.rank_targets` output."""
    out: dict[str, int] = {}
    for s in signals:
        out[s.selector] = out.get(s.selector, 0) + s.priority_bump
    return out


def summarize(learned: LearnedBehavior, signals: list[BehaviorSignal]) -> str:
    if not learned.available:
        return ("HISTORICAL BEHAVIOUR\n" + "=" * 19 + "\n\n  not available: "
                + learned.reason)
    lines = ["HISTORICAL BEHAVIOUR", "=" * 19, "",
             f"  {learned.n_txs} tx(s) sampled, {learned.n_revert} reverted",
             f"  {len(learned.fingerprints)} selector(s), "
             f"{len(learned.boundaries)} behavioural boundary(ies)",
             f"  {len(signals)} contrast signal(s) vs the source model"]
    for s in signals[:8]:
        lines.append(f"    [{s.kind}] {s.function}  (+{s.priority_bump})  {s.detail}")
    return "\n".join(lines)
