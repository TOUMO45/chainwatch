"""Deep-trace enrichment for Phase 1 - re-execute a historical tx on a LOCAL
Anvil fork and read its call tree + state diff.

The public endpoint does not serve `debug_traceTransaction`; a local Anvil fork
does. We fork at the tx's previous block, impersonate the sender, submit the
exact `{to, data, value}`, and read `callTracer` + `prestateTracer(diffMode)`
against the local node. Nothing is broadcast.

CAVEAT, recorded not hidden: the replay omits any same-block transactions that
ran BEFORE the target. For protocol calls that do not depend on same-block
ordering this matches on-chain behaviour; where it might not, the Trace is
marked `source="anvil-reexec"` so a consumer can weight it accordingly.
"""

from __future__ import annotations

from typing import Optional

from ..execground import foundry as F
from . import model as M
from .rpc import RpcClient

_BIG_BALANCE = 10 ** 24   # 1,000,000 ETH for the impersonated sender's gas


def enrich_many(collection: M.Collection, *, fork_rpc_url: str,
                toolchain: Optional[F.Toolchain] = None,
                max_txs: int = 40, span_blocks: int = 300) -> dict[str, M.Trace]:
    """Enrich up to `max_txs` transactions by re-executing them on a LOCAL
    Anvil fork. One fork per contiguous `span_blocks` window (a snapshot/revert
    isolates each replay), so a normal collection costs ONE anvil startup.

    Caveat, recorded: a tx is replayed against the state at the window's fork
    point (`min(block)-1`), not its exact position - same-window txs that ran
    earlier are omitted. `Trace.source == "anvil-reexec"` marks this.
    """
    tc = toolchain or F.resolve()
    out: dict[str, M.Trace] = {}
    txs = collection.txs[:max_txs]
    if tc is None or not F.anvil_available() or not txs:
        for tx in txs:
            out[tx.hash] = M.Trace(tx=tx, source="tx-only")
        return out

    # split into windows so a very wide collection still forks at fresh-ish state
    txs = sorted(txs, key=lambda t: t.block)
    windows: list[list[M.TxRecord]] = []
    cur: list[M.TxRecord] = []
    base = txs[0].block
    for tx in txs:
        if cur and tx.block - base > span_blocks:
            windows.append(cur)
            cur, base = [], tx.block
        cur.append(tx)
    if cur:
        windows.append(cur)

    for group in windows:
        fork_block = max(group[0].block - 1, 0)
        try:
            with F.AnvilFork(tc, fork_url=fork_rpc_url, fork_block=fork_block,
                             timeout=120) as fork:
                frpc = RpcClient(fork.rpc_url, timeout=45)
                snap = None
                try:
                    snap = frpc.anvil_snapshot()
                except Exception:  # noqa: BLE001
                    snap = None
                for tx in group:
                    out[tx.hash] = _one(frpc, tx)
                    if snap:
                        try:
                            frpc.anvil_revert(snap)
                            snap = frpc.anvil_snapshot()
                        except Exception:  # noqa: BLE001
                            pass
        except Exception as exc:  # noqa: BLE001
            for tx in group:
                out.setdefault(tx.hash, M.Trace(tx=tx, source="tx-only"))
            collection.notes.append(
                f"enrich fork @ {fork_block} failed: {type(exc).__name__}: "
                f"{str(exc)[:140]}")
    for tx in txs:
        out.setdefault(tx.hash, M.Trace(tx=tx, source="tx-only"))
    return out


def _one(frpc: RpcClient, tx: M.TxRecord) -> M.Trace:
    tr = M.Trace(tx=tx, source="anvil-reexec")
    try:
        frpc.anvil_set_balance(tx.sender, _BIG_BALANCE)
        frpc.anvil_impersonate(tx.sender)
        req = {"from": tx.sender, "to": tx.to, "value": hex(tx.value),
               "data": tx.input, "gas": hex(12_000_000)}
        try:
            h = frpc.send_tx(req)
        except Exception as exc:  # noqa: BLE001 - a revert here is real signal
            tr.tx.revert_reason = tr.tx.revert_reason or f"reexec send: {exc}"[:160]
            return tr
        try:
            frpc.anvil_mine()
        except Exception:  # noqa: BLE001 - auto-mine may already have run
            pass
        rc = frpc.get_receipt(h)
        if rc:
            tr.tx.status = int(rc.get("status", "0x0"), 16) == 1
            tr.event_topics = [(lg.get("topics") or ["0x"])[0]
                               for lg in rc.get("logs", [])]
            tr.transfers = _transfers_from_logs(rc.get("logs", []), tx.hash, tx.block)
        try:
            tr.call_tree = _parse_call_tree(frpc.debug_trace_call_tree(h), depth=0)
        except Exception:  # noqa: BLE001
            pass
        try:
            tr.state_diff = _parse_prestate_diff(frpc.debug_prestate_diff(h))
        except Exception:  # noqa: BLE001
            pass
    finally:
        try:
            frpc.anvil_stop_impersonate(tx.sender)
        except Exception:  # noqa: BLE001
            pass
    return tr


_KIND = {"CALL": "CALL", "STATICCALL": "STATICCALL", "DELEGATECALL": "DELEGATECALL",
         "CREATE": "CREATE", "CREATE2": "CREATE"}


def _parse_call_tree(node: dict, depth: int) -> Optional[M.TraceCall]:
    if not node:
        return None
    tc = M.TraceCall(
        frm=(node.get("from") or "").lower(),
        to=(node.get("to") or "").lower(),
        kind=_KIND.get((node.get("type") or "CALL").upper(), "CALL"),
        input=node.get("input", "0x") or "0x",
        output=node.get("output", "") or "",
        value=int(node.get("value", "0x0") or "0x0", 16)
        if str(node.get("value", "0")).startswith("0x") else int(node.get("value", 0) or 0),
        success=not node.get("error"),
        error=node.get("error", "") or "",
        depth=depth)
    for ch in node.get("calls", []) or []:
        c = _parse_call_tree(ch, depth + 1)
        if c:
            tc.children.append(c)
    return tc


def _parse_prestate_diff(diff: dict) -> dict:
    """`prestateTracer` with `diffMode: true` returns {"pre": {...}, "post": {...}}.
    Fold into {addr: {"storage": {slot: [pre, post]}, "balance": [pre, post],
    "nonce": [...], "code_changed": bool}}."""
    pre = diff.get("pre", {}) or {}
    post = diff.get("post", {}) or {}
    out: dict = {}
    for addr in set(pre) | set(post):
        a = addr.lower()
        p, q = pre.get(addr, {}) or {}, post.get(addr, {}) or {}
        entry: dict = {}
        ps, qs = p.get("storage", {}) or {}, q.get("storage", {}) or {}
        slots = {}
        for slot in set(ps) | set(qs):
            slots[slot] = [ps.get(slot), qs.get(slot)]
        if slots:
            entry["storage"] = slots
        if "balance" in p or "balance" in q:
            entry["balance"] = [p.get("balance"), q.get("balance")]
        if "nonce" in p or "nonce" in q:
            entry["nonce"] = [p.get("nonce"), q.get("nonce")]
        if p.get("code") != q.get("code") and ("code" in p or "code" in q):
            entry["code_changed"] = True
        if entry:
            out[a] = entry
    return out


def _transfers_from_logs(logs: list, base_hash: str, block: int) -> list:
    from .collect import _decode_transfer
    out = []
    for lg in logs:
        lg = dict(lg)
        lg.setdefault("transactionHash", base_hash)
        lg.setdefault("blockNumber", hex(block))
        t = _decode_transfer(lg)
        if t:
            out.append(t)
    return out
