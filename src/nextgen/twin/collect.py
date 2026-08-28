"""Phase 1 - collect real on-chain transactions for a target address.

Uses only cheap, universally-available JSON-RPC. Deep call traces + state diffs
are NOT fetched here - the free-tier endpoint does not serve
`debug_traceTransaction` - they come from re-executing a tx on a local Anvil
fork in `enrich.py`.

Transaction enumeration, best available first:
  1. `alchemy_getAssetTransfers` (to + from the address) when the endpoint
     supports it - every value-moving interaction, incl. internal.
  2. `eth_getLogs` address-filtered - every interaction that emitted a log
     from the address (catches successful non-value calls).
  3. in every block already implicated by (1)/(2), each tx whose `to` is the
     address - catches direct calls that REVERTED (no logs, no transfers).

Fully-silent reverted calls made THROUGH a router are not enumerable without a
tracing indexer; this is recorded in `Collection.notes`, not hidden. Pass
`deep_blocks=(lo, hi)` to force a full `eth_getBlockByNumber` scan of a narrow
window when reverted-input coverage matters.
"""

from __future__ import annotations

from typing import Optional

from . import model as M
from .rpc import (RpcClient, TOPIC_TRANSFER, TOPIC_TRANSFER_BATCH,
                  TOPIC_TRANSFER_SINGLE)

_LOG_CHUNK = 3000


def _addr(topic_or_word: str) -> str:
    return "0x" + topic_or_word[-40:]


def _int(hexstr) -> int:
    if hexstr in (None, "0x", ""):
        return 0
    return int(hexstr, 16)


def collect(rpc: RpcClient, address: str, *, from_block: int, to_block: int,
            max_txs: int = 250, log_chunk: int = _LOG_CHUNK,
            deep_blocks: Optional[tuple[int, int]] = None) -> M.Collection:
    address = address.lower()
    col = M.Collection(address=address, chain_id=_safe_chain_id(rpc),
                       from_block=from_block, to_block=to_block)
    col.trace_capable = rpc.supports(
        "debug_traceTransaction",
        ["0x" + "0" * 64, {"tracer": "callTracer"}])
    if not col.trace_capable:
        col.notes.append("endpoint has no debug/trace API - deep traces come "
                         "from local Anvil re-execution")

    log_blocks: set[int] = set()
    seen_tx: dict[str, dict] = {}

    # 0. alchemy_getAssetTransfers (to + from) - the best enumeration when
    #    available. Each entry carries a tx hash + block.
    if _alchemy_transfers(rpc, address, from_block, to_block, seen_tx,
                          log_blocks, stop_at=max_txs * 6):
        col.notes.append("enumerated via alchemy_getAssetTransfers")
    else:
        col.notes.append("alchemy_getAssetTransfers unavailable - using "
                         "eth_getLogs enumeration (reverted silent calls may "
                         "be missed)")

    # 1. logs emitted by the address -> candidate blocks + tx hashes.
    #    Shrink the chunk locally on failure (a busy address exceeds the
    #    provider's per-response log cap); never restart the whole collect.
    b, cur = from_block, log_chunk
    while b <= to_block:
        hi = min(b + cur - 1, to_block)
        try:
            logs = rpc.get_logs(from_block=b, to_block=hi, address=address)
        except Exception:  # noqa: BLE001
            if cur > 25:
                cur = max(cur // 4, 25)
                continue
            col.notes.append(f"getLogs gave up on {b}-{hi} (log cap); some "
                             f"non-value interactions may be missed")
            b = hi + 1
            continue
        for lg in logs:
            blk = _int(lg.get("blockNumber"))
            log_blocks.add(blk)
            th = lg.get("transactionHash")
            if th:
                col.logs_by_tx.setdefault(th, []).append(lg)
                seen_tx.setdefault(th, {"block": blk})
        b = hi + 1
        if cur < log_chunk:                     # recovered - grow back
            cur = min(cur * 2, log_chunk)

    # cap the candidate set BEFORE the per-hash tx/receipt fetches - a busy
    # address (WETH, a big AMM) can return tens of thousands of transfers.
    budget = max_txs * 4
    if len(seen_tx) > budget:
        keep = sorted(seen_tx.items(),
                      key=lambda kv: kv[1].get("block", 0), reverse=True)[:budget]
        seen_tx = dict(keep)
        col.notes.append(f"candidate set capped to the {budget} most recent "
                         f"(address is high-traffic)")

    # 2. optional deep block scan of a narrow window -> reverted silent calls
    scan_lo, scan_hi = deep_blocks or (0, -1)
    for blk in range(scan_lo, scan_hi + 1):
        try:
            block = rpc.get_block(blk, full=True)
        except Exception:  # noqa: BLE001
            continue
        ts = _int(block.get("timestamp"))
        for tx in block.get("transactions", []):
            if (tx.get("to") or "").lower() != address:
                continue
            seen_tx.setdefault(tx["hash"], {})
            seen_tx[tx["hash"]].update(_tx=tx, _ts=ts, block=blk)

    # 3. build TxRecords + decode token transfers from each receipt's logs.
    #    Batch the tx / receipt fetches - a wide window is hundreds of hashes.
    hashes = list(seen_tx)
    need_tx = [h for h in hashes if seen_tx[h].get("_tx") is None]
    if hasattr(rpc, "batch") and need_tx:
        txs = rpc.batch([("eth_getTransactionByHash", [h]) for h in need_tx])
        for h, tx in zip(need_tx, txs):
            if tx:
                seen_tx[h]["_tx"] = tx
    rcs: dict[str, dict] = {}
    if hasattr(rpc, "batch"):
        got = rpc.batch([("eth_getTransactionReceipt", [h]) for h in hashes])
        rcs = {h: g for h, g in zip(hashes, got) if g}

    records: list[M.TxRecord] = []
    for h, meta in seen_tx.items():
        tx = meta.get("_tx")
        try:
            if tx is None:
                tx = rpc.get_tx(h)
            rc = rcs.get(h) or rpc.get_receipt(h)
        except Exception:  # noqa: BLE001
            continue
        if not tx or not rc:
            continue
        inp = tx.get("input", "0x") or "0x"
        rec = M.TxRecord(
            hash=h, block=_int(tx.get("blockNumber")) or meta.get("block", 0),
            tx_index=_int(tx.get("transactionIndex")),
            sender=(tx.get("from") or "").lower(),
            to=(tx.get("to") or "").lower(),
            value=_int(tx.get("value")),
            input=inp, selector=inp[:10] if len(inp) >= 10 else inp,
            status=_int(rc.get("status")) == 1,
            gas_used=_int(rc.get("gasUsed")),
            nonce=_int(tx.get("nonce")),
            timestamp=meta.get("_ts", 0))
        # keep txs that target the address directly, emitted a log from it, or
        # moved an asset to/from it (alchemy enumeration)
        if not (rec.to == address or h in col.logs_by_tx or meta.get("_asset")):
            continue
        records.append(rec)
        for lg in rc.get("logs", []) or []:
            lg = {**lg, "transactionHash": lg.get("transactionHash", h),
                  "blockNumber": lg.get("blockNumber", hex(rec.block))}
            col.logs_by_tx.setdefault(h, []).append(lg)
            t = _decode_transfer(lg)
            if t and address in (t.frm, t.to):
                col.transfers.append(t)

    records.sort(key=lambda r: (r.block, r.tx_index))
    col.txs = records[:max_txs]
    col.transfers = [t for t in col.transfers
                     if t.tx_hash in {r.hash for r in col.txs}]
    if len(records) > max_txs:
        col.notes.append(f"{len(records)} txs found, kept the first {max_txs}")

    # 5. proxy implementation samples across the window
    for blk in _sample_blocks(from_block, to_block, 5):
        try:
            impl = rpc.implementation_at(address, blk)
        except Exception:  # noqa: BLE001
            impl = None
        col.impl_samples.append((blk, impl.lower() if impl else None))

    return col


def _decode_transfer(lg: dict) -> Optional[M.TransferEvent]:
    topics = lg.get("topics") or []
    if not topics:
        return None
    t0 = topics[0].lower()
    data = lg.get("data", "0x") or "0x"
    blk = _int(lg.get("blockNumber"))
    th = lg.get("transactionHash", "")
    li = _int(lg.get("logIndex"))
    token = (lg.get("address") or "").lower()

    if t0 == TOPIC_TRANSFER and len(topics) == 3:              # ERC20
        return M.TransferEvent(token, M.ERC20, _addr(topics[1]), _addr(topics[2]),
                               _int(data), tx_hash=th, log_index=li, block=blk)
    if t0 == TOPIC_TRANSFER and len(topics) == 4:              # ERC721
        return M.TransferEvent(token, M.ERC721, _addr(topics[1]), _addr(topics[2]),
                               _int(topics[3]), token_id=_int(topics[3]),
                               tx_hash=th, log_index=li, block=blk)
    if t0 == TOPIC_TRANSFER_SINGLE and len(topics) >= 4:       # ERC1155
        words = data[2:]
        tid = _int("0x" + words[:64]) if len(words) >= 64 else 0
        amt = _int("0x" + words[64:128]) if len(words) >= 128 else 0
        return M.TransferEvent(token, M.ERC1155, _addr(topics[2]), _addr(topics[3]),
                               amt, token_id=tid, tx_hash=th, log_index=li, block=blk)
    if t0 == TOPIC_TRANSFER_BATCH and len(topics) >= 4:
        return M.TransferEvent(token, M.ERC1155, _addr(topics[2]), _addr(topics[3]),
                               0, token_id=None, tx_hash=th, log_index=li, block=blk)
    return None


def _alchemy_transfers(rpc: RpcClient, address: str, lo: int, hi: int,
                       seen_tx: dict, log_blocks: set, *, stop_at: int = 2000
                       ) -> bool:
    """Populate `seen_tx` from `alchemy_getAssetTransfers` (to + from the
    address), newest first, stopping once `stop_at` distinct hashes are seen.
    Returns False if the endpoint does not support it."""
    cats = ["external", "internal", "erc20", "erc721", "erc1155"]
    got_any = False
    for direction in ("toAddress", "fromAddress"):
        if len(seen_tx) >= stop_at:
            break
        page = None
        for _ in range(20):
            params = {"fromBlock": hex(lo), "toBlock": hex(hi),
                      direction: address, "category": cats, "order": "desc",
                      "withMetadata": False, "excludeZeroValue": False,
                      "maxCount": "0x3e8"}
            if page:
                params["pageKey"] = page
            try:
                res = rpc.call("alchemy_getAssetTransfers", [params])
            except Exception:  # noqa: BLE001
                return got_any
            if res is None:
                return got_any
            got_any = True
            for t in res.get("transfers", []) or []:
                h = t.get("hash")
                if not h:
                    continue
                blk = int(t.get("blockNum", "0x0"), 16)
                m = seen_tx.setdefault(h, {})
                m["block"] = blk
                m["_asset"] = True
                log_blocks.add(blk)
            page = res.get("pageKey")
            if not page or len(seen_tx) >= stop_at:
                break
    return got_any


def _sample_blocks(lo: int, hi: int, n: int) -> list[int]:
    if hi <= lo:
        return [lo]
    step = max((hi - lo) // (n - 1), 1)
    pts = list(range(lo, hi + 1, step))
    if pts[-1] != hi:
        pts.append(hi)
    return pts


def _safe_chain_id(rpc: RpcClient) -> int:
    try:
        return rpc.chain_id()
    except Exception:  # noqa: BLE001
        return 0
