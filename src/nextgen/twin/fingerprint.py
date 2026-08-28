"""Phase 2 - behavioral fingerprints per function.

For every 4-byte selector seen calling the target address, aggregate across all
observed transactions:

  * accepted vs rejected (success / revert)
  * the caller set on each side
  * msg.value buckets
  * calldata-length classes (a coarse "input shape" without an ABI)
  * asset flows (did the address send / receive a token in this call)
  * emitted event topic0s
  * cross-contract call targets  (from the enriched call tree)
  * storage slots written        (from the enriched state diff)

These are the raw material for Phase 3 boundary mining and Phase 4 version
divergence.
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

from . import model as M


def _value_bucket(wei: int) -> str:
    if wei == 0:
        return "zero"
    if wei < 10 ** 15:            # < 0.001 ETH
        return "dust"
    if wei < 10 ** 19:           # < 10 ETH
        return "normal"
    return "large"


def build_fingerprints(collection: M.Collection,
                       traces: Optional[dict[str, M.Trace]] = None
                       ) -> dict[str, M.FunctionFingerprint]:
    traces = traces or {}
    addr = collection.address.lower()
    fps: dict[str, M.FunctionFingerprint] = {}

    # index transfers by tx hash for quick asset-flow lookup
    tx_transfers: dict[str, list[M.TransferEvent]] = {}
    for t in collection.transfers:
        tx_transfers.setdefault(t.tx_hash, []).append(t)

    for tx in collection.txs:
        # only fingerprint calls that TARGET the address directly (a selector
        # into the address); indirect interactions still feed asset flows below
        if tx.to != addr:
            continue
        sel = tx.selector if len(tx.selector) == 10 else "0x00000000"
        fp = fps.get(sel)
        if fp is None:
            fp = M.FunctionFingerprint(address=addr, selector=sel)
            fps[sel] = fp
        fp.n_total += 1
        clen = len(tx.input)
        if tx.status:
            fp.n_success += 1
            fp.callers_success.add(tx.sender)
            fp.value_buckets[_value_bucket(tx.value)] = \
                fp.value_buckets.get(_value_bucket(tx.value), 0) + 1
            fp.calldata_len_success.add(clen)
            if len(fp.example_success) < 5:
                fp.example_success.append(tx.hash)
        else:
            fp.n_revert += 1
            fp.callers_revert.add(tx.sender)
            fp.calldata_len_revert.add(clen)
            if len(fp.example_revert) < 5:
                fp.example_revert.append(tx.hash)

        # asset flow for this call
        for tr in tx_transfers.get(tx.hash, []):
            if tr.to == addr:
                fp.transfers_in += 1
            if tr.frm == addr:
                fp.transfers_out += 1

        # enriched signals
        trace = traces.get(tx.hash)
        if trace is not None:
            for topic in trace.event_topics:
                fp.event_topics[topic] = fp.event_topics.get(topic, 0) + 1
            for to, callsel in trace.external_calls():
                if to and to != addr:
                    fp.external_call_targets.add((to, callsel))
            sd = trace.state_diff.get(addr, {})
            for slot in (sd.get("storage") or {}):
                fp.storage_slots_written.add(slot)

    return fps


def summarize(fps: dict[str, M.FunctionFingerprint]) -> str:
    lines = ["BEHAVIORAL FINGERPRINTS (Phase 2)", "=" * 33, ""]
    for sel, fp in sorted(fps.items(), key=lambda kv: -kv[1].n_total):
        ex = fp.caller_exclusive
        lines.append(
            f"  {sel}  n={fp.n_total:<4} ok={fp.n_success:<4} rv={fp.n_revert:<4} "
            f"revert_rate={fp.revert_rate}")
        if ex:
            lines.append(f"       exclusive callers: {sorted(ex)}")
        if fp.value_buckets:
            lines.append(f"       value: {dict(fp.value_buckets)}")
        if fp.transfers_in or fp.transfers_out:
            lines.append(f"       token flow: in={fp.transfers_in} out={fp.transfers_out}")
        if fp.external_call_targets:
            lines.append(f"       calls out: "
                         f"{sorted(f'{a[:10]}:{s}' for a, s in fp.external_call_targets)[:6]}")
    return "\n".join(lines)
