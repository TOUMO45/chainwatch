"""Phase 6 - execute a Mutation on an isolated Anvil fork at the exact
historical state, and Phase 8 - minimise a violating chain of mutations to
the smallest one that still reproduces it.

Never broadcasts: every call in `Mutation.calls` goes to a LOCAL fork's
`eth_sendTransaction` (an anvil-only RPC method - see `rpc.RpcClient.send_tx`'s
own docstring), impersonating the sender rather than signing anything.
`state_overrides` are applied via `anvil_setStorageAt` before the calls run;
a `detail["delay_seconds"]` mutation (DELAY / ORACLE_STATE) advances the
fork's clock with `evm_increaseTime` + `evm_mine` first.

Phase 8 reuses the SAME delta-debugging algorithm as
`execground/sequences.minimize` - repeatedly try dropping one non-final call
and keep the drop if `verify` still reproduces - adapted to operate directly
on a replayed `Mutation`'s real `calls` rather than generated Foundry-test
source: the Twin's Phase 6 replays real transactions against a live fork over
RPC, it never compiles a test, so `sequences.CandidateSequence` (a Solidity
source generator) is not the right shape here. The algorithm is identical;
only what gets verified differs.
"""

from __future__ import annotations

from typing import Callable, Optional

from ..execground import foundry as F
from . import model as M
from .enrich import _parse_call_tree, _parse_prestate_diff, _transfers_from_logs
from .rpc import RpcClient

_BIG_BALANCE = 10 ** 24


def replay(fork_rpc: RpcClient, mutation: M.Mutation, *,
          on_call: Optional[Callable[[dict, "M.Trace"], None]] = None
          ) -> M.ReplayResult:
    """Execute every call in `mutation.calls`, in order, on `fork_rpc` (an
    already-running `AnvilFork`'s RpcClient - this function never starts or
    stops a fork itself, so a caller replaying many mutations against the
    same historical block can share one fork and snapshot/revert between
    them, exactly as `enrich.enrich_many` already does for Phase 1)."""
    res = M.ReplayResult(mutation=mutation, executed=False)
    if not mutation.calls:
        res.error = "mutation carries no calls"
        return res

    try:
        _apply_overrides(fork_rpc, mutation.state_overrides)
        _apply_delay(fork_rpc, mutation.detail.get("delay_seconds"))
    except Exception as exc:  # noqa: BLE001
        res.error = f"pre-replay setup failed: {type(exc).__name__}: {exc}"
        return res

    senders = {c.get("from") for c in mutation.calls if c.get("from")}
    for addr in senders:
        try:
            fork_rpc.anvil_set_balance(addr, _BIG_BALANCE)
            fork_rpc.anvil_impersonate(addr)
        except Exception:  # noqa: BLE001
            pass

    res.balances_before = _sample_balances(fork_rpc, mutation)

    all_submitted = True
    try:
        for call in mutation.calls:
            tr = _one_call(fork_rpc, call)
            res.all_traces.append(tr)
            if on_call:
                try:
                    on_call(call, tr)
                except Exception:  # noqa: BLE001
                    pass
            if tr.tx.revert_reason.startswith("send:"):
                # the call could not even be SUBMITTED (e.g. impersonation
                # rejected, malformed request) - stop the chain here, report
                # what ran so far. Distinct from an on-chain revert (which
                # `send_tx` does NOT raise for - anvil returns a real tx hash
                # for a transaction that will revert, and that is captured by
                # `tr.tx.status`, not here): a submission failure means the
                # mutation was never actually exercised, so `executed` must
                # be False even though a trace entry was still recorded for
                # it - checking only the trace COUNT against the call count
                # missed this, since the failed call still appends one entry.
                res.error = tr.tx.revert_reason
                all_submitted = False
                break
        res.executed = all_submitted
        if res.all_traces:
            res.trace = res.all_traces[-1]
    finally:
        for addr in senders:
            try:
                fork_rpc.anvil_stop_impersonate(addr)
            except Exception:  # noqa: BLE001
                pass

    res.balances_after = _sample_balances(fork_rpc, mutation)
    return res


def _apply_overrides(fork_rpc: RpcClient, overrides: dict) -> None:
    for addr, slots in (overrides or {}).items():
        for slot, value in slots.items():
            fork_rpc.anvil_set_storage_at(addr, slot, value)


def _apply_delay(fork_rpc: RpcClient, seconds: Optional[int]) -> None:
    if not seconds:
        return
    try:
        fork_rpc.call("evm_increaseTime", [seconds])
    except Exception:  # noqa: BLE001
        pass
    fork_rpc.anvil_mine()


def _sample_balances(fork_rpc: RpcClient, mutation: M.Mutation) -> dict:
    addrs = {c.get("to") for c in mutation.calls if c.get("to")}
    addrs |= {c.get("from") for c in mutation.calls if c.get("from")}
    out = {}
    for a in addrs:
        try:
            out[a] = int(fork_rpc.call("eth_getBalance", [a, "latest"]), 16)
        except Exception:  # noqa: BLE001
            continue
    return out


def _one_call(fork_rpc: RpcClient, call: dict) -> M.Trace:
    """Submit ONE call to the local fork and read back what happened. Reuses
    `enrich.py`'s own tracer parsing so a replayed trace has the exact same
    shape as an enriched Phase-1 one - Phase 7's checks can compare them
    without a second parser to keep in sync."""
    fake_tx = M.TxRecord(hash="", block=0, tx_index=0,
                         sender=call.get("from", ""), to=call.get("to", ""),
                         value=int(call.get("value", 0) or 0),
                         input=call.get("data", "0x") or "0x",
                         selector=(call.get("data") or "0x")[:10], status=False)
    tr = M.Trace(tx=fake_tx, source="anvil-reexec")
    req = {"from": call["from"], "to": call["to"],
          "value": hex(int(call.get("value", 0) or 0)),
          "data": call.get("data", "0x") or "0x", "gas": hex(12_000_000)}
    try:
        h = fork_rpc.send_tx(req)
    except Exception as exc:  # noqa: BLE001 - a revert here IS the signal
        fake_tx.revert_reason = f"send: {type(exc).__name__}: {exc}"[:200]
        return tr
    fake_tx.hash = h
    try:
        fork_rpc.anvil_mine()
    except Exception:  # noqa: BLE001
        pass
    rc = fork_rpc.get_receipt(h)
    if rc:
        fake_tx.status = int(rc.get("status", "0x0"), 16) == 1
        fake_tx.gas_used = int(rc.get("gasUsed", "0x0"), 16)
        tr.event_topics = [(lg.get("topics") or ["0x"])[0] for lg in rc.get("logs", [])]
        tr.transfers = _transfers_from_logs(rc.get("logs", []), h, 0)
    try:
        tr.call_tree = _parse_call_tree(fork_rpc.debug_trace_call_tree(h), depth=0)
    except Exception:  # noqa: BLE001
        pass
    try:
        tr.state_diff = _parse_prestate_diff(fork_rpc.debug_prestate_diff(h))
    except Exception:  # noqa: BLE001
        pass
    return tr


# --------------------------------------------------------------------------- #
# Phase 8 - minimise a reproducing call chain (ddmin, same algorithm as
# execground/sequences.minimize; see the module docstring for why this is a
# parallel implementation rather than a literal call into that function).
# --------------------------------------------------------------------------- #

def minimize_calls(mutation: M.Mutation,
                   verify: Callable[[M.Mutation], bool]) -> M.Mutation:
    """Delta-debug `mutation.calls` to the smallest prefix-preserving subset
    `verify` still accepts. The LAST call (the objective - the one whose
    outcome IS the violation) is never dropped, same rule as
    `sequences.minimize`. `verify(candidate)` returns True iff replaying that
    candidate still reproduces the violation."""
    calls = list(mutation.calls)
    changed = True
    while changed and len(calls) > 1:
        changed = False
        for i in range(len(calls) - 2, -1, -1):     # never drop the last call
            trial_calls = calls[:i] + calls[i + 1:]
            trial = M.Mutation(kind=mutation.kind, base_tx=mutation.base_tx,
                               selector=mutation.selector,
                               statement=mutation.statement + " (minimised)",
                               calls=trial_calls,
                               state_overrides=mutation.state_overrides,
                               fork_block=mutation.fork_block,
                               weight=mutation.weight, detail=mutation.detail)
            if verify(trial):
                calls = trial_calls
                changed = True
                break
    return M.Mutation(kind=mutation.kind, base_tx=mutation.base_tx,
                      selector=mutation.selector,
                      statement=mutation.statement + " (minimised)",
                      calls=calls, state_overrides=mutation.state_overrides,
                      fork_block=mutation.fork_block, weight=mutation.weight,
                      detail=mutation.detail)


def replay_on_fresh_fork(tc: F.Toolchain, fork_url: str, mutation: M.Mutation,
                        *, timeout: int = 100) -> M.ReplayResult:
    """Convenience: a whole fork lifecycle for ONE mutation - used by the
    Phase 8 minimiser's `verify` callback (each trial needs a clean, unaffected
    fork state, not the accumulated state of a shared one) and by Phase 10's
    blinded reproducer (a genuinely independent second execution)."""
    try:
        with F.AnvilFork(tc, fork_url=fork_url, fork_block=mutation.fork_block,
                         timeout=timeout) as fork:
            frpc = RpcClient(fork.rpc_url, timeout=45)
            return replay(frpc, mutation)
    except Exception as exc:  # noqa: BLE001
        return M.ReplayResult(mutation=mutation, executed=False,
                              error=f"{type(exc).__name__}: {exc}"[:200])
