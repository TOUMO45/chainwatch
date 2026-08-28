"""Counterfactual Twin - Phase 6 replay + Phase 8 minimise (src/nextgen/twin/replay.py).

Pure unit tests use a fake RpcClient (no network, no fork). One integration
test at the bottom needs a reachable Foundry toolchain + fork RPC and skips
visibly otherwise, same gate as test_nextgen_twin_anvil.py.

Run:  python -m pytest tests/test_nextgen_twin_replay.py -q
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:  # noqa: BLE001
    pass

from src.nextgen.twin import model as M, replay as R  # noqa: E402
from src.nextgen.execground import foundry as F  # noqa: E402
from src.nextgen.twin.rpc import RpcClient  # noqa: E402


class _FakeRpc:
    """Records every call made against it; answers just enough to exercise
    replay()'s control flow without a real node."""

    def __init__(self, *, send_fails: bool = False, status_hex: str = "0x1"):
        self.calls: list[tuple] = []
        self._send_fails = send_fails
        self._status_hex = status_hex
        self._balances: dict[str, int] = {}

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "eth_getBalance":
            return hex(self._balances.get(params[0], 0))
        return None

    def anvil_set_storage_at(self, addr, slot, value):
        self.calls.append(("anvil_set_storage_at", addr, slot, value))

    def anvil_set_balance(self, addr, wei):
        self._balances[addr] = wei
        self.calls.append(("anvil_set_balance", addr, wei))

    def anvil_impersonate(self, addr):
        self.calls.append(("anvil_impersonate", addr))

    def anvil_stop_impersonate(self, addr):
        self.calls.append(("anvil_stop_impersonate", addr))

    def anvil_mine(self, n=1):
        self.calls.append(("anvil_mine", n))

    def send_tx(self, tx):
        if self._send_fails:
            raise RuntimeError("simulated revert")
        return "0x" + "9" * 64

    def get_receipt(self, h):
        return {"status": self._status_hex, "gasUsed": "0x5208", "logs": []}

    def debug_trace_call_tree(self, h):
        return {}

    def debug_prestate_diff(self, h):
        return {}


def _mutation(calls=None, overrides=None, delay=None) -> M.Mutation:
    return M.Mutation(
        kind=M.ACTOR_SUBSTITUTION, base_tx="0x" + "a" * 64, selector="0x12345678",
        statement="test mutation",
        calls=calls or [{"from": "0x" + "1" * 40, "to": "0x" + "d" * 40,
                        "value": 0, "data": "0x12345678"}],
        state_overrides=overrides or {}, fork_block=100,
        detail={"delay_seconds": delay} if delay else {})


def test_replay_with_no_calls_errors_without_touching_rpc():
    fake = _FakeRpc()
    res = R.replay(fake, M.Mutation(kind=M.REPETITION, base_tx="0x", selector="0x1",
                                    statement="empty", calls=[]))
    assert not res.executed
    assert "no calls" in res.error
    assert fake.calls == []


def test_replay_executes_every_call_and_marks_executed():
    fake = _FakeRpc()
    mut = _mutation(calls=[{"from": "0x" + "1" * 40, "to": "0x" + "d" * 40,
                            "value": 0, "data": "0x12345678"}] * 2)
    res = R.replay(fake, mut)
    assert res.executed
    assert len(res.all_traces) == 2
    assert res.trace is res.all_traces[-1]


def test_replay_applies_state_overrides_before_sending():
    fake = _FakeRpc()
    mut = _mutation(overrides={"0xtarget": {"0xslot": "0xvalue"}})
    R.replay(fake, mut)
    assert ("anvil_set_storage_at", "0xtarget", "0xslot", "0xvalue") in fake.calls


def test_replay_applies_delay_before_sending():
    fake = _FakeRpc()
    mut = _mutation(delay=86400)
    R.replay(fake, mut)
    assert ("evm_increaseTime", [86400]) in fake.calls


def test_replay_records_send_failure_without_raising():
    fake = _FakeRpc(send_fails=True)
    mut = _mutation()
    res = R.replay(fake, mut)
    assert not res.executed
    assert "send:" in res.error


def test_replay_marks_tx_status_from_receipt():
    fake = _FakeRpc(status_hex="0x0")
    mut = _mutation()
    res = R.replay(fake, mut)
    assert res.trace.tx.status is False


def test_minimize_calls_never_drops_the_last_call():
    mut = _mutation(calls=[{"from": "a", "to": "t", "value": 0, "data": "0x1"},
                          {"from": "a", "to": "t", "value": 0, "data": "0x2"},
                          {"from": "a", "to": "t", "value": 0, "data": "0x3"}])

    def verify(m):
        return True    # everything reproduces - should collapse to 1 call

    out = R.minimize_calls(mut, verify)
    assert len(out.calls) == 1
    assert out.calls[0]["data"] == "0x3"


def test_minimize_calls_keeps_a_call_that_verify_needs():
    mut = _mutation(calls=[{"from": "a", "to": "t", "value": 0, "data": "setup"},
                          {"from": "a", "to": "t", "value": 0, "data": "objective"}])

    def verify(m):
        return len(m.calls) >= 2   # only reproduces with BOTH calls present

    out = R.minimize_calls(mut, verify)
    assert len(out.calls) == 2


def test_minimize_calls_is_a_noop_on_a_single_call_mutation():
    mut = _mutation()
    out = R.minimize_calls(mut, lambda m: True)
    assert out.calls == mut.calls


# --------------------------------------------------------------------- integration

_FORK_RPC = os.environ.get("CHAINWATCH_FORK_RPC") or os.environ.get("RPC_URL")
_TC = F.resolve()
_CAN = _TC is not None and F.anvil_available() and bool(_FORK_RPC)


@pytest.mark.skipif(not _CAN, reason="needs a Foundry toolchain with anvil and a fork RPC")
def test_replay_on_fresh_fork_against_real_weth():
    """A real, unprivileged eth_call-shaped mutation against WETH's public
    `deposit()` - always succeeds for anyone, so this is a genuine end-to-end
    replay proof, not a synthetic fixture."""
    weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    live = RpcClient(_FORK_RPC, timeout=20)
    block = live.block_number() - 50
    mut = M.Mutation(
        kind=M.ACTOR_SUBSTITUTION, base_tx="0x" + "0" * 64, selector="0xd0e30db0",
        statement="call WETH.deposit() from an unprivileged address",
        calls=[{"from": "0x2222222222222222222222222222222222222222",
               "to": weth, "value": 10 ** 15, "data": "0xd0e30db0"}],
        fork_block=block)
    res = R.replay_on_fresh_fork(_TC, _FORK_RPC, mut)
    assert res.executed, res.error
    assert res.trace.tx.status is True
