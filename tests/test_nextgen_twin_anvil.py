"""Counterfactual Twin - the Anvil fork lifecycle (execground/foundry.AnvilFork).

Integration: needs a reachable Foundry toolchain (native or WSL) AND a fork RPC
(`RPC_URL` in .env, or CHAINWATCH_FORK_RPC). Skips visibly otherwise.

Run:  python -m pytest tests/test_nextgen_twin_anvil.py -q
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

from src.nextgen.execground import foundry as F  # noqa: E402
from src.nextgen.twin.rpc import RpcClient  # noqa: E402

_FORK_RPC = os.environ.get("CHAINWATCH_FORK_RPC") or os.environ.get("RPC_URL")
_TC = F.resolve()
_CAN = _TC is not None and F.anvil_available() and bool(_FORK_RPC)

pytestmark = pytest.mark.skipif(
    not _CAN, reason="needs a Foundry toolchain with anvil and a fork RPC")


def test_anvil_fork_starts_serves_and_stops():
    with F.AnvilFork(_TC, fork_url=_FORK_RPC, timeout=120) as fork:
        rpc = RpcClient(fork.rpc_url, timeout=20)
        bn = rpc.block_number()
        assert bn > 15_000_000                     # a real mainnet fork
        # anvil-only cheatcodes work against the local node
        acct = "0x" + "ab" * 20
        rpc.anvil_set_balance(acct, 5 * 10 ** 18)
        assert int(rpc.call("eth_getBalance", [acct, "latest"]), 16) == 5 * 10 ** 18
        rpc.anvil_impersonate(acct)
        rpc.anvil_stop_impersonate(acct)
        # anvil exposes debug_ (the whole point of using it for enrichment)
        assert rpc.supports("debug_traceTransaction",
                            ["0x" + "0" * 64, {"tracer": "callTracer"}])
    # the launcher process is gone after the context
    assert fork._proc is None or fork._proc.poll() is not None


def test_anvil_fork_at_a_pinned_block():
    live = RpcClient(_FORK_RPC, timeout=20)
    target = live.block_number() - 200
    with F.AnvilFork(_TC, fork_url=_FORK_RPC, fork_block=target, timeout=120) as fork:
        rpc = RpcClient(fork.rpc_url, timeout=20)
        bn = rpc.block_number()
        # anvil forks at the given block; its head is that block (+/- a mined one)
        assert target <= bn <= target + 3
