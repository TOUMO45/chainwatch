"""Deep Hunt Phase 3 - the fork execution laboratory
(src/nextgen/deephunt/execadapter.py, spec sections 11, 12).

Two tiers:
  * always-run: no-toolchain / no-rpc degrade cleanly to `available=False` and
    every read returns None (no raise);
  * toolchain+RPC-gated: a real ETH-mainnet fork at a fixed block - reads WETH
    code, snapshot/revert, anvil_setBalance readback.

Run:  python -m pytest tests/test_nextgen_deephunt_execadapter.py -q
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.deephunt import execadapter as EA  # noqa: E402
from src.nextgen.execground import foundry as FOUNDRY  # noqa: E402

WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
_FIXED_BLOCK = 18_000_000


# --------------------------------------------------------------------------- #
# always-run: graceful degradation
# --------------------------------------------------------------------------- #

def test_no_toolchain_degrades(monkeypatch):
    monkeypatch.setattr(FOUNDRY, "resolve", lambda *a, **k: None)
    fc = EA.open_fork(1, _FIXED_BLOCK, WETH, "https://example.invalid")
    assert fc.available is False
    assert "toolchain" in fc.reason
    assert fc.start() is False
    assert fc.code(WETH) is None
    assert fc.balance(WETH) is None
    assert fc.block_number() is None
    assert fc.snapshot() is None
    assert fc.impersonate_send({"from": "0x" + "11" * 20, "to": WETH}) is None
    rs = fc.repro_state()
    assert rs.chain_id == 1 and rs.fork_block == _FIXED_BLOCK
    fc.stop()


def test_no_rpc_url_degrades(monkeypatch):
    monkeypatch.setattr(FOUNDRY, "resolve",
                        lambda *a, **k: FOUNDRY.Toolchain("native", "/bin/forge"))
    fc = EA.open_fork(1, _FIXED_BLOCK, WETH, "")
    assert fc.available is False
    assert "RPC" in fc.reason or "rpc" in fc.reason
    assert fc.start() is False


def test_repro_state_shape():
    rs = EA.ReproState(chain_id=1, fork_block=42, target=WETH,
                       implementation="0xabc", storage={"0x0": "0x1"},
                       balances={WETH: 5})
    d = rs.as_dict()
    assert d["chain_id"] == 1 and d["target"] == WETH
    assert d["balances"][WETH] == "5"          # int -> str for json safety


# --------------------------------------------------------------------------- #
# toolchain + RPC gated: a real fork
# --------------------------------------------------------------------------- #

def _rpc_url() -> str:
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    except Exception:  # noqa: BLE001
        pass
    return os.environ.get("RPC_URL", "")


_TOOLCHAIN = FOUNDRY.available()
_RPC = _rpc_url()
_LIVE_OK = _TOOLCHAIN and bool(_RPC)

live = pytest.mark.skipif(
    not _LIVE_OK,
    reason=f"needs Foundry (have={_TOOLCHAIN}) + RPC_URL (have={bool(_RPC)})")


@live
def test_real_fork_reads_and_mutations():
    fc = EA.open_fork(1, _FIXED_BLOCK, WETH, _RPC, timeout=150)
    assert fc.start() is True, fc.reason
    try:
        bn = fc.block_number()
        assert bn is not None and bn >= _FIXED_BLOCK

        code = fc.code(WETH)
        assert code and code.startswith("0x") and len(code) > 100
        assert fc.has_code(WETH) is True
        assert fc.has_code("0x" + "00" * 20) is False

        whale = "0x" + "42" * 20
        before = fc.balance(whale)
        assert before is not None
        snap = fc.snapshot()
        assert snap is not None
        assert fc.set_balance(whale, before + 7 * EA._ETHER) is True
        assert fc.balance(whale) == before + 7 * EA._ETHER
        assert fc.revert(snap) is True
        assert fc.balance(whale) == before      # snapshot rolled the write back

        rs = fc.repro_state(watch_addrs=(WETH,), watch_slots=("0x0",))
        assert rs.target == WETH and rs.chain_id == 1
        assert WETH in rs.balances
    finally:
        fc.stop()
    assert fc.available is False
