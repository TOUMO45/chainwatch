"""Deep Hunt - the pair-reserve-manipulation oracle
(`invariants.cat_pair_reserve_manipulation`).

Written from MEASURED demand, not intuition: across the 855 DeFiHackLabs
incidents, 14 are explicitly skim / pair-balance / reserve-manipulation and 17
more are reflection-or-fee tokens reaching the same end, and no existing
Chainwatch regression rule covers any of them.

The defect: a token contract that edits the AMM pair's own balance breaks the
pair's core assumption that reserves move only through mint / burn / swap.
Calling `sync()` immediately after makes the pool adopt the theft as canonical
reserves, converting a balance edit into an arbitrary price move.

Ground truth: DVBench `firetoken` (Ethereum, 2024-10). Its reference finding
reads "Sell path illegally burns tokens from the Uniswap pair balance and
forcibly syncs reserves" - which is precisely what this oracle reports.

Run:  python -m pytest tests/test_nextgen_deephunt_pairreserve.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen.deephunt import invariants as INV  # noqa: E402
from src.nextgen.deephunt import protocolmodel as PM  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")

HEAD = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "interface IUniswapV2Pair { function sync() external; "
        "function skim(address) external; }\n")


def _fire(body: str):
    model = PM.build_from_sources(HEAD + body)
    assert model.compiled, model.reason
    return INV.cat_pair_reserve_manipulation(model)


def _names(body: str) -> list[str]:
    return [f"{i.contract}.{i.functions[0]}" for i in _fire(body)]


# --------------------------------------------------------------------------- #
# DETECTION
# --------------------------------------------------------------------------- #

_FIRE_SHAPE = """
contract BadFireToken {
    mapping(address => uint256) private _balances;
    address public uniswapV2Pair;
    address constant DEAD = address(0xdEaD);
    function _transfer(address from, address to, uint256 amount) internal {
        _balances[from] -= amount;
        _balances[to] += amount;
        if (to == uniswapV2Pair) {
            uint256 sellAmount = amount / 2;
            _balances[uniswapV2Pair] -= sellAmount;
            _balances[DEAD] += sellAmount;
            IUniswapV2Pair(uniswapV2Pair).sync();
        }
    }
    function transfer(address to, uint256 v) external { _transfer(msg.sender, to, v); }
}
"""


def test_detects_pair_balance_edit_with_sync():
    got = _fire(_FIRE_SHAPE)
    assert [f"{i.contract}.{i.functions[0]}" for i in got] == \
        ["BadFireToken._transfer"]
    r = got[0].predicate["test_recipe"]
    assert r["type"] == INV.OBJ_PAIR_RESERVE
    assert r["pair_var"] == "uniswapV2Pair"
    assert r["forces_sync"] is True
    assert got[0].strength == INV.IM.STRONG


def test_the_balance_write_is_the_signal_not_sync():
    """`sync()` raises strength but is never required: editing a third party's
    balance is already the defect, and the pool can be made to notice later."""
    body = _FIRE_SHAPE.replace(
        "            IUniswapV2Pair(uniswapV2Pair).sync();\n", "")
    got = _fire(body)
    assert [f"{i.contract}.{i.functions[0]}" for i in got] == \
        ["BadFireToken._transfer"]
    assert got[0].predicate["test_recipe"]["forces_sync"] is False


# --------------------------------------------------------------------------- #
# PRECISION - the shapes that must NOT fire
# --------------------------------------------------------------------------- #

_TAX = """
contract GoodTaxToken {
    mapping(address => uint256) private _balances;
    address public uniswapV2Pair;
    uint256 public feeBps = 300;
    function _transfer(address from, address to, uint256 amount) internal {
        uint256 fee = (to == uniswapV2Pair) ? amount * feeBps / 10000 : 0;
        _balances[from] -= amount;
        _balances[to] += amount - fee;
        _balances[address(this)] += fee;
    }
    function transfer(address to, uint256 v) external { _transfer(msg.sender, to, v); }
}
"""

_PLAIN = """
contract GoodPlain {
    mapping(address => uint256) private _balances;
    function transfer(address to, uint256 v) external {
        _balances[msg.sender] -= v;
        _balances[to] += v;
    }
}
"""

_SYNC_ONLY = """
contract GoodSyncOnly {
    mapping(address => uint256) private _balances;
    address public uniswapV2Pair;
    // calls sync() but never edits anyone else's balance: unusual, not theft
    function poke() external { IUniswapV2Pair(uniswapV2Pair).sync(); }
    function transfer(address to, uint256 v) external {
        _balances[msg.sender] -= v;
        _balances[to] += v;
    }
}
"""


@pytest.mark.parametrize("name,src", [
    ("a fee/tax token that only COMPARES against the pair", _TAX),
    ("a plain ERC20 with no pair at all", _PLAIN),
    ("sync() called without touching a third party's balance", _SYNC_ONLY),
])
def test_correct_tokens_are_never_flagged(name, src):
    assert _names(src) == [], f"FALSE POSITIVE on {name}"


def test_vulnerable_and_safe_together_separate_cleanly():
    assert _names(_FIRE_SHAPE + _TAX + _PLAIN + _SYNC_ONLY) == \
        ["BadFireToken._transfer"]


def test_counterparty_writes_are_legitimate():
    """`_balances[from]` / `_balances[to]` are exactly what a transfer must
    write; only a NON-counterparty index is suspicious."""
    body = """
contract Ordinary {
    mapping(address => uint256) private _balances;
    address public uniswapV2Pair;
    function _transfer(address from, address to, uint256 amount) internal {
        _balances[from] -= amount;
        _balances[to] += amount;
    }
    function transfer(address to, uint256 v) external { _transfer(msg.sender, to, v); }
}
"""
    assert _names(body) == []


def test_registered_and_typed_as_accounting():
    from src.nextgen.deephunt import findings as F
    assert INV.cat_pair_reserve_manipulation in INV.CATEGORIES
    inv = _fire(_FIRE_SHAPE)[0]
    assert F.finding_type_for(inv) == F.ACCOUNTING
    found = [i for i in INV.discover(PM.build_from_sources(HEAD + _FIRE_SHAPE))
             if i.source == INV.SRC_PAIR_RESERVE]
    assert len(found) == 1


# --------------------------------------------------------------------------- #
# GROUND TRUTH - the real FireToken source, when the DVBench cache is present
# --------------------------------------------------------------------------- #

_DVBENCH = Path(__file__).resolve().parent.parent / "realworld-test" / "dvbench"


@pytest.mark.skipif(not (_DVBENCH / "data" / "cases.jsonl").exists(),
                    reason="DVBench checkout absent (realworld-test/dvbench)")
def test_reproduces_the_firetoken_reference_finding():
    from src.nextgen.deephunt import bench_dvbench as B
    cases = {c["id"]: c for c in B.load_cases(str(_DVBENCH))}
    if "firetoken" not in cases:
        pytest.skip("firetoken case not in this DVBench revision")
    src = B.load_source(cases["firetoken"], str(_DVBENCH))
    if src is None:
        pytest.skip("firetoken source not cached locally")
    model = PM.build_from_sources(src["source_files"],
                                  target=src.get("name", ""),
                                  compiler_version=src.get("compiler_version", ""))
    assert model.compiled, model.reason
    hits = {f"{i.contract}.{i.functions[0]}"
            for i in INV.cat_pair_reserve_manipulation(model)}
    assert "FireToken._transfer" in hits
