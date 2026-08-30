"""Deep Hunt - the credited-amount-mismatch oracle
(`invariants.cat_credited_amount_mismatch`).

Second rule written from MEASURED demand: 17 of the 855 DeFiHackLabs incidents
are reflection or fee-on-transfer tokens, and the mechanism is always the same -
a pool credits the caller with the amount they ASKED to deposit while the token
delivered less, so the difference comes out of other users' funds.

The escape hatch is deliberate and exact: a `balanceOf(address(this))`
measurement anywhere in the body clears the function, because that is precisely
how the correct version is written. That gives the rule a crisp boundary rather
than a tuned threshold.

Run:  python -m pytest tests/test_nextgen_deephunt_creditmismatch.py -q
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

HEAD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC20 {
    function transferFrom(address f, address t, uint256 a) external returns (bool);
    function transfer(address t, uint256 a) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}
"""


def _names(body: str) -> list[str]:
    model = PM.build_from_sources(HEAD + body)
    assert model.compiled, model.reason
    return [f"{i.contract}.{i.functions[0]}"
            for i in INV.cat_credited_amount_mismatch(model)]


_BAD = """
contract BadPool {
    mapping(address => uint256) public balances;
    IERC20 public token;
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }
}
"""

_GOOD_DELTA = """
contract GoodPool {
    mapping(address => uint256) public balances;
    IERC20 public token;
    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        balances[msg.sender] += received;
    }
}
"""

_GOOD_PUSH = """
contract GoodWithdraw {
    mapping(address => uint256) public balances;
    IERC20 public token;
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        token.transferFrom(address(this), msg.sender, amount);
    }
}
"""

_GOOD_NO_PULL = """
contract GoodNoPull {
    mapping(address => uint256) public balances;
    IERC20 public token;
    function payout(uint256 amount) external {
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""


def test_detects_crediting_the_requested_amount():
    assert _names(_BAD) == ["BadPool.deposit"]


def test_recipe_names_the_parameter_and_the_credited_state():
    model = PM.build_from_sources(HEAD + _BAD)
    inv = INV.cat_credited_amount_mismatch(model)[0]
    r = inv.predicate["test_recipe"]
    assert r["type"] == INV.OBJ_CREDIT_MISMATCH
    assert r["amount_param"] == "amount"
    assert "balances" in r["credited_vars"]
    assert inv.source == INV.SRC_CREDIT_MISMATCH


@pytest.mark.parametrize("name,src", [
    ("measures balanceOf(address(this)) before/after", _GOOD_DELTA),
    ("transferFrom PUSHES out, and debits - correct bookkeeping", _GOOD_PUSH),
    ("no transferFrom pull at all", _GOOD_NO_PULL),
])
def test_correct_pools_are_never_flagged(name, src):
    assert _names(src) == [], f"FALSE POSITIVE on {name}"


def test_a_debit_of_the_same_amount_is_not_a_credit():
    """`balances[x] -= amount` contains an `=`; matching it was this oracle's
    first false positive. Only `+=` or a bare `=` is a credit."""
    body = """
contract Debiter {
    mapping(address => uint256) public balances;
    IERC20 public token;
    function repay(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] -= amount;
    }
}
"""
    assert _names(body) == []


def test_vulnerable_and_safe_together_separate_cleanly():
    assert _names(_BAD + _GOOD_DELTA + _GOOD_PUSH + _GOOD_NO_PULL) == \
        ["BadPool.deposit"]


def test_registered_and_typed_as_accounting():
    from src.nextgen.deephunt import findings as F
    assert INV.cat_credited_amount_mismatch in INV.CATEGORIES
    model = PM.build_from_sources(HEAD + _BAD)
    inv = INV.cat_credited_amount_mismatch(model)[0]
    assert F.finding_type_for(inv) == F.ACCOUNTING
