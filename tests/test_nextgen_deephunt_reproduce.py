"""Deep Hunt Phase 9 - the blinded deep-hunt reproducer
(src/nextgen/deephunt/reproduce.py, spec sections 16, 17).

Always-run: generator selection, no-toolchain PENDING, fork-only PENDING.
forge-gated: a real unguarded ETH drain -> REPRODUCED; the guarded sibling ->
NOT_REPRODUCED.

Run:  python -m pytest tests/test_nextgen_deephunt_reproduce.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.adversarial.reproducer import (BlindTarget, PENDING,  # noqa: E402
                                                REPRODUCED, NOT_REPRODUCED)
from src.nextgen.deephunt import invariants as INV  # noqa: E402
from src.nextgen.deephunt import reproduce as RP  # noqa: E402
from src.nextgen.execground import foundry as FOUNDRY  # noqa: E402
from src.nextgen.execground.sequences import CandidateSequence, TxStep  # noqa: E402

_TOOLCHAIN = FOUNDRY.available()
forgegated = pytest.mark.skipif(not _TOOLCHAIN,
                                reason="needs a Foundry toolchain (native/WSL)")

DRAIN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw(uint256 amt) external {
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send");
    }
}
"""

GUARDED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw(uint256 amt) external {
        require(bal[msg.sender] >= amt, "bal");
        bal[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send");
    }
}
"""


def _target():
    return BlindTarget(
        contract="Vault", function="withdraw",
        invariant_statement="withdraw() must not pay more than the caller's balance",
        objective={"type": INV.OBJ_CONSERVATION, "contract": "Vault",
                   "function": "withdraw"},
        signature="withdraw(uint256)", constructor_args="", pragma="^0.8.0")


def _seq():
    return CandidateSequence(
        [TxStep("Vault", "withdraw", "withdraw(uint256)", "attacker",
                "100000000000000000000")],
        {"type": INV.OBJ_CONSERVATION}, "withdraw() balance conservation")


def test_no_toolchain_is_pending(monkeypatch):
    monkeypatch.setattr(FOUNDRY, "resolve", lambda *a, **k: None)
    _m, res = RP.reproduce(_target(), _seq(), source_bundle=DRAIN)
    assert res.status == PENDING
    assert "toolchain" in res.detail


def test_fork_only_recipe_is_pending_without_a_fork(monkeypatch):
    monkeypatch.setattr(FOUNDRY, "resolve",
                        lambda *a, **k: FOUNDRY.Toolchain("native", "/bin/forge"))
    t = _target()
    t.objective = {"type": INV.OBJ_ORACLE, "contract": "Vault", "function": "mint"}
    _m, res = RP.reproduce(t, _seq(), source_bundle=DRAIN)
    assert res.status == PENDING
    assert "source-only" in res.detail and "CONFIRMED" in res.detail


def test_pre_0_6_pragma_is_pending(monkeypatch):
    monkeypatch.setattr(FOUNDRY, "resolve",
                        lambda *a, **k: FOUNDRY.Toolchain("native", "/bin/forge"))
    t = _target()
    t.pragma = "0.5.17"
    _m, res = RP.reproduce(t, _seq(), source_bundle=DRAIN.replace("^0.8.0", "0.5.17"))
    assert res.status == PENDING
    assert "0.6.2" in res.detail


def test_make_runner_returns_a_repro_result(monkeypatch):
    monkeypatch.setattr(FOUNDRY, "resolve", lambda *a, **k: None)
    runner = RP.make_runner(_seq(), source_bundle=DRAIN)
    res = runner(_target())
    assert res.status == PENDING


@forgegated
def test_real_unguarded_drain_reproduces():
    minimal, res = RP.reproduce(_target(), _seq(), source_bundle=DRAIN)
    assert res.status == REPRODUCED, res.detail
    assert minimal is not None and len(minimal.steps) == 1


@forgegated
def test_real_guarded_withdraw_does_not_reproduce():
    minimal, res = RP.reproduce(_target(), _seq(), source_bundle=GUARDED)
    assert res.status == NOT_REPRODUCED, res.detail
    assert minimal is None
