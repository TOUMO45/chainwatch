"""Phase 5b - symbolic-sketch + concrete hybrid validation (src/nextgen/execground/hybrid.py, spec §6).

Needs slither (for the constraint sketch); the concrete half additionally needs
a Foundry toolchain. Skips visibly otherwise.

Run:  python -m pytest tests/test_nextgen_hybrid.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen import _solc  # noqa: E402
from src.nextgen import state as S  # noqa: E402
from src.nextgen.execground import foundry as F  # noqa: E402
from src.nextgen.execground import hybrid as HY  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P{function f() external pure returns(uint){return 1;}}\n")
try:
    _solc.slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable")


MSG_SENDER_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    uint256 public x;
    constructor() { owner = msg.sender; }
    function setX(uint256 v) external { require(msg.sender == owner, "no"); x = v; }
}
"""

PARAM_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    uint256 public x;
    function setX(uint256 v) external { require(v > 100, "too small"); x = v; }
}
"""


def test_msg_sender_guard_is_blocking():
    pc = HY.sketch_constraints(_solc.slither_for_source(MSG_SENDER_GUARD),
                               "Vault", "setX")
    cats = {c.category for c in pc.constraints}
    assert HY.MSG_SENDER in cats
    assert pc.blocking
    assert pc.attacker_satisfiable is False


def test_param_only_guard_is_attacker_satisfiable():
    pc = HY.sketch_constraints(_solc.slither_for_source(PARAM_GUARD),
                               "Vault", "setX")
    assert pc.constraints and all(c.category == HY.ATTACKER_PARAM
                                  for c in pc.constraints)
    assert pc.attacker_satisfiable is True


def test_synthesize_calldata_satisfies_a_greater_than_bound():
    pc = HY.sketch_constraints(_solc.slither_for_source(PARAM_GUARD),
                               "Vault", "setX")
    args = HY.synthesize_calldata(pc, ["uint256"])
    assert args == "101"


def test_run_returns_fail_gate_for_a_msg_sender_guard():
    res = HY.run(_solc.slither_for_source(MSG_SENDER_GUARD),
                 contract="Vault", function="setX", signature="setX(uint256)",
                 source_bundle=MSG_SENDER_GUARD)
    assert res.gate == S.FAIL
    assert res.concrete is None                 # short-circuited before running
    assert "not reachable by an unprivileged attacker" in res.rationale


@pytest.mark.skipif(F.resolve() is None, reason="no Foundry toolchain")
def test_run_concrete_pass_for_a_param_only_regression():
    # setX has no ownership check at all - a param guard is not access control
    res = HY.run(_solc.slither_for_source(PARAM_GUARD),
                 contract="Vault", function="setX", signature="setX(uint256)",
                 source_bundle=PARAM_GUARD)
    assert res.synthesized_args == "101"
    assert res.concrete is not None
    assert res.gate == S.PASS
    assert res.concrete.status == "REPRODUCED"
