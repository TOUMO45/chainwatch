"""Phase 3b - compensating-control analysis (src/nextgen/compensating.py, spec §11).

Integration: needs slither + solc. Self-contained sources. Pins that an
equivalent mechanism (renamed modifier, guarded caller, guarded state
precondition) REJECTS a "guard removed" claim, and that a genuinely open
function does not.

Run:  python -m pytest tests/test_nextgen_compensating.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen import _solc  # noqa: E402
from src.nextgen import compensating as C  # noqa: E402
from src.nextgen import gates as G  # noqa: E402
from src.nextgen import state as S  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    _solc.slither_for_source(_TRIVIAL)
    _OK = True
except Exception as _e:  # noqa: BLE001
    _OK, _WHY = False, f"{type(_e).__name__}: {_e}"
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")


RENAMED_MODIFIER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier auth() { require(msg.sender == owner, "no"); _; }   // renamed onlyOwner
    function setOwner(address o) external auth { owner = o; }
}
"""

GENUINELY_OPEN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    function setOwner(address o) external { owner = o; }         // no guard at all
}
"""

GUARDED_CALLER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function _setOwner(address o) internal { owner = o; }        // no guard here
    function rotate(address o) external onlyOwner { _setOwner(o); }
}
"""

STATE_PRECOND = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    address public pendingOwner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function proposeOwner(address o) external onlyOwner { pendingOwner = o; }
    function acceptOwner() external {
        require(pendingOwner != address(0), "none");
        owner = pendingOwner;                                    // reverts unless a guarded path set pendingOwner
    }
}
"""


def test_renamed_modifier_is_a_transitive_guard_and_rejects():
    rep = C.analyze_from_source(RENAMED_MODIFIER, "Vault", "setOwner")
    assert rep.gate == S.FAIL
    assert any(c.kind == C.TRANSITIVE_GUARD for c in rep.controls)
    fs = S.FindingState("f")
    G.apply_compensating(fs, rep)
    fine, verdict, _ = S.classify(fs.gates)
    assert fine == S.FALSE_POSITIVE and verdict == S.VERDICT_REJECTED


def test_genuinely_open_function_has_no_compensating_control():
    rep = C.analyze_from_source(GENUINELY_OPEN, "Vault", "setOwner")
    assert rep.gate == S.PASS
    assert rep.controls == []
    fs = S.FindingState("f")
    G.apply_compensating(fs, rep)
    assert fs.gates["no_compensating_control"] == S.PASS


def test_guarded_caller_protects_an_unguarded_internal():
    rep = C.analyze_from_source(GUARDED_CALLER, "Vault", "_setOwner")
    assert rep.gate == S.FAIL
    assert any(c.kind in (C.CALLER_GUARD, C.TRANSITIVE_GUARD)
               for c in rep.controls)


def test_state_precondition_set_only_by_a_guarded_path():
    rep = C.analyze_from_source(STATE_PRECOND, "Vault", "acceptOwner")
    assert rep.gate == S.FAIL
    assert any(c.kind == C.STATE_PRECONDITION for c in rep.controls)


def test_missing_function_is_unknown():
    rep = C.analyze_from_source(GENUINELY_OPEN, "Vault", "doesNotExist")
    assert rep.gate == S.GATE_UNKNOWN
