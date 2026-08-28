"""Phase 6 - cross-protocol composability analysis (src/nextgen/composability.py, spec §13).

Needs slither. Pins the ASSUMPTION -> ACTUAL BEHAVIOUR -> MISMATCH shape for
oracle staleness, balanceOf-as-accounting, and unchecked token transfers.

Run:  python -m pytest tests/test_nextgen_composability.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen import _solc  # noqa: E402
from src.nextgen import composability as CO  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P{function f() external pure returns(uint){return 1;}}\n")
try:
    _solc.slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False
pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable")


ORACLE_UNCHECKED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IOracle { function latestAnswer() external view returns (int256); }
contract Vault {
    IOracle public oracle;
    uint256 public price;
    function poke() external { price = uint256(int256(oracle.latestAnswer())); }
}
"""

BALANCE_ACCOUNTING = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address) external view returns (uint256); }
contract Vault {
    IERC20 public token;
    uint256 public shares;
    function sync() external { shares = token.balanceOf(address(this)); }
}
"""

TRANSFER_UNCHECKED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address,uint256) external returns (bool); }
contract Payout {
    IERC20 public token;
    function pay(address to, uint256 amt) external { token.transfer(to, amt); }
}
"""

CLEAN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Math { function add(uint a, uint b) external pure returns (uint) { return a + b; } }
"""


def test_unchecked_oracle_read_is_a_freshness_assumption_mismatch():
    rep = CO.analyze_from_source(ORACLE_UNCHECKED, "Vault")
    assert rep.risks
    r = rep.risks[0]
    assert r.dependency_kind == CO.ORACLE
    assert "fresh" in r.assumption
    assert "stale" in r.actual_behaviour.lower()


def test_balanceof_as_accounting_truth_is_flagged():
    rep = CO.analyze_from_source(BALANCE_ACCOUNTING, "Vault")
    assert any(r.dependency_kind == CO.TOKEN and "accounting" in r.assumption
               for r in rep.risks)


def test_unchecked_transfer_return_is_flagged():
    rep = CO.analyze_from_source(TRANSFER_UNCHECKED, "Payout")
    assert any(r.method.lower() == "transfer" for r in rep.risks)


def test_clean_contract_has_no_composability_risk():
    rep = CO.analyze_from_source(CLEAN, "Math")
    assert rep.risks == []
    assert "no external-dependency assumption mismatch" in rep.render_text()


def test_report_render_and_dict():
    rep = CO.analyze_from_source(ORACLE_UNCHECKED, "Vault")
    assert "COMPOSABILITY ANALYSIS" in rep.render_text()
    assert rep.as_dict()["risks"][0]["mismatch"]
