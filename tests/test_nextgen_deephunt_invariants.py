"""Deep Hunt Phase 2 - deep invariant discovery, categories A-J
(src/nextgen/deephunt/invariants.py, spec sections 4, 5).

Integration: needs slither + solc. Self-contained sources only.

Run:  python -m pytest tests/test_nextgen_deephunt_invariants.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen.deephunt import invariants as INV  # noqa: E402
from src.nextgen.deephunt import llm_hypotheses as LLM  # noqa: E402
from src.nextgen.deephunt import protocolmodel as PM  # noqa: E402
from src.nextgen.invariants import model as IM  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")
try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception as _e:  # noqa: BLE001
    _OK = False

pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")


VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}
contract Vault {
    address public owner;
    IERC20 public asset;
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    bool public initialized;
    event Withdraw(address indexed who, uint256 assets);
    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
    function initialize(address a) external {
        require(!initialized, "init");
        initialized = true; owner = msg.sender; asset = IERC20(a);
    }
    function deposit(uint256 a) external returns (uint256 m) {
        asset.transferFrom(msg.sender, address(this), a);
        m = totalShares == 0 ? a : (a * totalShares) / totalAssets;
        shares[msg.sender] += m; totalShares += m; totalAssets += a;
    }
    function withdraw(uint256 s) external returns (uint256 a) {
        require(shares[msg.sender] >= s, "bal");
        a = (s * totalAssets) / totalShares;
        shares[msg.sender] -= s; totalShares -= s; totalAssets -= a;
        asset.transfer(msg.sender, a);
        emit Withdraw(msg.sender, a);
    }
    function setFee(uint256 f) external onlyOwner { totalAssets = totalAssets - f; }
    function rescue(uint256 f) external { totalAssets = totalAssets - f; }  // unguarded sibling
}
"""

# HYDT / AIZPT-shaped: a state-changing mint priced off instantaneous AMM spot
AMM_MINT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }
contract Minter {
    IPair public pair;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor(address p) { pair = IPair(p); }
    function _price() internal view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);
    }
    function mint() external payable {
        uint256 amt = (msg.value * _price()) / 1e18;
        balanceOf[msg.sender] += amt;
        totalSupply += amt;
    }
}
"""

CLEAN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Calc {
    function add(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
    function double(uint256 a) external pure returns (uint256) { return a * 2; }
}
"""


@pytest.fixture(scope="module")
def vault():
    m = PM.build_from_sources(VAULT, target="Vault")
    assert m.compiled, m.reason
    return m, INV.discover(m)


def test_discover_produces_recipe_typed_candidates(vault):
    _m, invs = vault
    assert invs, "expected deep invariants for a share vault"
    for inv in invs:
        rt = (inv.predicate or {}).get("test_recipe", {}).get("type")
        assert rt in INV.RECIPE_TYPES, f"{inv.source}: bad recipe type {rt!r}"
        assert inv.status == IM.INFERRED
        assert inv.kind in IM.KINDS


def test_entitlement_invariant_on_withdraw(vault):
    _m, invs = vault
    ent = [i for i in invs if i.source == INV.SRC_ENTITLEMENT]
    assert any("withdraw" in i.functions for i in ent)
    assert all(i.predicate["test_recipe"]["type"] == INV.OBJ_ENTITLEMENT for i in ent)


def test_share_math_invariant(vault):
    _m, invs = vault
    sm = [i for i in invs if i.source == INV.SRC_SHARE_MATH]
    assert sm, "expected a share/asset-math consistency invariant"
    assert any(i.predicate["test_recipe"]["type"] == INV.OBJ_SHARE_MATH for i in sm)


def test_conservation_invariant(vault):
    _m, invs = vault
    cons = [i for i in invs if i.source == INV.SRC_CONSERVATION]
    assert any("withdraw" in i.functions for i in cons)


def test_state_machine_invariant_on_initializer(vault):
    _m, invs = vault
    sm = [i for i in invs if i.source == INV.SRC_STATE_MACHINE]
    assert any("initialize" in i.functions for i in sm)
    assert all(i.predicate["test_recipe"]["type"] == INV.OBJ_REINIT for i in sm)


def test_authorization_contradiction_is_found_and_validates(vault):
    m, invs = vault
    # setFee (onlyOwner) and rescue (open) both write totalAssets -> F contradiction
    f = [i for i in invs if i.source == INV.SRC_AUTH_REACH and "rescue" in i.functions]
    assert f, "expected an authorization-reachability contradiction for rescue()"
    assert f[0].contradiction
    INV.validate(m, invs)
    assert f[0].status == IM.VALIDATED           # concrete unguarded writer stands


def test_oracle_assumption_on_spot_priced_mint():
    m = PM.build_from_sources(AMM_MINT, target="Minter")
    assert m.compiled, m.reason
    invs = INV.discover(m)
    ora = [i for i in invs if i.source == INV.SRC_ORACLE]
    assert ora, "expected an oracle-manipulation invariant for a spot-priced mint()"
    rec = ora[0].predicate["test_recipe"]
    assert rec["type"] == INV.OBJ_ORACLE
    assert rec["spot_priced"] is True
    assert "mint" in ora[0].functions


def test_clean_contract_yields_no_relationship_invariants():
    m = PM.build_from_sources(CLEAN, target="Calc")
    assert m.compiled, m.reason
    invs = INV.discover(m)
    for bad in (INV.SRC_SHARE_MATH, INV.SRC_ORACLE, INV.SRC_ENTITLEMENT,
                INV.SRC_DEBT_LTV, INV.SRC_CONSERVATION):
        assert not [i for i in invs if i.source == bad], f"unexpected {bad}"


def test_discover_is_deterministic_without_llm(vault):
    m, _invs = vault
    a = [(i.source, i.statement) for i in INV.discover(m)]
    b = [(i.source, i.statement) for i in INV.discover(m)]
    assert a == b


def test_llm_hook_is_gated_and_never_required(monkeypatch):
    monkeypatch.setattr(LLM, "available", lambda: False)
    m = PM.build_from_sources(VAULT, target="Vault")
    got = INV.cat_protocol_specific(m, use_llm=True)
    # with the hook disabled, category J still returns only its structural finds
    assert all(not i.source.endswith(":llm") for i in got)
    assert LLM.propose_invariants(m) == []


def test_validate_promotes_to_at_least_tested(vault):
    m, invs = vault
    INV.validate(m, invs)
    assert all(i.status in (IM.TESTED, IM.VALIDATED, IM.REJECTED) for i in invs)
    assert any(i.status in (IM.TESTED, IM.VALIDATED) for i in invs)


def test_summarize_is_safe_on_empty():
    assert "none discovered" in INV.summarize([])


def test_discover_on_uncompiled_model_is_empty():
    m = PM.build_from_sources("garbage")
    assert m.compiled is False
    assert INV.discover(m) == []
