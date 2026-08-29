"""Deep Hunt Phase 1 - ProtocolModel on real compiled code
(src/nextgen/deephunt/protocolmodel.py, spec section 3).

Integration: needs slither + solc. Self-contained sources only. Skips visibly
when the toolchain cannot compile a trivial contract.

Run:  python -m pytest tests/test_nextgen_deephunt_protocolmodel.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen.deephunt import protocolmodel as PM  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P { function f() external pure returns (uint){return 1;} }\n")

try:
    from src.nextgen._solc import slither_for_source
    slither_for_source(_TRIVIAL)
    _OK = True
except Exception as _e:  # noqa: BLE001
    _OK, _WHY = False, f"{type(_e).__name__}: {_e}"

pytestmark = pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")


VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IOracle { function latestAnswer() external view returns (uint256); }
interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract Vault {
    address public owner;
    IERC20 public asset;
    IOracle public oracle;
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    event Deposit(address indexed who, uint256 assets, uint256 minted);
    event Withdraw(address indexed who, uint256 assets, uint256 burned);

    constructor(address _asset, address _oracle) {
        owner = msg.sender;
        asset = IERC20(_asset);
        oracle = IOracle(_oracle);
    }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function name() external pure returns (string memory) { return "Vault"; }

    function pricePerShare() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalAssets * 1e18) / totalShares;
    }

    function deposit(uint256 assets) external returns (uint256 minted) {
        asset.transferFrom(msg.sender, address(this), assets);
        minted = totalShares == 0 ? assets : (assets * totalShares) / totalAssets;
        shares[msg.sender] += minted;
        totalShares += minted;
        totalAssets += assets;
        emit Deposit(msg.sender, assets, minted);
    }

    function withdraw(uint256 shareAmt) external returns (uint256 assets) {
        require(shares[msg.sender] >= shareAmt, "bal");
        assets = (shareAmt * totalAssets) / totalShares;
        shares[msg.sender] -= shareAmt;
        totalShares -= shareAmt;
        totalAssets -= assets;
        asset.transfer(msg.sender, assets);
        emit Withdraw(msg.sender, assets, shareAmt);
    }

    function setOracle(address o) external onlyOwner { oracle = IOracle(o); }

    function priceCheck() external view returns (uint256) {
        return oracle.latestAnswer();
    }
}
"""

PROXY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Impl { uint256 public x; function setX(uint256 v) external { x = v; } }
contract Proxy {
    address public implementation;
    function upgradeTo(address newImpl) external { implementation = newImpl; }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
"""


@pytest.fixture(scope="module")
def vault_model():
    m = PM.build_from_sources(VAULT, target="Vault")
    assert m.compiled, m.reason
    return m


def test_target_and_contracts(vault_model):
    assert vault_model.target_contract == "Vault"
    names = {c.name for c in vault_model.contracts}
    assert {"Vault", "IOracle", "IERC20"} <= names
    tgt = vault_model.target()
    assert tgt is not None and tgt.name == "Vault" and tgt.is_target


def test_functions_have_selectors_and_shape(vault_model):
    wd = vault_model.function("Vault", "withdraw")
    assert wd is not None
    assert wd.signature == "withdraw(uint256)"
    assert wd.selector == "0x2e1a7d4d"          # keccak("withdraw(uint256)")[:4]
    assert wd.visibility in ("external", "public")
    assert "totalAssets" in wd.writes and "shares" in wd.writes
    assert any("transfer" in ec.lower() for ec in wd.external_calls)
    assert "Withdraw" in wd.events
    # a `require(shares[msg.sender] >= x)` balance check is NOT access control
    assert wd.access_controlled is False
    so = vault_model.function("Vault", "setOracle")
    assert so.access_controlled is True          # onlyOwner -> caller identity gated


def test_roles_from_behaviour_not_names(vault_model):
    assert vault_model.roles, "expected at least one derived role"
    owner_role = next((r for r in vault_model.roles if "owner" in r.name.lower()), None)
    assert owner_role is not None
    assert owner_role.kind == "OWNER"
    assert "Vault.setOracle" in owner_role.gated_functions
    # withdraw is NOT gated -> must not be attributed to a role
    assert "Vault.withdraw" not in owner_role.gated_functions


def test_assets_detected(vault_model):
    kinds = {a.kind for a in vault_model.assets}
    assert PM.SHARES in kinds
    # ERC4626-ish: has asset() + totalAssets() getters
    assert PM.ERC4626 in kinds or PM.ERC20 in kinds


def test_oracle_dependency_unchecked(vault_model):
    ora = [d for d in vault_model.dependencies if d.kind == PM.DEP_ORACLE]
    assert ora, "expected an oracle dependency"
    la = next((d for d in ora if "latestanswer" in d.hint.lower()), ora[0])
    assert la.return_checked is not True          # latestAnswer -> no freshness check
    assert "Vault.priceCheck" in la.consumed_by


def test_state_relations(vault_model):
    rels = {(r.kind, r.function) for r in vault_model.relations}
    assert (PM.REL_DEPOSIT_SHARES, "Vault.deposit") in rels
    assert (PM.REL_WITHDRAW_ASSET, "Vault.withdraw") in rels


def test_risk_ranking_is_deterministic_and_sane(vault_model):
    wd = vault_model.function("Vault", "withdraw")
    nm = vault_model.function("Vault", "name")
    assert wd.risk > nm.risk
    assert nm.risk == 0
    ranked1 = [f"{f.contract}.{f.name}" for f in vault_model.ranked_functions()]
    ranked2 = [f"{f.contract}.{f.name}" for f in vault_model.ranked_functions()]
    assert ranked1 == ranked2                     # deterministic
    assert ranked1[0] in ("Vault.withdraw", "Vault.deposit")


def test_coverage_block(vault_model):
    cov = vault_model.coverage()
    assert cov["contracts_modeled"] >= 3
    assert cov["functions_modeled"] >= 5
    assert cov["roles"] >= 1 and cov["dependencies"] >= 1


def test_proxy_relationship():
    m = PM.build_from_sources(PROXY, target="Proxy")
    assert m.compiled, m.reason
    proxy = m.contract("Proxy")
    assert proxy is not None and proxy.kind == PM.PROXY


def test_non_compiling_blob_is_unmeasured_not_a_crash():
    m = PM.build_from_sources("pragma solidity ^0.8.0;\ncontract Broken {{{ ")
    assert m.compiled is False
    assert m.reason
    assert m.contracts == ()
    # helpers still safe on an empty model
    assert m.ranked_functions() == []
    assert m.target() is None


def test_plain_garbage_string_is_unmeasured():
    m = PM.build_from_sources("not solidity at all")
    assert m.compiled is False and m.contracts == ()
