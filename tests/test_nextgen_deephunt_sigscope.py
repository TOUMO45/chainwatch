"""Deep Hunt - the signature-SCOPE oracle (src/nextgen/deephunt/invariants.py,
spec section 5.H).

A nonce stops a signature being replayed against the SAME party. It does
nothing about replay across DIFFERENT parties unless the signed digest also
binds that party's identity. This oracle finds the gap.

Ground truth: code4rena 2021-10 Ambire, finding H-03 "Signature replay attacks
for different identities (nonce on wrong party)" - confirmed and patched by the
Ambire team. Web3Bugs labels it S2-3. The live regression test at the bottom
runs against that exact source when the Web3Bugs checkout is present.

The precision cases matter more than the detection case: an oracle that fires
on EIP-2612 `permit` would be worthless.

Run:  python -m pytest tests/test_nextgen_deephunt_sigscope.py -q
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


HEAD = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"


def _fire(body: str) -> list[str]:
    """Contract.function for every signature-scope invariant raised."""
    model = PM.build_from_sources(HEAD + body)
    assert model.compiled, model.reason
    return [f"{i.contract}.{i.functions[0]}"
            for i in INV.cat_signature_scope(model)]


# --------------------------------------------------------------------------- #
# PRECISION - correct code must stay silent. These are the cases that decide
# whether the oracle is shippable at all.
# --------------------------------------------------------------------------- #

_PERMIT = """
contract GoodPermit {
    mapping(address => uint256) public nonces;
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    function permit(address owner, address spender, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))));
        require(ecrecover(digest, v, r, s) == owner, "BAD_SIG");
    }
}
"""

_SELF_NONCE = """
contract GoodSelfNonce {
    mapping(address => uint256) public nonces;
    function act(bytes calldata sig, uint256 amount) external {
        bytes32 h = keccak256(abi.encode(amount, nonces[msg.sender]++));
        require(ecrecover(h, 27, bytes32(0), bytes32(0)) != address(0), "S");
    }
}
"""

_BOUND = """
contract GoodBound {
    mapping(address => uint256) public nonces;
    function relay(address account, bytes calldata sig, uint256 v) external {
        bytes32 h = keccak256(abi.encode(account, v, nonces[account]++));
        require(ecrecover(h, 27, bytes32(0), bytes32(0)) == account, "S");
    }
}
"""

_NO_SIG = """
contract GoodNoSig {
    mapping(address => uint256) public nonces;
    function bump(address who) external { nonces[who]++; }
}
"""


@pytest.mark.parametrize("name,src", [
    ("eip2612 permit: owner is keyed AND signed", _PERMIT),
    ("nonce keyed on msg.sender (the safe shape)", _SELF_NONCE),
    ("party is keyed AND appears in the digest", _BOUND),
    ("no signature verified: no replay surface", _NO_SIG),
])
def test_correct_signature_code_is_never_flagged(name, src):
    assert _fire(src) == [], f"FALSE POSITIVE on {name}"


def test_all_four_safe_patterns_together_stay_silent():
    """Together in one unit, so a cross-contract leak would show up too."""
    assert _fire(_PERMIT + _SELF_NONCE + _BOUND + _NO_SIG) == []


# --------------------------------------------------------------------------- #
# DETECTION
# --------------------------------------------------------------------------- #

_BAD = """
contract BadCrossParty {
    mapping(address => uint256) public nonces;
    function send(address wallet, bytes calldata sig, uint256 amount) external {
        bytes32 h = keccak256(abi.encode(amount, nonces[wallet]++));
        require(ecrecover(h, 27, bytes32(0), bytes32(0)) != address(0), "S");
    }
}
"""


def test_detects_nonce_on_the_wrong_party():
    assert _fire(_BAD) == ["BadCrossParty.send"]


def test_the_vulnerable_case_is_separated_from_the_safe_ones():
    """The whole point: one unit holding both shapes reports only the bad one."""
    assert _fire(_PERMIT + _SELF_NONCE + _BOUND + _NO_SIG + _BAD) == \
        ["BadCrossParty.send"]


def test_finding_carries_a_machine_checkable_recipe():
    model = PM.build_from_sources(HEAD + _BAD)
    inv = INV.cat_signature_scope(model)[0]
    r = inv.predicate["test_recipe"]
    assert r["type"] == INV.OBJ_SIG_CROSS_PARTY
    assert r["party_param"] == "wallet"          # the unbound party, named
    assert r["nonce_var"] == "nonces"
    assert "wallet" in r["nonce_index"]
    assert inv.strength == INV.IM.STRONG
    assert inv.source == INV.SRC_SIG_SCOPE
    # the statement names the party rather than being generic boilerplate
    assert "wallet" in inv.statement


def test_one_report_per_party_not_per_mention():
    """`nonces[wallet]` read twice in one body is still ONE finding."""
    src = """
contract Twice {
    mapping(address => uint256) public nonces;
    function go(address wallet, bytes calldata sig) external {
        bytes32 a = keccak256(abi.encode(uint256(1), nonces[wallet]));
        bytes32 b = keccak256(abi.encode(uint256(2), nonces[wallet]++));
        require(ecrecover(a, 27, bytes32(0), bytes32(0)) != address(0), "S");
        require(b != 0, "x");
    }
}
"""
    assert _fire(src) == ["Twice.go"]


def test_registered_in_the_discovery_pipeline():
    assert INV.cat_signature_scope in INV.CATEGORIES
    found = [i for i in INV.discover(PM.build_from_sources(HEAD + _BAD))
             if i.source == INV.SRC_SIG_SCOPE]
    assert len(found) == 1


def test_no_source_text_means_no_guess():
    """The oracle reads an expression, so with no source it must say nothing -
    never infer the bug from the nonce's existence alone."""
    model = PM.build_from_sources(HEAD + _BAD)
    for c in model.contracts:
        for f in c.functions:
            object.__setattr__(f, "source", "") if hasattr(f, "__dataclass_fields__") \
                else None
    stripped = [f for c in model.contracts for f in c.functions if f.source]
    assert stripped == []
    assert INV.cat_signature_scope(model) == []


# --------------------------------------------------------------------------- #
# GROUND TRUTH - the real Ambire source, when the Web3Bugs checkout is present
# --------------------------------------------------------------------------- #

_AMBIRE = (Path(__file__).resolve().parent.parent / "realworld-test" /
           "web3bugs" / "contracts" / "38" / "contracts")


_OZ = (Path(__file__).resolve().parent.parent / "realworld-test" / "oz5" /
       "node_modules" / "@openzeppelin" / "contracts" / "token" / "ERC20" /
       "extensions")


@pytest.mark.skipif(not _OZ.exists(),
                    reason="OpenZeppelin 5 checkout absent (realworld-test/oz5)")
def test_openzeppelin_erc20permit_is_not_flagged():
    """The decisive precision case: the most widely deployed signature-consuming
    function in DeFi. It keys the nonce on `owner` AND signs `owner`, so it is
    correct - and the oracle must say nothing about it."""
    model = PM.build_from_sources(_OZ, target="ERC20Permit")
    assert model.compiled, model.reason
    permit = [f for f in model.external_functions()
              if f.contract == "ERC20Permit" and f.name == "permit"]
    # guard the guard: if permit stopped being modelled, silence would be vacuous
    assert permit and permit[0].source, "ERC20Permit.permit was not modelled"
    assert any("nonce" in w.lower() for w in permit[0].writes)
    assert INV.cat_signature_scope(model) == []


@pytest.mark.skipif(not _AMBIRE.exists(),
                    reason="Web3Bugs checkout absent (realworld-test/web3bugs)")
def test_reproduces_ambire_h03_on_the_real_source():
    """code4rena 2021-10 Ambire H-03, confirmed by the team: a QuickAccount can
    serve several identities, and the digest omits `identity`, so one signature
    replays across all of them. The report names send / sendTransfer / sendTxns
    among the affected entry points."""
    model = PM.build_from_sources(_AMBIRE)
    assert model.compiled, model.reason
    hits = {f"{i.contract}.{i.functions[0]}"
            for i in INV.cat_signature_scope(model)}
    assert {"QuickAccManager.send",
            "QuickAccManager.sendTransfer",
            "QuickAccManager.sendTxns"} <= hits
    party = {i.predicate["test_recipe"]["party_param"]
             for i in INV.cat_signature_scope(model)}
    assert party == {"identity"}          # exactly the parameter the report names
