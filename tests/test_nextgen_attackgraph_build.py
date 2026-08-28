"""Phase 3 - building the attack-path graph from real compiled Solidity
(src/nextgen/attackgraph.build_graph, spec §4/§12).

Integration: needs slither + solc. Self-contained multi-contract sources.
Skips visibly when the toolchain cannot compile a trivial contract.

Run:  python -m pytest tests/test_nextgen_attackgraph_build.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("slither")

from src.nextgen import _solc  # noqa: E402
from src.nextgen import attackgraph as AG  # noqa: E402
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


PROTOCOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address public owner;
    mapping(address => uint256) public shares;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function deposit() external payable { shares[msg.sender] += msg.value; }
    function setOwner(address o) external onlyOwner { owner = o; }
    function drain(address to) external { owner = to; }        // unguarded sensitive writer
}

contract Router {
    Vault public v;
    constructor(Vault _v) { v = _v; }
    function go(address to) external { v.drain(to); }          // reaches Vault.drain
}
"""

ONLY_GUARDED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Safe {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address o) external onlyOwner { owner = o; }
}
"""


def _node(g, contract, fn):
    for n in g.nodes.values():
        if n.kind == AG.FUNCTION and n.contract == contract and n.function == fn:
            return n
    return None


def test_function_nodes_carry_guard_and_sensitivity():
    g = AG.build_graph(_solc.slither_for_source(PROTOCOL))
    drain = _node(g, "Vault", "drain")
    set_owner = _node(g, "Vault", "setOwner")
    assert drain is not None and drain.mutates_sensitive is True
    assert drain.guarded is False
    assert set_owner is not None and set_owner.guarded is True


def test_vault_is_classified_by_shape():
    g = AG.build_graph(_solc.slither_for_source(PROTOCOL))
    vault_nodes = [n for n in g.nodes.values()
                   if n.contract == "Vault" and n.kind in
                   (AG.VAULT, AG.TOKEN, AG.CONTRACT)]
    assert vault_nodes and vault_nodes[0].kind in (AG.VAULT, AG.CONTRACT)


def test_unprivileged_path_reaches_the_unguarded_sensitive_writer():
    g = AG.build_graph(_solc.slither_for_source(PROTOCOL))
    paths = AG.find_attack_paths(g, target_contract="Vault",
                                 target_function="drain")
    assert paths, "drain must be reachable"
    assert any(p.unprivileged for p in paths)


def test_cross_contract_path_through_router_is_found():
    g = AG.build_graph(_solc.slither_for_source(PROTOCOL))
    paths = AG.find_attack_paths(g, target_contract="Vault",
                                 target_function="drain")
    assert any(p.unprivileged and p.crosses_contracts for p in paths), \
        "EOA -> Router.go -> Vault.drain should be a cross-contract path"


def test_gate_pass_for_the_reachable_regression():
    g = AG.build_graph(_solc.slither_for_source(PROTOCOL))
    paths = AG.find_attack_paths(g, target_contract="Vault",
                                 target_function="drain")
    fs = S.FindingState("f")
    G.apply_attackgraph(fs, paths)
    assert fs.gates["reachable_path"] == S.PASS


def test_gate_fail_when_only_a_guarded_writer_exists():
    g = AG.build_graph(_solc.slither_for_source(ONLY_GUARDED))
    paths = AG.find_attack_paths(g, target_contract="Safe",
                                 target_function="setOwner")
    fs = S.FindingState("f")
    G.apply_attackgraph(fs, paths)
    assert fs.gates["reachable_path"] == S.FAIL
    fine, verdict, _ = S.classify(fs.gates)
    assert fine == S.UNREACHABLE
