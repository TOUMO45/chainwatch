"""Phase 5b - regression fuzzing between two commits (src/nextgen/execground/regfuzz.py, spec §21).

Pure: contract renaming, fuzz-param decls, counterexample extraction. Gated:
run a real fuzz test that diverges when a guard was removed.

Run:  python -m pytest tests/test_nextgen_regfuzz.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.execground import foundry as F  # noqa: E402
from src.nextgen.execground import regfuzz as RF  # noqa: E402


def test_rename_contract_renames_decl_and_refs():
    src = ("contract Vault { function f() external {} }\n"
           "contract User { function g() external { new Vault(); } }")
    out = RF._rename_contract(src, "Vault", "OldTarget")
    assert "contract OldTarget {" in out
    assert "new OldTarget()" in out
    assert "contract Vault" not in out


def test_fuzz_param_decls():
    decls, args = RF._fuzz_param_decls(["uint256", "address"])
    assert decls == "uint256 p0, address p1"
    assert args == ", p0, p1"
    assert RF._fuzz_param_decls([]) == ("", "")


def test_extract_counterexample():
    tail = "... testFuzz failed\ncounterexample: calldata=0x.., args=[42]\n..."
    assert "args=[42]" in RF._extract_counterexample(tail)


def test_no_toolchain_is_pending(monkeypatch):
    monkeypatch.setattr(RF.foundry, "resolve", lambda *a, **k: None)
    r = RF.run_regression_fuzz(function="f", signature="f(uint256)",
                               old_source="x", new_source="y", contract="C")
    assert r.status == RF.PENDING


# --------------------------------------------------------------------------- #
# end to end
# --------------------------------------------------------------------------- #

_HAVE = F.resolve() is not None
_skip = pytest.mark.skipif(not _HAVE, reason="no reachable Foundry toolchain")

OLD_GUARDED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    uint256 public x;
    constructor() { owner = msg.sender; }
    function setX(uint256 v) external { require(msg.sender == owner, "no"); x = v; }
}
"""
NEW_UNGUARDED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    uint256 public x;
    constructor() { owner = msg.sender; }
    function setX(uint256 v) external { x = v; }
}
"""


@_skip
def test_removed_guard_produces_a_behavioural_divergence():
    r = RF.run_regression_fuzz(
        function="setX", signature="setX(uint256)",
        old_source=OLD_GUARDED, new_source=NEW_UNGUARDED, contract="Vault")
    assert r.status == RF.DIVERGENCE_FOUND, r.as_dict()
    assert r.diverged is True


@_skip
def test_identical_versions_show_no_divergence():
    r = RF.run_regression_fuzz(
        function="setX", signature="setX(uint256)",
        old_source=OLD_GUARDED, new_source=OLD_GUARDED, contract="Vault")
    assert r.status == RF.NO_DIVERGENCE, r.as_dict()
