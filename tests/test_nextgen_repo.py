"""Tier 1 - dependency-aware real-repo scanning (src/nextgen/repo.py + pipeline.run_from_repo).

Pure helpers always run. The end-to-end case needs slither/solc/git AND the
`realworld-test/88mph-src` checkout that `backtest-cases.json` anchors to; it
skips visibly otherwise. No network (repo-only pass).

Run:  python -m pytest tests/test_nextgen_repo.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.nextgen import repo as RP  # noqa: E402


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #

def test_exact_from_pragma():
    assert RP._exact_from_pragma("0.5.17") == "0.5.17"
    assert RP._exact_from_pragma("=0.8.19") == "0.8.19"
    assert RP._exact_from_pragma("^0.8.0") is None
    assert RP._exact_from_pragma(">=0.7.0 <0.9.0") is None
    assert RP._exact_from_pragma(None) is None


def test_pragma_of():
    assert RP._pragma_of("pragma solidity 0.5.17;\ncontract X {}") == "0.5.17"
    assert RP._pragma_of("// no pragma") is None


def test_resolve_import_relative(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "B.sol").write_text("x")
    got = RP._resolve_import("./B.sol", tmp_path / "a", tmp_path)
    assert got == (tmp_path / "a" / "B.sol").resolve()


def test_python_flatten_inlines_relative_imports(tmp_path):
    (tmp_path / "Lib.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "library Lib { function f() internal pure returns (uint) { return 1; } }\n")
    entry = tmp_path / "Main.sol"
    entry.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        'import "./Lib.sol";\n'
        "contract Main { function g() external pure returns (uint) { return Lib.f(); } }\n")
    flat = RP._python_flatten(entry, tmp_path)
    assert "library Lib" in flat and "contract Main" in flat
    assert flat.count("pragma solidity") == 1
    assert 'import "./Lib.sol"' not in flat


# --------------------------------------------------------------------------- #
# end to end on the real 88mph repo (repo-only, no network)
# --------------------------------------------------------------------------- #

pytest.importorskip("slither")
_88MPH = ROOT / "realworld-test" / "88mph-src"
_HAVE_88MPH = (_88MPH / ".git").exists()

_PARENT = "5f52a2ead702e4cb9ab3d04a1109807462dde228"
_VULN = "a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e"


@pytest.mark.skipif(not _HAVE_88MPH,
                    reason="realworld-test/88mph-src checkout not present")
def test_repocontext_compiles_both_sides_with_dependencies():
    rc = RP.RepoContext(str(_88MPH))
    try:
        before = rc.compiled(_PARENT, "contracts/NFT.sol")
        after = rc.compiled(_VULN, "contracts/NFT.sol")
        nb = [c for c in before.contracts if c.name == "NFT"][0]
        na = [c for c in after.contracts if c.name == "NFT"][0]
        b_fns = {f.name for f in nb.functions}
        a_fns = {f.name for f in na.functions}
        assert "init" not in b_fns and any(f.is_constructor for f in nb.functions)
        assert "init" in a_fns                       # the regression: init added
        # imports resolved -> Ownable's _owner is visible
        assert any("_transferOwnership" in {ic.function.name
                                            for ic in f.all_internal_calls()
                                            if getattr(ic.function, "name", None)}
                   for f in na.functions if f.name == "init")
    finally:
        rc.close()


@pytest.mark.skipif(not _HAVE_88MPH,
                    reason="realworld-test/88mph-src checkout not present")
def test_run_from_repo_confirms_the_shape_repo_only():
    from src.nextgen import pipeline as PL
    from src.nextgen import state as S

    res = PL.run_from_repo(
        repo=str(_88MPH), parent=_PARENT, commit=_VULN,
        file="contracts/NFT.sol", contract="NFT", function="init", rule_id="10")

    g = res.finding_state.gates
    # git history + dependency-resolved analysis establishes these offline:
    assert g["regression_commit"] == S.PASS
    assert g["security_invariant"] == S.PASS
    assert g["reachable_path"] == S.PASS          # EOA --CALL--> NFT.init, unprivileged
    assert g["no_compensating_control"] == S.PASS
    assert g["build_environment"] == S.PASS       # exact 0.5.17 pragma
    # no --address -> cannot CONFIRM; the honest offline verdict is UNKNOWN
    assert res.verdict == S.VERDICT_UNKNOWN
    # the attack-path evidence in the report names the real target
    from src.nextgen import evidence_graph as EG
    ap_nodes = res.evidence_graph.nodes(EG.ATTACK_PATH)
    assert ap_nodes and any("NFT.init" in n.label for n in ap_nodes)
