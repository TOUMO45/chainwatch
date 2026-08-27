"""RC-DEDUP1. The same 3c finding on `UniswapV3Pair` was emitted TWICE against
a real v3-core commit - once attributed to `UniswapV3Factory.sol`, once to
`UniswapV3Pair.sol` - because `UniswapV3Pair` is reachable from both files'
compiled units, both files were genuinely in the commit's changed set, and
`accept_finding`'s per-file scope correctly admits both discoveries. Two bugs
compounded: `src/scan.py` stamped `f.file` with whichever file the walker
happened to be compiling (`rel`) instead of the file that actually declares
the fired contract, AND nothing collapsed the resulting duplicate.

Both are tested here as pure functions - no Slither/solc needed, exactly like
`_nothing_compared` in test_scope.py - because the defect is in how scan.py
assembles a Finding, not in any rule's detection logic.
"""

from __future__ import annotations

from pathlib import Path

from src import verdict as V
from src.scan import _dedupe, _repo_relative


def _f(**kw) -> V.Finding:
    base = dict(rule_id="3c", commit="deadbeef", contract="UniswapV3Pair",
                function=None, line=42, detail="UniswapV3Pair.reserve0 moved",
                raw_evidence={"variable": "reserve0"})
    base.update(kw)
    return V.Finding(**base)


# ------------------------------------------------------------- _repo_relative


def test_repo_relative_resolves_against_the_matching_root():
    cur_root = Path("/scratch/cur")
    prev_root = Path("/scratch/prev")
    abs_path = "/scratch/cur/contracts/UniswapV3Pair.sol"
    assert _repo_relative(abs_path, cur_root, prev_root) == "contracts/UniswapV3Pair.sol"


def test_repo_relative_tries_every_root_given():
    cur_root = Path("/scratch/cur")
    prev_root = Path("/scratch/prev")
    abs_path = "/scratch/prev/contracts/UniswapV3Pair.sol"
    assert _repo_relative(abs_path, cur_root, prev_root) == "contracts/UniswapV3Pair.sol"


def test_repo_relative_returns_none_when_no_root_matches():
    """Caller falls back to `rel` in this case - never silently wrong."""
    assert _repo_relative("/elsewhere/X.sol", Path("/scratch/cur")) is None


def test_repo_relative_returns_none_for_empty_path():
    assert _repo_relative(None, Path("/scratch/cur")) is None
    assert _repo_relative("", Path("/scratch/cur")) is None


# ------------------------------------------------------------------- _dedupe


def test_dedupe_collapses_the_same_declaration_found_twice():
    """The exact v3-core shape: one true fact, discovered once while
    compiling Factory.sol's unit (mislabelled) and once while compiling
    Pair.sol's unit (correctly labelled) - now that f.file is fixed both
    carry the SAME file, and dedupe collapses them to one."""
    a = _f(file="contracts/UniswapV3Pair.sol")
    b = _f(file="contracts/UniswapV3Pair.sol")
    out = _dedupe([a, b])
    assert len(out) == 1


def test_dedupe_keeps_distinct_variables_on_the_same_contract():
    a = _f(detail="UniswapV3Pair.reserve0 moved", raw_evidence={"variable": "reserve0"})
    b = _f(detail="UniswapV3Pair.reserve1 moved", raw_evidence={"variable": "reserve1"})
    out = _dedupe([a, b])
    assert len(out) == 2


def test_dedupe_keeps_the_same_contract_regressing_at_two_different_commits():
    a = _f(commit="aaaaaaa")
    b = _f(commit="bbbbbbb")
    out = _dedupe([a, b])
    assert len(out) == 2, "a real regression at commit B must not be swallowed " \
                          "because commit A happened to trip the same rule"


def test_dedupe_keeps_the_same_variable_fired_by_two_different_rules():
    a = _f(rule_id="3c")
    b = _f(rule_id="10")
    out = _dedupe([a, b])
    assert len(out) == 2


def test_dedupe_preserves_order_of_first_occurrence():
    a = _f(file="contracts/UniswapV3Factory.sol")
    b = _f(file="contracts/UniswapV3Factory.sol")
    c = _f(commit="cccccc", file="contracts/Other.sol")
    out = _dedupe([a, b, c])
    assert out == [a, c]
