"""COMP-L3 - `Stack too deep` must not cost a file its whole comparison.

Measured live on `1inch/farming` (2026-08-25): a genuine `Stack too deep`,
which is neither a broken file nor a wrong compiler version. It is the LEGACY
codegen running out of EVM stack slots on a function the IR pipeline compiles
without complaint. Every rule on that file was lost.

TWO THINGS THIS TEST PINS, both of which were measured rather than assumed:

1. **`--optimize` is mandatory alongside `--via-ir`.** solc's own diagnostic
   says to retry "while enabling the optimizer", and it means it: on 0.8.20,
   against the contract built below, `--via-ir` ALONE does not merely fail - it
   aborts with an uncaught C++ exception out of libyul and exits 2, while
   `--via-ir --optimize` exits 0. A retry that passed only `--via-ir` would
   have turned a clean compiler error into a compiler crash.

2. **The retry is gated on solc's own wording**, not enabled globally, because
   `--via-ir` is materially slower. Precision is unaffected either way:
   `--via-ir` changes CODEGEN, not the AST or the SlithIR every rule reads, so
   a file that compiles both ways yields the same analysis.

The contract below is a real reproduction, not a mock: 18 parameters and 18
return values all live across one expression. Note that it only fails when
BYTECODE is requested - `--combined-json abi` alone never runs codegen and so
never hits the error, which is why an early version of this reproduction
misleadingly "passed".

Run:  python -m pytest tests/test_via_ir_retry.py -q
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.rules import _shared  # noqa: E402

_N = 18


def _stack_too_deep_source() -> str:
    params = ", ".join(f"uint p{i}" for i in range(_N))
    rets = ", ".join("uint" for _ in range(_N))
    body = ", ".join(f"p{i}+1" for i in range(_N))
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.20;\n"
        "contract Deep {\n"
        f"    function f({params}) public pure returns ({rets}) {{\n"
        f"        return ({body});\n"
        "    }\n"
        "}\n"
    )


@pytest.fixture()
def deep_sol(tmp_path):
    p = tmp_path / "Deep.sol"
    p.write_text(_stack_too_deep_source(), encoding="utf-8")
    return p


# ------------------------------------------------------------ the predicate


def test_predicate_matches_solcs_own_wording():
    assert _shared._stack_too_deep(Exception(
        "Error: Stack too deep. Try compiling with `--via-ir` (cli)"))


def test_predicate_is_narrow():
    """A broad match would send genuinely broken files down a slow retry that
    cannot help them - the retry is worth paying for only where it resolves
    something."""
    for unrelated in ("ParserError: expected ';'",
                      "Source file requires different compiler version",
                      "Invalid option to --combined-json: storage-layout",
                      "DeclarationError: Identifier already declared"):
        assert not _shared._stack_too_deep(Exception(unrelated)), unrelated


def test_via_ir_args_include_the_optimizer():
    """THE MEASURED ONE. Without --optimize, solc aborts (exit 2) instead of
    compiling. See this module's docstring."""
    assert "--via-ir" in _shared.VIA_IR_ARGS
    assert "--optimize" in _shared.VIA_IR_ARGS


# ------------------------------------------------- the real compiler behaviour


def _solc(args, path) -> int:
    import os

    env = dict(os.environ, SOLC_VERSION="0.8.20")
    return subprocess.run(["solc", *args, "--combined-json", "abi,bin", str(path)],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=str(path.parent)).returncode


@pytest.mark.skipif(not _shared.shutil.which("solc"), reason="solc not on PATH")
def test_the_fixture_really_does_overflow_the_stack(deep_sol):
    """Guard on the fixture itself: if a future solc compiles this cleanly, the
    tests below would pass vacuously and prove nothing."""
    assert _solc([], deep_sol) != 0, "fixture no longer reproduces Stack too deep"


@pytest.mark.skipif(not _shared.shutil.which("solc"), reason="solc not on PATH")
def test_via_ir_without_the_optimizer_is_worse_than_the_original_error(deep_sol):
    """Locks the reason VIA_IR_ARGS is not just '--via-ir'."""
    assert _solc(["--via-ir"], deep_sol) != 0


@pytest.mark.skipif(not _shared.shutil.which("solc"), reason="solc not on PATH")
def test_via_ir_with_the_optimizer_compiles(deep_sol):
    assert _solc(_shared.VIA_IR_ARGS.split(), deep_sol) == 0


@pytest.mark.skipif(not _shared.shutil.which("solc"), reason="solc not on PATH")
def test_parse_recovers_a_stack_too_deep_file_end_to_end(deep_sol):
    """The whole point: a file that used to cost every rule on it now parses."""
    _shared.reset_caches()
    sl = _shared.parse(deep_sol)
    assert [c.name for c in sl.contracts] == ["Deep"]
