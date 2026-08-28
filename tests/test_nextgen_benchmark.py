"""Phase 4 - the next-gen benchmark (src/nextgen/benchmark/*, spec §20, §27).

Two layers:
  * pure: Metrics.tally + the §27 CONFIRMED/FP ratio
  * slither-gated: run the OFFLINE suite (heavy on hard negatives) and require
    zero false positives and every case correct.

Run:  python -m pytest tests/test_nextgen_benchmark.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.benchmark import model as M  # noqa: E402
from src.nextgen.benchmark import runner as RUN  # noqa: E402


# --------------------------------------------------------------------------- #
# pure metrics
# --------------------------------------------------------------------------- #

def _r(nature, expected, actual):
    return M.BenchmarkResult("c", nature, expected, actual, actual_state=actual)


def test_tally_confusion_and_ratio():
    results = [
        _r(M.POSITIVE, M.EXP_CONFIRMED, "CONFIRMED"),        # TP
        _r(M.POSITIVE, M.EXP_CONFIRMED, "UNKNOWN"),          # FN
        _r(M.HARD_NEGATIVE, M.EXP_REJECTED, "REJECTED"),     # TN
        _r(M.HARD_NEGATIVE, M.EXP_REJECTED, "CONFIRMED"),    # FP
    ]
    m = M.tally(results)
    assert (m.tp, m.fn, m.tn, m.fp) == (1, 1, 1, 1)
    assert m.precision == 0.5
    assert m.recall == 0.5
    assert m.confirmed_over_false_positive == 1.0


def test_ratio_is_none_when_no_false_positives():
    results = [_r(M.HARD_NEGATIVE, M.EXP_REJECTED, "REJECTED"),
               _r(M.POSITIVE, M.EXP_CONFIRMED, "CONFIRMED")]
    m = M.tally(results)
    assert m.fp == 0
    assert m.confirmed_over_false_positive is None
    assert "no false positives" in m.render_text()


def test_result_correctness_requires_gate_match_too():
    r = M.BenchmarkResult("c", M.HARD_NEGATIVE, M.EXP_REJECTED, "REJECTED",
                          gate_mismatches=["reachable_path: want FAIL, got PASS"])
    assert r.correct is False


# --------------------------------------------------------------------------- #
# offline suite (needs slither/solc)
# --------------------------------------------------------------------------- #

pytest.importorskip("slither")
from src.nextgen import _solc  # noqa: E402
from src.nextgen.benchmark import cases as CASES  # noqa: E402

_TRIVIAL = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract P{function f() external pure returns(uint){return 1;}}\n")
try:
    _solc.slither_for_source(_TRIVIAL)
    _OK = True
except Exception:  # noqa: BLE001
    _OK = False


@pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")
def test_offline_suite_has_zero_false_positives_and_every_case_correct():
    results, metrics = RUN.run_suite(CASES.OFFLINE_CASES)
    wrong = [r.as_dict() for r in results if not r.correct]
    assert metrics.errors == 0, wrong
    assert metrics.fp == 0, f"false positives: {wrong}"
    assert wrong == [], wrong
    assert metrics.confirmed_over_false_positive is None   # no FP -> the good case
    # the suite is hard-negative-heavy by construction
    assert sum(1 for c in CASES.OFFLINE_CASES if c.nature == M.HARD_NEGATIVE) >= 3


@pytest.mark.skipif(not _OK, reason="slither/solc unavailable here")
def test_offline_suite_metric_text_renders():
    _, metrics = RUN.run_suite(CASES.OFFLINE_CASES)
    txt = metrics.render_text()
    assert "CHAINWATCH NEXT-GEN BENCHMARK" in txt
    assert "CONFIRMED / FP" in txt
