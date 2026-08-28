"""Phase 1 - compiler / build-environment security (src/nextgen/buildenv.py, spec §19).

Pure - no compiler, no chain. Pins the five risk patterns and, above all, that
the `build_environment` gate is conservative: FAIL only for a provable drift,
PASS only for an exact matching build, UNKNOWN otherwise.

Run:  python -m pytest tests/test_nextgen_buildenv.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import buildenv as BE  # noqa: E402
from src.nextgen import state as S  # noqa: E402


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def test_parse_version_and_range_detection():
    assert BE.parse_version("0.8.20") == (0, 8, 20)
    assert BE.parse_version("v0.5.17+commit.d19bba13") == (0, 5, 17)
    assert BE.parse_version(None) is None
    assert BE.is_range_pragma("^0.8.0") is True
    assert BE.is_range_pragma(">=0.7.0 <0.9.0") is True
    assert BE.is_range_pragma("0.8") is True          # not fully qualified
    assert BE.is_range_pragma("0.8.19") is False
    assert BE.is_range_pragma("pragma solidity 0.8.19;") is False


def test_crossed_boundaries_is_order_independent():
    a = BE.crossed_boundaries((0, 7, 6), (0, 8, 4))
    b = BE.crossed_boundaries((0, 8, 4), (0, 7, 6))
    assert a == b
    assert any(bnd == (0, 8, 0) for bnd, _ in a)
    assert BE.crossed_boundaries((0, 8, 1), (0, 8, 9)) == []


def test_matching_advisories_are_trigger_gated():
    v = (0, 8, 13)
    assert BE.matching_advisories(v) == []                       # no trigger on
    hits = BE.matching_advisories(v, via_ir=True)
    assert any(a.id == "via-ir-inline-asm-memory-2022" for a in hits)


# --------------------------------------------------------------------------- #
# analyze() - gate behaviour
# --------------------------------------------------------------------------- #

def test_exact_matching_build_with_no_deployment_passes():
    ctx = BE.BuildContext(pragma_expr="0.8.19", pinned_solc="0.8.19",
                          analysis_solc="0.8.19")
    rep = BE.analyze(ctx)
    assert rep.gate == S.PASS
    assert rep.blocking == []


def test_range_pragma_alone_is_advisory_not_a_fail():
    ctx = BE.BuildContext(pragma_expr="^0.8.0", pinned_solc="0.8.19",
                          analysis_solc="0.8.19")
    rep = BE.analyze(ctx)
    assert rep.gate in (S.GATE_UNKNOWN,)          # not PASS (not exact), not FAIL
    assert any(h.pattern == BE.RANGE_PRAGMA and h.severity == "advisory"
               for h in rep.hits)


def test_semantic_boundary_between_pinned_and_analysis_is_blocking():
    ctx = BE.BuildContext(pragma_expr="0.7.6", pinned_solc="0.7.6",
                          analysis_solc="0.8.17")
    rep = BE.analyze(ctx)
    assert rep.gate == S.FAIL
    assert any(h.pattern == BE.HISTORICAL_MISMATCH for h in rep.blocking)


def test_known_buggy_analysis_compiler_with_trigger_is_blocking():
    ctx = BE.BuildContext(pragma_expr="0.8.13", pinned_solc="0.8.13",
                          analysis_solc="0.8.13", analysis_via_ir=True)
    rep = BE.analyze(ctx)
    assert rep.gate == S.FAIL
    assert any(h.pattern == BE.KNOWN_BUGGY_COMPILER for h in rep.blocking)


def test_known_buggy_without_the_trigger_does_not_fire():
    ctx = BE.BuildContext(pragma_expr="0.8.13", pinned_solc="0.8.13",
                          analysis_solc="0.8.13", analysis_via_ir=False)
    rep = BE.analyze(ctx)
    assert not any(h.pattern == BE.KNOWN_BUGGY_COMPILER for h in rep.hits)


def test_optimizer_runs_drift_is_blocking_even_if_versions_match():
    ctx = BE.BuildContext(
        pragma_expr="0.8.19", pinned_solc="0.8.19", analysis_solc="0.8.19",
        deployed_solc="0.8.19",
        analysis_optimizer=True, analysis_runs=200,
        deployed_optimizer=True, deployed_runs=10_000)
    rep = BE.analyze(ctx)
    assert rep.gate == S.FAIL
    assert any(h.pattern == BE.OPTIMIZER_DRIFT for h in rep.blocking)


def test_via_ir_drift_is_blocking():
    ctx = BE.BuildContext(
        pragma_expr="0.8.19", pinned_solc="0.8.19", analysis_solc="0.8.19",
        deployed_solc="0.8.19", analysis_via_ir=False, deployed_via_ir=True)
    rep = BE.analyze(ctx)
    assert rep.gate == S.FAIL


def test_evm_version_drift_is_blocking():
    ctx = BE.BuildContext(
        pragma_expr="0.8.19", pinned_solc="0.8.19", analysis_solc="0.8.19",
        deployed_solc="0.8.19",
        analysis_evm="london", deployed_evm="shanghai")
    rep = BE.analyze(ctx)
    assert rep.gate == S.FAIL
    assert any(h.pattern == BE.EVM_VERSION_DRIFT for h in rep.blocking)


def test_shanghai_push0_split_is_advisory_when_evm_unknown():
    ctx = BE.BuildContext(pragma_expr="0.8.19", pinned_solc="0.8.19",
                          analysis_solc="0.8.19", deployed_solc="0.8.25")
    rep = BE.analyze(ctx)
    assert any(h.pattern == BE.EVM_VERSION_DRIFT and h.severity == "advisory"
               for h in rep.hits)


def test_full_match_to_deployment_passes():
    ctx = BE.BuildContext(
        pragma_expr="0.8.19", pinned_solc="0.8.19", analysis_solc="0.8.19",
        deployed_solc="0.8.19",
        analysis_optimizer=True, analysis_runs=200, analysis_via_ir=False,
        deployed_optimizer=True, deployed_runs=200, deployed_via_ir=False,
        analysis_evm="paris", deployed_evm="paris")
    rep = BE.analyze(ctx)
    assert rep.gate == S.PASS


def test_matching_versions_but_unknown_optimizer_is_unknown_not_pass():
    ctx = BE.BuildContext(
        pragma_expr="0.8.19", pinned_solc="0.8.19", analysis_solc="0.8.19",
        deployed_solc="0.8.19")
    rep = BE.analyze(ctx)
    assert rep.gate == S.GATE_UNKNOWN


def test_no_information_is_unknown():
    assert BE.analyze(BE.BuildContext()).gate == S.GATE_UNKNOWN


def test_report_dict_and_text_render():
    ctx = BE.BuildContext(pragma_expr="^0.8.0", analysis_solc="0.8.20")
    rep = BE.analyze(ctx)
    d = rep.as_dict()
    assert d["gate"] == rep.gate
    assert "BUILD-ENVIRONMENT SECURITY" in rep.render_text()
