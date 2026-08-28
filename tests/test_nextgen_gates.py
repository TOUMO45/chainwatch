"""Phase 1 - the analysis-to-gate bridge (src/nextgen/gates.py).

Pure. Confirms Phase 1 outputs move the Phase 0 state machine the intended way,
and never past what the evidence supports.

Run:  python -m pytest tests/test_nextgen_gates.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import buildenv as BE  # noqa: E402
from src.nextgen import gates as G  # noqa: E402
from src.nextgen import state as S  # noqa: E402
from src.nextgen import timemachine as TM  # noqa: E402


def _snap(sha, present, value=None, measurable=True, subject=""):
    return TM.Snapshot(sha, sha[:12], "dev", "2026-01-01T00:00:00Z",
                       subject or sha, present, value, measurable)


def test_live_regression_timeline_passes_the_regression_gate():
    tl = TM.build_timeline(
        [_snap("c1", True, ("g",), subject="add guard"),
         _snap("c2", False, (), subject="drop guard")],
        title="Only owner withdraws", kind=TM.ACCESS_CONTROL,
        paths=("V.sol",))
    fs = S.FindingState("f1")
    G.apply_timeline(fs, tl, evidence_ref="prop-1")
    assert fs.gates["regression_commit"] == S.PASS
    assert fs.gates["security_invariant"] == S.PASS
    assert fs.history[-1].evidence_ref == "prop-1" or any(
        t.evidence_ref == "prop-1" for t in fs.history)


def test_property_present_at_head_fails_the_regression_gate():
    tl = TM.build_timeline(
        [_snap("c1", False, ()), _snap("c2", True, ("g",))],
        title="Only owner withdraws", kind=TM.ACCESS_CONTROL)
    fs = S.FindingState("f1")
    G.apply_timeline(fs, tl)
    assert fs.gates["regression_commit"] == S.FAIL
    fine, verdict, _ = S.classify(fs.gates)
    assert verdict == S.VERDICT_REJECTED
    assert fine == S.INSUFFICIENT_EVIDENCE


def test_unmeasurable_timeline_leaves_regression_gate_unknown():
    tl = TM.build_timeline([_snap("c1", False, None, measurable=False)],
                           title="p", kind=TM.CODE)
    fs = S.FindingState("f1")
    G.apply_timeline(fs, tl)
    assert fs.gates["regression_commit"] == S.GATE_UNKNOWN
    assert fs.verdict() == S.VERDICT_UNKNOWN


def test_buildenv_pass_and_fail_map_straight_through():
    ok = BE.analyze(BE.BuildContext(pragma_expr="0.8.19", pinned_solc="0.8.19",
                                    analysis_solc="0.8.19"))
    fs = S.FindingState("f1")
    G.apply_buildenv(fs, ok)
    assert fs.gates["build_environment"] == S.PASS

    bad = BE.analyze(BE.BuildContext(pragma_expr="0.7.6", pinned_solc="0.7.6",
                                     analysis_solc="0.8.17"))
    fs2 = S.FindingState("f2")
    G.apply_buildenv(fs2, bad)
    assert fs2.gates["build_environment"] == S.FAIL
    fine, verdict, _ = S.classify(fs2.gates)
    assert verdict == S.VERDICT_REJECTED


def test_timeline_and_buildenv_together_still_need_the_rest_of_the_chain():
    tl = TM.build_timeline(
        [_snap("c1", True, ("g",)), _snap("c2", False, ())],
        title="p", kind=TM.ACCESS_CONTROL, paths=("V.sol",))
    fs = S.FindingState("f1")
    G.apply_timeline(fs, tl)
    G.apply_buildenv(fs, BE.analyze(BE.BuildContext(
        pragma_expr="0.8.19", pinned_solc="0.8.19", analysis_solc="0.8.19")))
    # two gates PASS, everything else still PENDING -> UNKNOWN, not CONFIRMED
    assert fs.verdict() == S.VERDICT_UNKNOWN
    assert fs.gates["reproducer"] == S.PENDING
