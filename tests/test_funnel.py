"""Capability 19 - the funnel trace.

The load-bearing test in this file is
`test_classic_gate_model_agrees_with_verdict_classify`: it walks the ENTIRE
product space of classic finding shapes (768 of them) and asserts that the
funnel's restatement of the six-field model returns exactly what
`verdict.classify` returns. If the funnel could ever disagree with the engine,
it would be a second opinion about what CONFIRMED means - the one thing this
project refuses to have. The equivalence is therefore proved, not asserted in
a docstring.
"""

from __future__ import annotations

import itertools

import pytest

from src import funnel as F
from src import verdict as V
from src.nextgen import state as S


# --------------------------------------------------------------------------- #
# 1. The classic model: proved equivalent to verdict.classify, exhaustively.
# --------------------------------------------------------------------------- #

_EVIDENCE_FIELDS = ("regression_commit", "pre_state", "post_state",
                    "reachability", "no_compensating_control")


def _finding(present: tuple[bool, ...], severity: str, liveness, survives):
    """A Finding shaped the way `verdict.build` actually shapes one.

    The liveness COUPLING matters and is not incidental: `build` writes the
    same value into `Finding.liveness` and `Evidence.liveness`, and
    `verdict.classify` reads both - the evidence field for presence, the top
    level for the LIVE requirement. Constructing them independently would test
    a Finding the engine never produces, and the first version of this test
    did exactly that (it reported a divergence that only existed in the
    fixture). `test_build_couples_the_two_liveness_fields` below pins the
    coupling so this simplification stays honest.
    """
    ev = V.Evidence(liveness=liveness)
    for name, is_present in zip(_EVIDENCE_FIELDS, present):
        if not is_present:
            continue
        setattr(ev, name, {"hash": "abc", "line_range": "1-2"}
                if name == "regression_commit" else f"{name} established")
    f = V.Finding(rule_id="1", severity_hint=severity, evidence=ev,
                  liveness=liveness, survives_to_head=survives)
    V.classify(f)
    return f


def test_build_couples_the_two_liveness_fields():
    for live in (None, V.LIVE, V.PATCHED, V.UNKNOWN):
        f = V.build({"rule_id": "1", "evidence": {}}, liveness=live)
        assert f.liveness == f.evidence.liveness == live


def test_classic_gate_model_agrees_with_verdict_classify():
    checked = 0
    for present in itertools.product((True, False), repeat=5):
        for severity in (V.CONFIRMED, V.CANDIDATE):
            for liveness in (None, V.LIVE, V.PATCHED, V.UNKNOWN):
                for survives in (True, False, None):
                    f = _finding(present, severity, liveness, survives)
                    gates = F._classic_gates(f.as_dict())
                    assert F._classic_classify(gates) == f.verdict, (
                        f"divergence at present={present} severity={severity} "
                        f"liveness={liveness} survives={survives}: "
                        f"funnel says {F._classic_classify(gates)}, "
                        f"engine says {f.verdict}")
                    checked += 1
    assert checked == 2 ** 5 * 2 * 4 * 3 == 768


def test_classic_trace_verifies_and_carries_deepen_steps():
    f = _finding((True,) * 5, V.CONFIRMED, V.LIVE, True)
    t = F.from_classic_finding(f.as_dict(), repo="acme/proto",
                               commit_pair=("aaa", "bbb"))
    F.verify(t)
    assert t["verdict"] == V.CONFIRMED
    assert t["distance_to_confirmed"] == 0
    assert t["kill_gate"] is None
    assert t["gate_model"] == F.CLASSIC_6
    assert t["engine"] == F.ENGINE_REGRESSION
    assert t["commit_pair"] == ["aaa", "bbb"]
    assert "deepen_steps" in t


def test_classic_missing_liveness_blocks_on_one_input():
    """The single most common real shape: a repo-only scan. Everything is
    established except the deployed address - two gates unresolved, but one
    single input closes both of them."""
    f = _finding((True,) * 5, V.CONFIRMED, None, True)
    t = F.from_classic_finding(f.as_dict())
    F.verify(t)
    assert t["verdict"] == V.CANDIDATE
    assert t["kill_gate"] is None
    # `liveness` (the evidence field) and `liveness_live` (the LIVE
    # requirement) are both unresolved by the same missing input.
    assert t["blocking_gates"] == ["liveness", "liveness_live"]
    assert t["distance_to_confirmed"] == 2
    reqs = {r["gate"]: r for r in t["evidence_requests"]}
    assert "address" in reqs["liveness"]["needs"]


def test_classic_patched_liveness_is_a_kill_not_a_distance():
    f = _finding((True,) * 5, V.CONFIRMED, V.PATCHED, True)
    t = F.from_classic_finding(f.as_dict())
    F.verify(t)
    assert t["kill_gate"] == "liveness_live"
    assert t["distance_to_confirmed"] is None


def test_classic_rule_ceiling_is_a_kill():
    f = _finding((True,) * 5, V.CANDIDATE, V.LIVE, True)
    t = F.from_classic_finding(f.as_dict())
    F.verify(t)
    assert t["kill_gate"] == "rule_ceiling"
    assert t["distance_to_confirmed"] is None


# --------------------------------------------------------------------------- #
# 2. The next-gen model: the trace is a projection of state.classify, never a
#    second implementation of it.
# --------------------------------------------------------------------------- #

def _fs(**gates) -> S.FindingState:
    fs = S.FindingState("cand-1")
    for name, result in gates.items():
        fs.set_gate(name, result)
    return fs


def test_fresh_finding_state_is_distance_thirteen_and_unknown():
    t = F.from_finding_state(S.FindingState("c"))
    F.verify(t)
    assert t["verdict"] == S.VERDICT_UNKNOWN
    assert t["distance_to_confirmed"] == len(S.GATES) == 13
    assert t["kill_gate"] is None


def test_all_gates_pass_is_confirmed_at_distance_zero():
    fs = _fs(**{g.name: S.PASS for g in S.GATES})
    t = F.from_finding_state(fs)
    F.verify(t)
    assert t["verdict"] == S.VERDICT_CONFIRMED
    assert t["distance_to_confirmed"] == 0
    assert t["blocking_gates"] == []


def test_one_failed_gate_names_the_kill_gate_and_drops_the_distance():
    gates = {g.name: S.PASS for g in S.GATES}
    gates["reproducer"] = S.FAIL
    t = F.from_finding_state(_fs(**gates))
    F.verify(t)
    assert t["verdict"] == S.VERDICT_REJECTED
    assert t["kill_gate"] == "reproducer"
    assert t["distance_to_confirmed"] is None


def test_kill_gate_is_the_first_failure_in_evidence_order():
    gates = {g.name: S.PASS for g in S.GATES}
    gates["reproducer"] = S.FAIL
    gates["reachable_path"] = S.FAIL      # earlier in GATES than reproducer
    t = F.from_finding_state(_fs(**gates))
    assert t["kill_gate"] == "reachable_path"


def test_skipped_optional_gate_counts_as_pass_exactly_as_the_engine_says():
    gates = {g.name: S.PASS for g in S.GATES}
    gates["economically_feasible"] = S.SKIPPED     # na_is_pass=True
    t = F.from_finding_state(_fs(**gates))
    F.verify(t)
    assert t["verdict"] == S.VERDICT_CONFIRMED
    assert t["distance_to_confirmed"] == 0


def test_skipped_blocking_gate_does_not_count_as_pass():
    gates = {g.name: S.PASS for g in S.GATES}
    gates["reproducer"] = S.SKIPPED               # na_is_pass=False
    t = F.from_finding_state(_fs(**gates))
    F.verify(t)
    assert t["verdict"] == S.VERDICT_UNKNOWN
    assert t["blocking_gates"] == ["reproducer"]
    assert t["distance_to_confirmed"] == 1


@pytest.mark.parametrize("stuck", [g.name for g in S.GATES])
def test_every_gate_has_a_registered_evidence_request(stuck):
    """A blocking gate with no registered request is a hole in the resolution
    queue: the reader is told what is missing but not what closes it."""
    gates = {g.name: S.PASS for g in S.GATES}
    gates[stuck] = S.PENDING
    t = F.from_finding_state(_fs(**gates))
    reqs = {r["gate"]: r for r in t["evidence_requests"]}
    assert stuck in reqs
    assert reqs[stuck]["how"] != "no registered evidence request for this gate"
    assert reqs[stuck]["status"] == S.PENDING


def test_distance_falls_by_one_for_each_gate_resolved():
    gates = {g.name: S.PENDING for g in S.GATES}
    seen = []
    for spec in S.GATES:
        t = F.from_finding_state(_fs(**gates))
        seen.append(t["distance_to_confirmed"])
        gates[spec.name] = S.PASS
    assert seen == list(range(13, 0, -1))


# --------------------------------------------------------------------------- #
# 3. verify() is the guard, so it must actually catch a corrupted trace.
# --------------------------------------------------------------------------- #

def test_verify_rejects_a_tampered_verdict():
    t = F.from_finding_state(S.FindingState("c"))
    t["verdict"] = S.VERDICT_CONFIRMED         # a lie about its own gates
    with pytest.raises(F.TraceDivergence):
        F.verify(t)


def test_verify_rejects_an_unknown_gate_model():
    t = F.from_finding_state(S.FindingState("c"))
    t["gate_model"] = "made-up"
    with pytest.raises(F.TraceDivergence):
        F.verify(t)


def test_verify_all_counts_every_trace():
    ts = [F.from_finding_state(S.FindingState(f"c{i}")) for i in range(5)]
    assert F.verify_all(ts) == 5


# --------------------------------------------------------------------------- #
# 4. The resolution queue: ordering is mechanical and stable.
# --------------------------------------------------------------------------- #

def _trace(fid, distance, severity_rank=2, killed=False):
    t = F.from_finding_state(S.FindingState(fid))
    t["distance_to_confirmed"] = None if killed else distance
    t["severity_rank"] = severity_rank
    return t


def test_queue_orders_by_distance_then_severity_then_id():
    rows = [_trace("d", 3), _trace("b", 1, severity_rank=1),
            _trace("a", 1, severity_rank=0), _trace("c", 2)]
    assert [t["finding_id"] for t in F.resolution_queue(rows)] == \
        ["a", "b", "c", "d"]


def test_queue_excludes_killed_candidates_by_default():
    rows = [_trace("live", 2), _trace("dead", 0, killed=True)]
    assert [t["finding_id"] for t in F.resolution_queue(rows)] == ["live"]
    both = F.resolution_queue(rows, include_killed=True)
    assert [t["finding_id"] for t in both] == ["live", "dead"]


def test_summary_counts_verdicts_kill_gates_and_median_distance():
    gates = {g.name: S.PASS for g in S.GATES}
    gates["target_live"] = S.FAIL
    killed = F.from_finding_state(_fs(**gates))
    open_one = F.from_finding_state(S.FindingState("c2"))
    s = F.summarize([killed, open_one])
    assert s["traces"] == 2
    assert s["verdicts"] == {S.VERDICT_REJECTED: 1, S.VERDICT_UNKNOWN: 1}
    assert s["kill_gates"] == {"target_live": 1}
    assert s["killed"] == 1 and s["resolvable"] == 1
    assert s["median_distance_to_confirmed"] == 13.0


def test_trace_records_provenance_context():
    t = F.from_finding_state(S.FindingState("c"), repo="acme/p",
                             commit_pair=("a", "b"), rule_class="rule 10",
                             finding_type="Access Control Security Regression")
    assert t["repo"] == "acme/p"
    assert t["rule_class"] == "rule 10"
    assert t["severity_rank"] == 0
    assert t["toolchain_versions"]["python"]
    assert t["schema"] == F.SCHEMA


# --------------------------------------------------------------------------- #
# 5. Real report artifacts, not synthetic ones. These are committed scan
#    outputs from real repositories; a trace built from one must verify.
# --------------------------------------------------------------------------- #

import json          # noqa: E402
import pathlib       # noqa: E402

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_REAL_REPORTS = [".scan-88mph-r10.json", ".e2-full-aave.json",
                 ".e2-full-88mph.json"]


@pytest.mark.parametrize("name", _REAL_REPORTS)
def test_traces_from_a_real_committed_scan_report_verify(name):
    path = _ROOT / name
    if not path.exists():                       # pragma: no cover
        pytest.skip(f"{name} not present")
    rep = json.loads(path.read_text(encoding="utf-8"))
    findings = rep.get("findings") or []
    traces = [F.from_classic_finding(f, repo=rep.get("repo", ""),
                                     commit_pair=(f.get("parent") or "",
                                                  f.get("commit") or ""))
              for f in findings]
    assert F.verify_all(traces) == len(findings)
    for f, t in zip(findings, traces):
        # The trace must carry the engine's own verdict, unaltered.
        assert t["verdict"] == f["verdict"]
        # Every unresolved gate names an input, or the queue is decorative.
        for req in t["evidence_requests"]:
            assert req["how"] != "no registered evidence request for this gate"


def test_the_88mph_finding_is_one_address_away():
    """The demo case, kept honest: the real rule-10 finding on 88mph's NFT
    stops on liveness/reachability, not on anything the tool could bluff its
    way past. If this ever reads distance 0 without an address, the funnel has
    started lying."""
    path = _ROOT / ".scan-88mph-r10.json"
    if not path.exists():                       # pragma: no cover
        pytest.skip("scan artifact not present")
    rep = json.loads(path.read_text(encoding="utf-8"))
    traces = [F.from_classic_finding(f) for f in rep["findings"]]
    assert traces, "the artifact should carry the rule-10 finding"
    t = traces[0]
    F.verify(t)
    assert t["verdict"] == V.CANDIDATE
    assert t["kill_gate"] is None
    assert "liveness" in t["blocking_gates"]
    assert t["distance_to_confirmed"] > 0


def test_required_inputs_deduplicate_across_gates():
    """Two gates waiting on the same deployed address are ONE piece of work.
    Distance still counts gates (it is a projection of the gate function), so
    the distinct inputs are reported next to it rather than instead of it."""
    f = _finding((True,) * 5, V.CONFIRMED, None, True)
    t = F.from_classic_finding(f.as_dict())
    assert t["blocking_gates"] == ["liveness", "liveness_live"]
    assert t["distance_to_confirmed"] == 2
    assert t["required_inputs"] == ["address", "rpc_url"]
