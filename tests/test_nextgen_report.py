"""Phase 4 - professional report mode (src/nextgen/report.py, spec §23).

Pure. Pins the three shapes (CONFIRMED / UNKNOWN / REJECTED), that a severity
is assigned ONLY on CONFIRMED, and that the evidence-chain lines are pulled
from gate results.

Run:  python -m pytest tests/test_nextgen_report.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import evidence_graph as EG  # noqa: E402
from src.nextgen import report as RPT  # noqa: E402
from src.nextgen import state as S  # noqa: E402


def _line_has(txt: str, *needles: str) -> bool:
    return any(all(n in line for n in needles) for line in txt.splitlines())


def _all_pass() -> S.FindingState:
    fs = S.FindingState("f1")
    for g in S.GATES:
        fs.set_gate(g.name, S.PASS, note="proved")
    return fs


def _inp():
    return RPT.ReportInputs(
        finding_id="f1", type_label="Authorization Security Regression",
        contract="Vault", function="withdraw",
        regression_commit="8f72a9c",
        security_property="Only an authorized user may withdraw assets.",
        root_cause="onlyOwner removed in 8f72a9c.",
        invariant_kind="ACCESS_CONTROL_INVARIANT")


def test_confirmed_report_has_severity_and_confidence():
    txt = RPT.render(_all_pass(), _inp())
    assert "CHAINWATCH CONFIRMED FINDING" in txt
    assert _line_has(txt, "Severity:", "CRITICAL")    # access-control + unpriv + live
    assert _line_has(txt, "Confidence:", "EVIDENCE-COMPLETE")
    assert _line_has(txt, "Reachability:", "PROVEN")
    assert _line_has(txt, "Compensating control:", "NONE FOUND")


def test_unknown_report_names_the_unresolved_gates_and_assigns_no_severity():
    fs = _all_pass()
    fs.set_gate("reproducer", S.PENDING)
    fs.set_gate("target_live", S.GATE_UNKNOWN)
    txt = RPT.render(fs, _inp())
    assert "UNKNOWN (evidence incomplete)" in txt
    assert "NOT ASSIGNED" in txt
    assert "reproducer" in txt and "target_live" in txt
    assert "WHY NOT CONFIRMED" in txt


def test_rejected_report_says_not_a_finding_with_the_reason():
    fs = _all_pass()
    fs.set_gate("no_compensating_control", S.FAIL, note="internal auth lib checks msg.sender")
    txt = RPT.render(fs, _inp())
    assert "NOT A FINDING (FALSE_POSITIVE)" in txt
    assert "WHY REJECTED" in txt
    assert _line_has(txt, "Compensating control:", "FAILED")


def test_severity_scales_with_liveness():
    inp = _inp()
    base = {g.name: S.PASS for g in S.GATES}
    assert RPT._severity(inp, {**base, "target_live": S.PASS}) == "CRITICAL"
    assert RPT._severity(inp, {**base, "target_live": S.GATE_UNKNOWN}) == "HIGH"
    npriv = RPT.ReportInputs(**{**inp.__dict__, "attacker_capability": "MINTER role"})
    assert RPT._severity(npriv, {**base, "target_live": S.GATE_UNKNOWN}) == "MEDIUM"


def test_evidence_graph_appendix_and_unsupported_note():
    g = EG.EvidenceGraph()
    g.add_node(EG.ATTACK_PATH, "ungrounded guess", established_by=EG.LLM_HYPOTHESIS)
    txt = RPT.render(_all_pass(), _inp(), evidence_graph=g)
    assert "EVIDENCE GRAPH" in txt
    assert "HYPOTHESIS are leads, not" in txt


def test_render_dict_mirrors_the_verdict():
    d = RPT.render_dict(_all_pass(), _inp())
    assert d["verdict"] == S.VERDICT_CONFIRMED
    assert d["severity"] == "CRITICAL"
    d2 = RPT.render_dict(S.FindingState("x"))       # all PENDING
    assert d2["verdict"] == S.VERDICT_UNKNOWN
    assert d2["severity"] is None
