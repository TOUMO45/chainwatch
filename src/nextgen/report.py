"""Reporting mode (spec §23) - a professional security-research report.

Deterministic. Every line is pulled from a `state.FindingState`'s gate results
and their recorded notes; nothing is generated, nothing is embellished. Three
shapes, chosen by `state.classify`:

  CONFIRMED  every evidence gate passed -> a full finding with a severity
  UNKNOWN    evidence incomplete, nothing disproved -> the finding, plus
             exactly which gates are unresolved (spec §24)
  REJECTED   a gate failed -> "NOT A FINDING", plus the disproving reason

No dramatic language, no severity on a non-confirmed finding (same discipline
as the classic CANDIDATE-report rule enforced by `agent/verify.py`), no claim
that is not backed by a gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import state as S

# gate -> (confirmed-line label, how to phrase a non-PASS)
_LINES: tuple[tuple[str, str], ...] = (
    ("regression_commit", "Regression"),
    ("build_environment", "Build environment"),
    ("security_invariant", "Security property"),
    ("reachable_path", "Reachability"),
    ("state_reachable", "Required state"),
    ("no_compensating_control", "Compensating control"),
    ("invariant_violated", "Invariant violation"),
    ("reproducer", "Reproducer"),
    ("bytecode_provenance", "Deployment provenance"),
    ("target_live", "Live deployment"),
    ("economically_feasible", "Economic feasibility"),
    ("independent_validation", "Independent validation"),
    ("not_duplicate", "Deduplication"),
)

_PASS_PHRASE = {
    "regression_commit": "PROVEN",
    "build_environment": "VERIFIED",
    "security_invariant": "IDENTIFIED",
    "reachable_path": "PROVEN",
    "state_reachable": "PROVEN",
    "no_compensating_control": "NONE FOUND",
    "invariant_violated": "PROVEN",
    "reproducer": "PASS",
    "bytecode_provenance": "MATCH",
    "target_live": "YES",
    "economically_feasible": "FEASIBLE",
    "independent_validation": "PASS",
    "not_duplicate": "NOT A DUPLICATE",
}


@dataclass
class ReportInputs:
    finding_id: str = ""
    type_label: str = ""                 # "Authorization Security Regression"
    contract: str = ""
    function: str = ""
    regression_commit: str = ""
    security_property: str = ""
    root_cause: str = ""
    attacker_capability: str = "UNPRIVILEGED EOA"
    economic_impact: str = ""            # filled by §14 in Phase 5
    invariant_kind: str = ""             # e.g. ACCESS_CONTROL_INVARIANT


def _last_note_for_gate(fs: S.FindingState, gate: str) -> str:
    note = ""
    for t in fs.history:
        if t.note.startswith(f"gate {gate}="):
            note = t.note.split(":", 1)[1].strip() if ":" in t.note else ""
    return note


def _severity(inp: ReportInputs, gates: dict) -> str:
    """Conservative, and ONLY on a confirmed finding."""
    kind = (inp.invariant_kind or "").upper()
    unprivileged = "UNPRIVILEGED" in (inp.attacker_capability or "").upper()
    live = gates.get("target_live") == S.PASS
    if kind.startswith("ACCESS_CONTROL") or kind.startswith("DEPLOYMENT"):
        if unprivileged and live:
            return "CRITICAL"
        if unprivileged:
            return "HIGH"
        return "MEDIUM"
    if kind.startswith(("ACCOUNTING", "ECONOMIC")):
        return "HIGH" if live else "MEDIUM"
    return "MEDIUM"


def render(fs: S.FindingState, inp: Optional[ReportInputs] = None, *,
          evidence_graph=None) -> str:
    inp = inp or ReportInputs(finding_id=fs.finding_id)
    fine, verdict, reasons = S.classify(fs.gates)
    where = f"{inp.contract}.{inp.function}".strip(".") or "(target not named)"
    out: list[str] = []

    if verdict == S.VERDICT_CONFIRMED:
        out.append("CHAINWATCH CONFIRMED FINDING")
        out.append("=" * 27)
        out.append("")
        out.append(f"Severity:            {_severity(inp, fs.gates)}")
        out.append(f"Type:                {inp.type_label or 'Security Regression'}")
    elif verdict == S.VERDICT_UNKNOWN:
        out.append("CHAINWATCH FINDING - UNKNOWN (evidence incomplete)")
        out.append("=" * 49)
        out.append("")
        out.append("Severity:            NOT ASSIGNED (a non-confirmed finding "
                   "carries no severity)")
        out.append(f"Type:                {inp.type_label or 'Security Regression'}")
    else:  # REJECTED
        out.append(f"CHAINWATCH - NOT A FINDING ({fine})")
        out.append("=" * 40)
        out.append("")
        out.append("Severity:            NOT ASSIGNED")

    out.append(f"Finding id:          {inp.finding_id or fs.finding_id}")
    out.append(f"Affected:            {where}")
    if inp.regression_commit:
        out.append(f"Regression commit:   {inp.regression_commit}")
    if inp.security_property:
        out.append(f"Security property:   {inp.security_property}")
    if inp.root_cause:
        out.append(f"Root cause:          {inp.root_cause}")
    out.append(f"Attacker capability: {inp.attacker_capability}")
    if inp.economic_impact:
        out.append(f"Economic impact:     {inp.economic_impact}")
    out.append("")
    out.append("EVIDENCE CHAIN")
    out.append("-" * 14)
    for gate, label in _LINES:
        res = fs.gates.get(gate, S.PENDING)
        note = _last_note_for_gate(fs, gate)
        if res == S.PASS:
            phrase = _PASS_PHRASE.get(gate, "PASS")
            out.append(f"  {label + ':':<24} {phrase}"
                       + (f"  - {note}" if note else ""))
        elif res == S.FAIL:
            out.append(f"  {label + ':':<24} FAILED  - {note or 'see reasons'}")
        elif res == S.SKIPPED:
            out.append(f"  {label + ':':<24} n/a"
                       + (f"  - {note}" if note else ""))
        else:  # PENDING / UNKNOWN
            out.append(f"  {label + ':':<24} NOT ESTABLISHED"
                       + (f"  - {note}" if note else ""))

    out.append("")
    if verdict == S.VERDICT_CONFIRMED:
        out.append("Confidence:          EVIDENCE-COMPLETE")
    elif verdict == S.VERDICT_UNKNOWN:
        out.append("Confidence:          INCOMPLETE - unresolved gate(s): "
                   + ", ".join(sorted(g for g in fs.gates
                                      if fs.gates[g] in (S.PENDING, S.GATE_UNKNOWN,
                                                         S.SKIPPED))))
        out.append("")
        out.append("WHY NOT CONFIRMED")
        out.append("-" * 16)
        for r in reasons:
            out.append(f"  - {r}")
    else:
        out.append("WHY REJECTED")
        out.append("-" * 12)
        for r in reasons:
            out.append(f"  - {r}")

    if evidence_graph is not None:
        out.append("")
        out.append(evidence_graph.render_text())
        loose = evidence_graph.unsupported()
        if loose:
            out.append("")
            out.append("NOTE: the items above marked HYPOTHESIS are leads, not "
                       "evidence, and are excluded from every claim in this "
                       "report.")

    return "\n".join(out)


def render_dict(fs: S.FindingState, inp: Optional[ReportInputs] = None) -> dict:
    inp = inp or ReportInputs(finding_id=fs.finding_id)
    fine, verdict, reasons = S.classify(fs.gates)
    return {
        "finding_id": inp.finding_id or fs.finding_id,
        "verdict": verdict,
        "state": fine,
        "severity": _severity(inp, fs.gates) if verdict == S.VERDICT_CONFIRMED
        else None,
        "affected": f"{inp.contract}.{inp.function}".strip("."),
        "type": inp.type_label,
        "regression_commit": inp.regression_commit,
        "security_property": inp.security_property,
        "gates": dict(fs.gates),
        "reasons": reasons,
    }
