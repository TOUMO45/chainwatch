"""Phase 10 - finding taxonomy + FACT/INFERENCE/ASSUMPTION report
(spec sections 26, 27) and the LIVE-hunt gate profile (spec section 18).

Deep Hunt does not collapse everything into "vulnerability". A finding carries a
`FindingType` (REGRESSION / LIVE_LOGIC / ACCOUNTING / ECONOMIC / STATE_MACHINE /
ACCESS_CONTROL / ORACLE / CROSS_CONTRACT / PROTOCOL_INVARIANT / DEPLOYMENT) and
a `confidence` that is NOT forced binary (CONFIRMED / LIKELY / CANDIDATE /
UNKNOWN / REJECTED).

`classify_live(gates)` is `state.classify` with the two git-regression links
(`regression_commit`, `build_environment`) made non-blocking - a live finding
has no regression to identify. Everything else in the section-18 chain still
blocks: no reproduced invariant violation, no CONFIRMED. `state.py` is NOT
modified.

Every rendered line is tagged FACT (a deterministic node established it),
INFERENCE (derived, defensible, not observed), or ASSUMPTION (a modelling
choice). An inference is never presented as a fact (spec section 22).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .. import state as S
from . import invariants as INV

# --------------------------------------------------------------------------- #
# taxonomy (spec section 26)
# --------------------------------------------------------------------------- #

REGRESSION = "REGRESSION"
LIVE_LOGIC = "LIVE_LOGIC"
ACCOUNTING = "ACCOUNTING"
ECONOMIC = "ECONOMIC"
STATE_MACHINE = "STATE_MACHINE"
ACCESS_CONTROL = "ACCESS_CONTROL"
ORACLE = "ORACLE"
CROSS_CONTRACT = "CROSS_CONTRACT"
PROTOCOL_INVARIANT = "PROTOCOL_INVARIANT"
DEPLOYMENT = "DEPLOYMENT"

FINDING_TYPES = frozenset({
    REGRESSION, LIVE_LOGIC, ACCOUNTING, ECONOMIC, STATE_MACHINE, ACCESS_CONTROL,
    ORACLE, CROSS_CONTRACT, PROTOCOL_INVARIANT, DEPLOYMENT,
})

# confidence - deliberately not binary (spec section 18)
CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
CANDIDATE = "CANDIDATE"
UNKNOWN = "UNKNOWN"
REJECTED = "REJECTED"

# statement class (spec section 27)
FACT = "FACT"
INFERENCE = "INFERENCE"
ASSUMPTION = "ASSUMPTION"

_SOURCE_TO_TYPE = {
    INV.SRC_CONSERVATION: ACCOUNTING,
    INV.SRC_ENTITLEMENT: ACCOUNTING,
    INV.SRC_SHARE_MATH: ACCOUNTING,
    INV.SRC_SUPPLY_SUM: ACCOUNTING,
    INV.SRC_DEBT_LTV: ECONOMIC,
    INV.SRC_AUTH_REACH: ACCESS_CONTROL,
    INV.SRC_STATE_MACHINE: STATE_MACHINE,
    INV.SRC_REPLAY: STATE_MACHINE,
    INV.SRC_ORACLE: ORACLE,
    INV.SRC_PROTOCOL: PROTOCOL_INVARIANT,
}


def finding_type_for(invariant) -> str:
    src = getattr(invariant, "source", "")
    if src.startswith(INV.SRC_PROTOCOL):
        return PROTOCOL_INVARIANT
    if getattr(invariant, "kind", "") == INV.IM.CROSS_CONTRACT:
        return CROSS_CONTRACT
    return _SOURCE_TO_TYPE.get(src, LIVE_LOGIC)


# --------------------------------------------------------------------------- #
# the LIVE-hunt gate profile (spec section 18)
# --------------------------------------------------------------------------- #

_LIVE_NONBLOCKING = frozenset({"regression_commit", "build_environment"})


def classify_live(gates: dict) -> tuple[str, str, list[str]]:
    """`state.classify`, with the two git-regression links non-blocking.

      1. any blocking gate FAIL      -> REJECTED at that gate's on_fail state
      2. else any blocking gate not PASS (and not in _LIVE_NONBLOCKING) -> UNKNOWN
      3. else -> CONFIRMED
    """
    reasons: list[str] = []
    failed: list = []
    unresolved: list[str] = []
    for spec in S.GATES:
        raw = gates.get(spec.name, S.PENDING)
        eff = S._gate_effective(spec, raw)
        if eff == S.FAIL:
            failed.append(spec)
            reasons.append(f"gate {spec.name} FAILED "
                           f"(spec sec {', '.join(spec.sections)}) -> {spec.on_fail}")
        elif (eff != S.PASS and spec.blocks_confirm
              and spec.name not in _LIVE_NONBLOCKING):
            unresolved.append(spec.name)
            reasons.append(f"gate {spec.name} is {raw} - not established")
    if failed:
        return failed[0].on_fail, S.VERDICT_REJECTED, reasons
    if unresolved:
        return S.UNKNOWN, S.VERDICT_UNKNOWN, reasons
    return S.CONFIRMED, S.VERDICT_CONFIRMED, ["every live evidence gate passed"]


def confidence_for(verdict: str, gates: dict) -> str:
    if verdict == S.VERDICT_REJECTED:
        return REJECTED
    if verdict == S.VERDICT_CONFIRMED:
        return CONFIRMED
    g = gates
    if g.get("reproducer") == S.PASS and g.get("invariant_violated") == S.PASS:
        return LIKELY                       # observed, but deployment unproven
    if g.get("security_invariant") == S.PASS and g.get("reachable_path") == S.PASS:
        return CANDIDATE                    # statically supported + reachable
    return UNKNOWN


_SEV_BY_TYPE = {
    ACCOUNTING: "high", ECONOMIC: "high", ORACLE: "high",
    ACCESS_CONTROL: "high", CROSS_CONTRACT: "high", DEPLOYMENT: "high",
    STATE_MACHINE: "medium", PROTOCOL_INVARIANT: "medium", LIVE_LOGIC: "medium",
    REGRESSION: "medium",
}


def severity_for(confidence: str, finding_type: str,
                 protocol_loss_usd: Optional[float] = None) -> str:
    if confidence in (UNKNOWN, REJECTED, CANDIDATE):
        return "unknown"                    # no severity without a proof
    base = _SEV_BY_TYPE.get(finding_type, "medium")
    if confidence == CONFIRMED and (protocol_loss_usd or 0) >= 100_000:
        return "critical"
    if confidence == LIKELY:
        # one notch down - not deployment-verified
        return {"critical": "high", "high": "medium", "medium": "low"}.get(base, base)
    return base


# --------------------------------------------------------------------------- #
# the finding record (spec section 27 fields)
# --------------------------------------------------------------------------- #

@dataclass
class Line:
    cls: str                                # FACT / INFERENCE / ASSUMPTION
    text: str

    def as_dict(self) -> dict:
        return {"class": self.cls, "text": self.text}


@dataclass
class DeepFinding:
    finding_id: str
    finding_type: str
    title: str
    confidence: str = UNKNOWN
    severity: str = "unknown"
    target: str = ""
    chain: str = ""
    block: Optional[int] = None
    contract: str = ""
    implementation: str = ""
    function: str = ""
    security_property: str = ""
    why_it_should_hold: str = ""
    how_discovered: str = ""
    min_sequence: list[str] = field(default_factory=list)
    initial_state: dict = field(default_factory=dict)
    final_state: dict = field(default_factory=dict)
    attacker_gain: str = ""
    protocol_loss: str = ""
    required_capital: str = ""
    execution_proof: str = ""
    storage_changes: list = field(default_factory=list)
    events: list = field(default_factory=list)
    calls: list = field(default_factory=list)
    git_provenance: str = "n/a - live hunt, no regression required"
    bytecode_provenance: str = ""
    independent_reproduction: str = ""
    lines: list[Line] = field(default_factory=list)
    gates: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.finding_type not in FINDING_TYPES:
            raise ValueError(f"unknown finding type {self.finding_type!r}")

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "type": self.finding_type,
            "title": self.title, "confidence": self.confidence,
            "severity": self.severity, "target": self.target, "chain": self.chain,
            "block": self.block, "contract": self.contract,
            "implementation": self.implementation, "function": self.function,
            "security_property": self.security_property,
            "why_it_should_hold": self.why_it_should_hold,
            "how_discovered": self.how_discovered,
            "min_sequence": list(self.min_sequence),
            "initial_state": self.initial_state, "final_state": self.final_state,
            "attacker_gain": self.attacker_gain,
            "protocol_loss": self.protocol_loss,
            "required_capital": self.required_capital,
            "execution_proof": self.execution_proof,
            "storage_changes": list(self.storage_changes),
            "events": list(self.events), "calls": list(self.calls),
            "git_provenance": self.git_provenance,
            "bytecode_provenance": self.bytecode_provenance,
            "independent_reproduction": self.independent_reproduction,
            "lines": [ln.as_dict() for ln in self.lines],
            "gates": dict(self.gates), "reasons": list(self.reasons),
            "notes": list(self.notes),
        }

    def render(self) -> str:
        head = "REJECTED - NOT A FINDING" if self.confidence == REJECTED else \
               f"{self.confidence} {self.finding_type}"
        out = ["-" * 78, f"{head}   [{self.finding_id}]", "-" * 78,
               f"Title       {self.title}",
               f"Severity    {self.severity}",
               f"Target      {self.target or self.contract}"
               + (f".{self.function}" if self.function else ""),
               f"Chain       {self.chain or 'n/a'}    Block {self.block or 'n/a'}",
               f"Contract    {self.contract}"
               + (f"   impl {self.implementation}" if self.implementation else "")]
        if self.security_property:
            out.append(f"\nSecurity property\n  {self.security_property}")
        if self.why_it_should_hold:
            out.append(f"Why it should hold\n  {self.why_it_should_hold}")
        if self.how_discovered:
            out.append(f"How Chainwatch found it\n  {self.how_discovered}")
        if self.min_sequence:
            out.append("Minimal reproduction sequence")
            for i, s in enumerate(self.min_sequence, 1):
                out.append(f"  {i}. {s}")
        if self.attacker_gain or self.protocol_loss:
            out.append(f"Impact      attacker_gain={self.attacker_gain or '?'}  "
                       f"protocol_loss={self.protocol_loss or '?'}  "
                       f"required_capital={self.required_capital or '?'}")
        if self.execution_proof:
            out.append(f"Execution proof\n  {self.execution_proof}")
        out.append(f"Git provenance     {self.git_provenance}")
        out.append(f"Bytecode provenance {self.bytecode_provenance or 'not established'}")
        out.append(f"Independent repro   {self.independent_reproduction or 'not attempted'}")
        if self.lines:
            out.append("\nStatements (FACT / INFERENCE / ASSUMPTION)")
            for ln in self.lines:
                out.append(f"  [{ln.cls:<10}] {ln.text}")
        if self.reasons:
            out.append("\nWhy this confidence")
            for r in self.reasons:
                out.append(f"  - {r}")
        return "\n".join(out)


def fact(text: str) -> Line:
    return Line(FACT, text)


def inference(text: str) -> Line:
    return Line(INFERENCE, text)


def assumption(text: str) -> Line:
    return Line(ASSUMPTION, text)
