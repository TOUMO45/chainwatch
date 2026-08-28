"""The finding state machine (spec §17) and the gate model that drives it.

The classic pipeline has three verdicts (`src/verdict.py`: DISCARDED /
CANDIDATE / CONFIRMED). That is deliberately coarse and it stays. The next-gen
pipeline needs a finer, auditable progression - every candidate carries an
explicit state, and the path it took to that state is recorded, so a reviewer
can see *where* a claim stopped being provable rather than only that it did.

    DISCOVERED
        -> HYPOTHESIS
        -> STATICALLY_SUPPORTED
        -> REACHABILITY_TESTED
        -> INVARIANT_TESTED
        -> REPRODUCED
        -> INDEPENDENTLY_VALIDATED
        -> DEPLOYMENT_VERIFIED
        -> DEDUPLICATED
        -> CONFIRMED

Rejection is a first-class outcome and there are many kinds of it, because
"why this is not a finding" is as much a product as "why it is":

    FALSE_POSITIVE  UNREACHABLE  PATCHED  DEPLOYMENT_MISMATCH
    ECONOMICALLY_INFEASIBLE  DUPLICATE  OUT_OF_SCOPE  INSUFFICIENT_EVIDENCE

And `UNKNOWN` (spec §24) is neither CONFIRMED nor a rejection: the evidence is
incomplete and nothing has *disproved* the candidate. A professional system is
allowed to say "we do not know" instead of manufacturing certainty.

HOW THE STATE IS DECIDED
------------------------
Not by narration and not by an LLM. `classify(gates)` is mechanical:

  * any gate FAIL                      -> REJECTED, with that gate's rejection state
  * else any gate UNKNOWN / PENDING    -> UNKNOWN, listing the unresolved gates
  * else (every blocking gate PASS)    -> CONFIRMED

A gate that is legitimately not applicable is SKIPPED. SKIPPED never counts as
PASS for a blocking gate unless the gate's spec says so (`na_is_pass`), so the
default effect of "could not check this" is UNKNOWN - never CONFIRMED. This is
the same discipline as the classic charter's decisive gate: a repo-only scan
with no address cannot reach CONFIRMED, it reaches UNKNOWN.

The score in `proofscore.py` is advisory. It cannot move a finding out of
REJECTED or UNKNOWN. This module owns the verdict; the score only describes it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------- #
# Forward pipeline states, in order. Index in this tuple == progress.
# --------------------------------------------------------------------------- #

DISCOVERED = "DISCOVERED"
HYPOTHESIS = "HYPOTHESIS"
STATICALLY_SUPPORTED = "STATICALLY_SUPPORTED"
REACHABILITY_TESTED = "REACHABILITY_TESTED"
INVARIANT_TESTED = "INVARIANT_TESTED"
REPRODUCED = "REPRODUCED"
INDEPENDENTLY_VALIDATED = "INDEPENDENTLY_VALIDATED"
DEPLOYMENT_VERIFIED = "DEPLOYMENT_VERIFIED"
DEDUPLICATED = "DEDUPLICATED"
CONFIRMED = "CONFIRMED"

PIPELINE: tuple[str, ...] = (
    DISCOVERED,
    HYPOTHESIS,
    STATICALLY_SUPPORTED,
    REACHABILITY_TESTED,
    INVARIANT_TESTED,
    REPRODUCED,
    INDEPENDENTLY_VALIDATED,
    DEPLOYMENT_VERIFIED,
    DEDUPLICATED,
    CONFIRMED,
)

# --------------------------------------------------------------------------- #
# Rejection states (spec §17) and the extra outcome UNKNOWN (spec §24).
# --------------------------------------------------------------------------- #

FALSE_POSITIVE = "FALSE_POSITIVE"
UNREACHABLE = "UNREACHABLE"
PATCHED = "PATCHED"
DEPLOYMENT_MISMATCH = "DEPLOYMENT_MISMATCH"
ECONOMICALLY_INFEASIBLE = "ECONOMICALLY_INFEASIBLE"
DUPLICATE = "DUPLICATE"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

REJECTIONS: frozenset[str] = frozenset({
    FALSE_POSITIVE,
    UNREACHABLE,
    PATCHED,
    DEPLOYMENT_MISMATCH,
    ECONOMICALLY_INFEASIBLE,
    DUPLICATE,
    OUT_OF_SCOPE,
    INSUFFICIENT_EVIDENCE,
})

UNKNOWN = "UNKNOWN"

TERMINAL: frozenset[str] = REJECTIONS | {CONFIRMED, UNKNOWN}

# The coarse verdict a consumer that does not care about the fine state wants.
VERDICT_CONFIRMED = "CONFIRMED"
VERDICT_REJECTED = "REJECTED"
VERDICT_UNKNOWN = "UNKNOWN"
VERDICT_IN_PROGRESS = "IN_PROGRESS"


# --------------------------------------------------------------------------- #
# Gate results.
# --------------------------------------------------------------------------- #

PASS = "PASS"
FAIL = "FAIL"
GATE_UNKNOWN = "UNKNOWN"     # checked, could not decide
SKIPPED = "SKIPPED"          # not applicable / not attempted
PENDING = "PENDING"          # a later phase will fill this

_GATE_RESULTS = frozenset({PASS, FAIL, GATE_UNKNOWN, SKIPPED, PENDING})


@dataclass(frozen=True)
class GateSpec:
    """One link in the evidence chain (NEXTGEN.md).

    `blocks_confirm`  a FAIL or an unresolved value keeps the finding out of
                      CONFIRMED. Every gate here blocks; the field exists so a
                      later phase can add a purely informational gate.
    `on_fail`         the rejection state a FAIL maps to.
    `na_is_pass`      a SKIPPED value is treated as PASS for this gate. Only for
                      gates that are genuinely optional for a whole finding
                      class (e.g. economic feasibility on a non-value finding).
    `sections`        the spec sections this gate implements, for traceability.
    """

    name: str
    sections: tuple[str, ...]
    on_fail: str
    blocks_confirm: bool = True
    na_is_pass: bool = False


# The chain from NEXTGEN.md, in evidence order. Later phases POPULATE these;
# Phase 0 only defines them and the machine that reads them.
GATES: tuple[GateSpec, ...] = (
    GateSpec("regression_commit", ("1", "9"), INSUFFICIENT_EVIDENCE),
    GateSpec("build_environment", ("19",), INSUFFICIENT_EVIDENCE),
    GateSpec("security_invariant", ("2", "3"), INSUFFICIENT_EVIDENCE),
    GateSpec("reachable_path", ("4", "5"), UNREACHABLE),
    GateSpec("state_reachable", ("5",), UNREACHABLE),
    GateSpec("no_compensating_control", ("11",), FALSE_POSITIVE),
    GateSpec("invariant_violated", ("3", "6"), FALSE_POSITIVE),
    GateSpec("reproducer", ("15",), INSUFFICIENT_EVIDENCE),
    GateSpec("bytecode_provenance", ("9",), DEPLOYMENT_MISMATCH),
    GateSpec("target_live", ("10",), PATCHED),
    GateSpec("independent_validation", ("7", "8"), FALSE_POSITIVE),
    GateSpec("not_duplicate", ("20",), DUPLICATE),
    GateSpec("economically_feasible", ("14",), ECONOMICALLY_INFEASIBLE,
             na_is_pass=True),
)

GATE_BY_NAME: dict[str, GateSpec] = {g.name: g for g in GATES}

# The state a finding has "reached" once a given gate is PASS. Used only to
# derive a human-facing pipeline position; the verdict never depends on it.
_GATE_STATE_ORDER: dict[str, str] = {
    "regression_commit": STATICALLY_SUPPORTED,
    "build_environment": STATICALLY_SUPPORTED,
    "security_invariant": STATICALLY_SUPPORTED,
    "reachable_path": REACHABILITY_TESTED,
    "state_reachable": REACHABILITY_TESTED,
    "no_compensating_control": INVARIANT_TESTED,
    "invariant_violated": INVARIANT_TESTED,
    "reproducer": REPRODUCED,
    "independent_validation": INDEPENDENTLY_VALIDATED,
    "bytecode_provenance": DEPLOYMENT_VERIFIED,
    "target_live": DEPLOYMENT_VERIFIED,
    "not_duplicate": DEDUPLICATED,
    "economically_feasible": INVARIANT_TESTED,
}

# --------------------------------------------------------------------------- #
# Hard gates from spec §16 - restated here as the machine's own invariants so
# a reader of THIS module sees them without cross-referencing the score.
# --------------------------------------------------------------------------- #

HARD_GATES_DOC = (
    "no reproducer -> NOT CONFIRMED; "
    "no reachable attack path -> NOT CONFIRMED; "
    "deployment mismatch -> NOT LIVE; "
    "compensating control exists -> REJECT; "
    "independent validation failure -> NOT CONFIRMED"
)


class IllegalTransition(RuntimeError):
    """Raised on an attempt to move backward, skip forward, or leave a terminal
    state. The state machine is append-only and monotone by construction."""


@dataclass
class Transition:
    frm: str
    to: str
    at: float
    note: str = ""
    evidence_ref: Optional[str] = None   # a node id in the evidence graph

    def as_dict(self) -> dict:
        return {"from": self.frm, "to": self.to, "at": self.at,
                "note": self.note, "evidence_ref": self.evidence_ref}


@dataclass
class FindingState:
    """The live state of one next-gen candidate.

    `gates` holds the current result for each gate name (default PENDING).
    `state` is the fine pipeline position; `history` is every transition, in
    order, each optionally tied to an evidence-graph node.
    """

    finding_id: str
    state: str = DISCOVERED
    gates: dict[str, str] = field(default_factory=dict)
    history: list[Transition] = field(default_factory=list)
    rejection_reason: str = ""

    def __post_init__(self) -> None:
        for g in GATES:
            self.gates.setdefault(g.name, PENDING)
        if not self.history:
            self.history.append(Transition("", self.state, time.time(),
                                           note="created"))

    # -- transitions ----------------------------------------------------- #

    def advance(self, to: str, *, note: str = "",
                evidence_ref: Optional[str] = None) -> None:
        """Move forward one or more pipeline steps. Never backward, never past
        the end, never out of a terminal state."""
        if self.state in TERMINAL:
            raise IllegalTransition(
                f"{self.finding_id}: already terminal ({self.state})")
        if to not in PIPELINE:
            raise IllegalTransition(f"{to!r} is not a pipeline state")
        if PIPELINE.index(to) <= PIPELINE.index(self.state):
            raise IllegalTransition(
                f"{self.finding_id}: {self.state} -> {to} is not forward")
        self._commit(to, note, evidence_ref)

    def reject(self, reason: str, *, note: str = "",
               evidence_ref: Optional[str] = None) -> None:
        if reason not in REJECTIONS:
            raise IllegalTransition(f"{reason!r} is not a rejection state")
        if self.state in TERMINAL:
            raise IllegalTransition(
                f"{self.finding_id}: already terminal ({self.state})")
        self.rejection_reason = note or reason
        self._commit(reason, note, evidence_ref)

    def to_unknown(self, *, note: str = "",
                   evidence_ref: Optional[str] = None) -> None:
        if self.state in TERMINAL:
            raise IllegalTransition(
                f"{self.finding_id}: already terminal ({self.state})")
        self._commit(UNKNOWN, note, evidence_ref)

    def _commit(self, to: str, note: str, evidence_ref: Optional[str]) -> None:
        self.history.append(
            Transition(self.state, to, time.time(), note, evidence_ref))
        self.state = to

    # -- gates --------------------------------------------------------------- #

    def set_gate(self, name: str, result: str, *, note: str = "",
                 evidence_ref: Optional[str] = None) -> None:
        if name not in GATE_BY_NAME:
            raise KeyError(f"unknown gate {name!r}")
        if result not in _GATE_RESULTS:
            raise ValueError(f"{result!r} is not a gate result")
        self.gates[name] = result
        self.history.append(
            Transition(self.state, self.state, time.time(),
                       note=f"gate {name}={result}" + (f": {note}" if note else ""),
                       evidence_ref=evidence_ref))

    # -- derived views ----------------------------------------------------- #

    def verdict(self) -> str:
        """The coarse verdict. Mechanical; see `classify`."""
        return classify(self.gates)[1]

    def as_dict(self) -> dict:
        state, verdict, reasons = classify(self.gates)
        return {
            "finding_id": self.finding_id,
            "state": self.state,
            "derived_state": state,
            "verdict": verdict,
            "reasons": reasons,
            "rejection_reason": self.rejection_reason,
            "gates": dict(self.gates),
            "history": [t.as_dict() for t in self.history],
        }


def _gate_effective(spec: GateSpec, result: str) -> str:
    """Fold SKIPPED into PASS or UNKNOWN per the gate's own rule."""
    if result == SKIPPED:
        return PASS if spec.na_is_pass else GATE_UNKNOWN
    return result


def classify(gates: dict[str, str]) -> tuple[str, str, list[str]]:
    """The one decision this module makes.

    Returns `(fine_state, coarse_verdict, reasons)` where

        fine_state      one of PIPELINE / REJECTIONS / UNKNOWN
        coarse_verdict  VERDICT_CONFIRMED / VERDICT_REJECTED / VERDICT_UNKNOWN
        reasons         plain-language, one per unresolved-or-failed gate

    Rules, in order:
      1. any blocking gate FAIL  -> REJECTED at that gate's `on_fail` state.
         The FIRST such gate in evidence order names the state; all failures
         are listed in `reasons`.
      2. else any blocking gate not PASS (UNKNOWN / PENDING, or SKIPPED where
         `na_is_pass` is false) -> UNKNOWN, listing every unresolved gate.
      3. else -> CONFIRMED.
    """
    reasons: list[str] = []
    failed: list[GateSpec] = []
    unresolved: list[str] = []

    for spec in GATES:
        raw = gates.get(spec.name, PENDING)
        eff = _gate_effective(spec, raw)
        if eff == FAIL:
            failed.append(spec)
            reasons.append(
                f"gate {spec.name} FAILED (spec §{', §'.join(spec.sections)}) "
                f"-> {spec.on_fail}")
        elif eff != PASS and spec.blocks_confirm:
            unresolved.append(spec.name)
            reasons.append(
                f"gate {spec.name} is {raw} - not established "
                f"(spec §{', §'.join(spec.sections)})")

    if failed:
        return failed[0].on_fail, VERDICT_REJECTED, reasons
    if unresolved:
        return UNKNOWN, VERDICT_UNKNOWN, reasons
    return CONFIRMED, VERDICT_CONFIRMED, ["every evidence gate passed"]


def derive_pipeline_state(gates: dict[str, str]) -> str:
    """The furthest pipeline position justified by the PASSED gates.

    Advisory only - a display aid. `classify` is what decides a verdict.
    """
    reached = DISCOVERED
    for spec in GATES:
        if _gate_effective(spec, gates.get(spec.name, PENDING)) == PASS:
            st = _GATE_STATE_ORDER.get(spec.name, DISCOVERED)
            if PIPELINE.index(st) > PIPELINE.index(reached):
                reached = st
    _, verdict, _ = classify(gates)
    if verdict == VERDICT_CONFIRMED:
        return CONFIRMED
    return reached
