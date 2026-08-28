"""Benchmark data types + metrics (spec §20, §27)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .. import state as S

# expected outcomes a case can declare
EXP_CONFIRMED = "CONFIRMED"
EXP_REJECTED = "REJECTED"
EXP_UNKNOWN = "UNKNOWN"

# a case's ground-truth nature
POSITIVE = "positive"          # a real regression
HARD_NEGATIVE = "hard_negative"  # benign but suspicious-looking
NEGATIVE = "negative"          # plainly fine


@dataclass
class BenchmarkCase:
    id: str
    nature: str                      # POSITIVE / HARD_NEGATIVE / NEGATIVE
    expected: str                    # EXP_* - the verdict the pipeline SHOULD reach
    vuln_class: str = ""             # OWASP-ish tag
    invariant: str = ""
    reason: str = ""                 # why `expected` is right
    # inline synthetic sources for the offline suite
    before_source: str = ""
    after_source: str = ""
    contract: str = ""
    function: str = ""
    # optionally, the specific gate assertions a correct run must satisfy
    expect_gates: dict = field(default_factory=dict)
    # real-repo anchoring (used by the online suite, Phase 5/6)
    repo: str = ""
    parent: str = ""
    commit: str = ""
    address: str = ""
    patched_commit: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "nature": self.nature, "expected": self.expected,
                "vuln_class": self.vuln_class, "invariant": self.invariant,
                "reason": self.reason, "contract": self.contract,
                "function": self.function, "expect_gates": dict(self.expect_gates),
                "repo": self.repo, "commit": self.commit, "address": self.address}


@dataclass
class BenchmarkResult:
    case_id: str
    nature: str
    expected: str
    actual: str                      # the verdict the pipeline reached
    actual_state: str = ""           # the fine state (e.g. FALSE_POSITIVE)
    gate_mismatches: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def correct(self) -> bool:
        return not self.error and self.actual == self.expected \
            and not self.gate_mismatches

    def as_dict(self) -> dict:
        return {"case_id": self.case_id, "nature": self.nature,
                "expected": self.expected, "actual": self.actual,
                "actual_state": self.actual_state,
                "gate_mismatches": list(self.gate_mismatches),
                "error": self.error, "correct": self.correct}


@dataclass
class Metrics:
    total: int = 0
    correct: int = 0
    # confusion, defined on "did the pipeline CONFIRM":
    tp: int = 0     # positive case, pipeline CONFIRMED
    fp: int = 0     # negative/hard-negative case, pipeline CONFIRMED
    tn: int = 0     # negative/hard-negative case, pipeline did NOT confirm
    fn: int = 0     # positive case, pipeline did NOT confirm
    errors: int = 0

    @property
    def accuracy(self) -> float:
        return round(self.correct / self.total, 4) if self.total else 0.0

    @property
    def precision(self) -> Optional[float]:
        d = self.tp + self.fp
        return round(self.tp / d, 4) if d else None

    @property
    def recall(self) -> Optional[float]:
        d = self.tp + self.fn
        return round(self.tp / d, 4) if d else None

    @property
    def false_positive_rate(self) -> Optional[float]:
        d = self.fp + self.tn
        return round(self.fp / d, 4) if d else None

    @property
    def false_negative_rate(self) -> Optional[float]:
        d = self.fn + self.tp
        return round(self.fn / d, 4) if d else None

    @property
    def confirmed_over_false_positive(self) -> Optional[float]:
        """The §27 ratio. None when there are no false positives (the good
        case) - reported as 'inf-safe' by the renderer."""
        return round(self.tp / self.fp, 4) if self.fp else None

    def as_dict(self) -> dict:
        return {"total": self.total, "correct": self.correct,
                "accuracy": self.accuracy,
                "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "errors": self.errors,
                "precision": self.precision, "recall": self.recall,
                "false_positive_rate": self.false_positive_rate,
                "false_negative_rate": self.false_negative_rate,
                "confirmed_over_false_positive": self.confirmed_over_false_positive}

    def render_text(self) -> str:
        cofp = self.confirmed_over_false_positive
        cofp_s = "no false positives" if self.fp == 0 else f"{cofp}"
        return "\n".join([
            "CHAINWATCH NEXT-GEN BENCHMARK", "=" * 29, "",
            f"  cases            : {self.total}",
            f"  correct          : {self.correct}  (accuracy {self.accuracy})",
            f"  confusion (did it CONFIRM?): TP={self.tp} FP={self.fp} "
            f"TN={self.tn} FN={self.fn}  errors={self.errors}",
            f"  precision        : {self.precision}",
            f"  recall           : {self.recall}",
            f"  false-positive   : {self.false_positive_rate}",
            f"  false-negative   : {self.false_negative_rate}",
            f"  CONFIRMED / FP   : {cofp_s}    (spec §27)",
        ])


def tally(results: list[BenchmarkResult]) -> Metrics:
    m = Metrics(total=len(results))
    for r in results:
        if r.error:
            m.errors += 1
        if r.correct:
            m.correct += 1
        confirmed = r.actual == EXP_CONFIRMED
        is_positive = r.nature == POSITIVE
        if is_positive and confirmed:
            m.tp += 1
        elif is_positive and not confirmed:
            m.fn += 1
        elif not is_positive and confirmed:
            m.fp += 1
        else:
            m.tn += 1
    return m
