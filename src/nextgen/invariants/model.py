"""Pure data types for invariant discovery (spec §2) and the status discipline.

A `CandidateInvariant` moves through:

    INFERRED   discover.py proposed it from a structural pattern
       |
    TESTED     validate.py re-checked it against the code and it holds there
       |
    VALIDATED  TESTED and nothing contradicts it (no unguarded sibling, no
               counter-example the discoverer found)
       |
    USED       promoted to a security property - becomes a Time Machine probe
               and can feed the `security_invariant` gate

    REJECTED   at any point: the pattern did not survive re-check

Only VALIDATED (or USED) invariants are allowed to influence a verdict. An
INFERRED invariant is a lead - it may be mentioned in a report as a hypothesis,
never stated as a property that was violated (spec §22).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .. import timemachine as TM

# invariant classes - reuse the Time Machine's set so a promoted invariant maps
# straight onto a probe kind.
KINDS = TM.INVARIANT_KINDS
CODE = TM.CODE
PROTOCOL = TM.PROTOCOL
ACCESS_CONTROL = TM.ACCESS_CONTROL
ACCOUNTING = TM.ACCOUNTING
ECONOMIC = TM.ECONOMIC
STATE_MACHINE = TM.STATE_MACHINE
DEPLOYMENT = TM.DEPLOYMENT
CROSS_CONTRACT = TM.CROSS_CONTRACT

# status
INFERRED = "INFERRED"
TESTED = "TESTED"
VALIDATED = "VALIDATED"
USED = "USED"
REJECTED = "REJECTED"

_FORWARD = (INFERRED, TESTED, VALIDATED, USED)


class InvariantStatusError(RuntimeError):
    pass


# where an inference came from - the structural signal, never a guess
SOURCE_GUARD = "guard"                 # msg.sender-dependent require/modifier
SOURCE_ROLE = "role-check"             # onlyRole / hasRole / role-var compare
SOURCE_INIT = "init-guard"             # initializer / one-shot flag
SOURCE_UPGRADE = "upgrade-auth"        # _authorizeUpgrade / upgradeTo
SOURCE_ACCOUNTING = "accounting-shape" # mint/burn touch supply+balance together
SOURCE_SUPPLY = "supply-accounting"
SOURCE_SOLVENCY = "solvency-shape"
SOURCE_NONCE = "nonce-replay"
SOURCE_REQUIRE = "require-assert"
SOURCE_COMMENT = "natspec-spec"
SOURCE_EVENT = "event-correspondence"

# strength of the structural signal: how much the pattern alone tells us.
# Not a probability - a coarse ordering used only to rank and to decide which
# candidates are worth the cost of execution testing later.
STRONG = "strong"
MEDIUM = "medium"
WEAK = "weak"


@dataclass
class CandidateInvariant:
    id: str
    kind: str
    statement: str                     # human-readable, e.g. "only MINTER_ROLE may call mint()"
    source: str                        # one of the SOURCE_* constants
    strength: str = MEDIUM
    contract: str = ""
    functions: tuple[str, ...] = ()
    variables: tuple[str, ...] = ()
    # a small machine-checkable descriptor (structured), when the pattern has one
    predicate: Optional[dict] = None
    status: str = INFERRED
    notes: list[str] = field(default_factory=list)
    # set by validate.py: a concrete contradiction that blocked promotion
    contradiction: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"invariant kind {self.kind!r} not recognised")
        if self.status not in (*_FORWARD, REJECTED):
            raise ValueError(f"invariant status {self.status!r} not recognised")

    # -- status transitions ------------------------------------------------ #

    def advance(self, to: str, *, note: str = "") -> None:
        if self.status == REJECTED:
            raise InvariantStatusError(f"{self.id}: REJECTED is terminal")
        if to not in _FORWARD:
            raise InvariantStatusError(f"{to!r} is not a forward status")
        if _FORWARD.index(to) != _FORWARD.index(self.status) + 1:
            raise InvariantStatusError(
                f"{self.id}: {self.status} -> {to} is not the next step")
        self.status = to
        if note:
            self.notes.append(f"{to}: {note}")

    def reject(self, reason: str) -> None:
        self.status = REJECTED
        self.contradiction = reason
        self.notes.append(f"REJECTED: {reason}")

    @property
    def usable(self) -> bool:
        """May this invariant influence a verdict?"""
        return self.status in (VALIDATED, USED)

    @property
    def subject_key(self) -> tuple:
        """Identity for cross-version matching in regress.py - the thing the
        invariant is ABOUT, independent of how it is currently phrased."""
        return (self.kind, self.contract, tuple(sorted(self.functions)),
                tuple(sorted(self.variables)), self.source)

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "statement": self.statement,
                "source": self.source, "strength": self.strength,
                "contract": self.contract, "functions": list(self.functions),
                "variables": list(self.variables), "predicate": self.predicate,
                "status": self.status, "notes": list(self.notes),
                "contradiction": self.contradiction}


@dataclass
class InvariantSet:
    """The invariants discovered for one version of a codebase."""

    version_ref: str = ""              # a commit sha, or "HEAD", or a label
    invariants: list[CandidateInvariant] = field(default_factory=list)

    def add(self, inv: CandidateInvariant) -> None:
        self.invariants.append(inv)

    def usable(self) -> list[CandidateInvariant]:
        return [i for i in self.invariants if i.usable]

    def by_kind(self, kind: str) -> list[CandidateInvariant]:
        return [i for i in self.invariants if i.kind == kind]

    def index_by_subject(self) -> dict[tuple, CandidateInvariant]:
        out: dict[tuple, CandidateInvariant] = {}
        for i in self.invariants:
            out.setdefault(i.subject_key, i)
        return out

    def as_dict(self) -> dict:
        return {"version_ref": self.version_ref,
                "invariants": [i.as_dict() for i in self.invariants]}
