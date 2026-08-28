"""The Reproducer (spec §8, "Agent C") - blinded independent reproduction.

Given ONLY the technical target and the proposed invariant - never the Hunter's
explanation - independently attempt to reproduce the behaviour. This is what
stops "Hunter hallucination -> Reproducer reads hallucination -> confirmation".

Phase 4 ships the blinded interface and a PENDING result. The real reproduction
runs against a local forked EVM in Phase 5 (`nextgen/execground/`), which is
wired here through an injected `runner`. With no runner, `attempt` returns
PENDING and the `reproducer` gate stays PENDING - never PASS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .. import state as S

PENDING = "PENDING"
REPRODUCED = "REPRODUCED"
NOT_REPRODUCED = "NOT_REPRODUCED"
ERROR = "ERROR"


@dataclass
class BlindTarget:
    """Everything the Reproducer is allowed to see. Deliberately minimal:
    no narrative, no severity, no attack write-up."""

    contract: str
    function: str
    invariant_statement: str
    objective: dict                       # the §3 SearchTarget.objective
    address: str = ""
    regression_commit: str = ""
    build_settings: dict = field(default_factory=dict)
    # optional shape hints for a generated reproducer (still not a write-up)
    signature: str = ""                   # e.g. "setOwner(address)"
    constructor_args: str = ""            # solidity literal list, e.g. ""
    call_args: str = ""                   # solidity literal args for the call
    pragma: str = "^0.8.0"

    def as_dict(self) -> dict:
        return {"contract": self.contract, "function": self.function,
                "invariant_statement": self.invariant_statement,
                "objective": self.objective, "address": self.address,
                "regression_commit": self.regression_commit,
                "build_settings": dict(self.build_settings),
                "signature": self.signature,
                "constructor_args": self.constructor_args,
                "call_args": self.call_args}


@dataclass
class ReproResult:
    status: str                           # PENDING / REPRODUCED / NOT_REPRODUCED / ERROR
    detail: str = ""
    artifacts: dict = field(default_factory=dict)

    @property
    def agrees(self) -> Optional[bool]:
        if self.status == REPRODUCED:
            return True
        if self.status == NOT_REPRODUCED:
            return False
        return None

    def as_dict(self) -> dict:
        return {"status": self.status, "detail": self.detail,
                "agrees": self.agrees, "artifacts": self.artifacts}


def attempt(target: BlindTarget, *,
            runner: Optional[Callable[[BlindTarget], ReproResult]] = None
            ) -> ReproResult:
    """Run the blinded reproduction. `runner` is the Phase 5 fork executor;
    absent, this is honestly PENDING."""
    if runner is None:
        return ReproResult(PENDING,
                           "no execution runner is wired (Foundry fork layer is "
                           "Phase 5); independent reproduction not attempted")
    try:
        res = runner(target)
        if not isinstance(res, ReproResult):
            return ReproResult(ERROR, f"runner returned {type(res).__name__}")
        return res
    except Exception as exc:  # noqa: BLE001
        return ReproResult(ERROR, f"{type(exc).__name__}: {exc}")
