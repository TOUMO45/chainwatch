"""Stateful multi-transaction reasoning (spec §5).

Many serious DeFi bugs need a sequence, not one call:

    deposit() -> manipulate price -> borrow() -> update oracle -> liquidate()

This module builds candidate transaction sequences (from the attack-path graph
and a few structural heuristics), runs each as a generated Foundry test, and
MINIMISES a working one to the smallest sub-sequence that still reproduces the
violation (delta-debugging).

Output shape (spec §5):

    Minimal attack sequence:
      1. attacker.deposit(100 ether)
      2. attacker.trigger(...)
      3. attacker.withdraw(...)
    Expected invariant : ...
    Observed violation : ...

Local fork only, no broadcast, throwaway project - same charter carve-out as
`reproducer.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..adversarial.reproducer import (ReproResult, NOT_REPRODUCED, PENDING,
                                      REPRODUCED)
from . import foundry
from . import reproducer as R

_CALLER_ADDR = {
    "attacker": "address(0xA11CE)",
    "victim": "address(0xB0B)",
    "deployer": "address(this)",
}

_SETUP_HINTS = ("deposit", "approve", "mint", "stake", "addliquidity", "supply")


@dataclass
class TxStep:
    contract: str
    function: str
    signature: str = ""
    caller: str = "attacker"          # attacker | victim | deployer
    args: str = ""                    # solidity literal list
    value_wei: int = 0
    must_succeed: bool = False        # a setup step that must not revert

    def sig(self) -> str:
        return self.signature or f"{self.function}()"

    def render(self, idx: int, is_objective: bool) -> str:
        caller = _CALLER_ADDR.get(self.caller, _CALLER_ADDR["attacker"])
        enc = f'abi.encodeWithSignature("{self.sig()}"' + (
            f", {self.args}" if self.args.strip() else "") + ")"
        val = f"{{value: {self.value_wei}}}" if self.value_wei else ""
        lines = []
        if self.caller != "deployer":
            lines.append(f"        vm.prank({caller});")
        lines.append(f"        (bool ok{idx}, ) = address(target).call{val}({enc});")
        if is_objective:
            lines.append(f'        assertTrue(ok{idx}, "objective call reverted '
                         f'- invariant still holds");')
        elif self.must_succeed:
            lines.append(f'        require(ok{idx}, "setup step {idx} failed");')
        return "\n".join(lines)

    def as_text(self) -> str:
        v = f" {{value: {self.value_wei}}}" if self.value_wei else ""
        return f"{self.caller}.{self.function}({self.args}){v}"


@dataclass
class CandidateSequence:
    steps: list[TxStep]
    objective: dict = field(default_factory=dict)
    invariant_statement: str = ""

    def __len__(self) -> int:
        return len(self.steps)

    def render_test(self, contract: str, *, constructor_args: str = "",
                    pragma: str = "^0.8.0", deployer_funds_wei: int = 0) -> str:
        head = (f"// SPDX-License-Identifier: MIT\npragma solidity {pragma};\n\n"
                f'import {{Test}} from "forge-std/Test.sol";\n'
                f'import {{{contract}}} from "../src/Target.sol";\n\n'
                f"contract ReproTest is Test {{\n"
                f"    {contract} internal target;\n\n"
                f"    function setUp() public {{\n"
                f"        target = new {contract}({constructor_args});\n")
        if deployer_funds_wei:
            head += f"        vm.deal(address(this), {deployer_funds_wei});\n"
        for c in ("attacker", "victim"):
            head += f"        vm.deal({_CALLER_ADDR[c]}, 100 ether);\n"
        head += "    }\n\n    function test_invariant_is_violated() public {\n"
        body = "\n".join(
            s.render(i, is_objective=(i == len(self.steps) - 1))
            for i, s in enumerate(self.steps))
        return head + body + "\n    }\n}\n"

    def as_report(self) -> str:
        lines = ["Minimal attack sequence:"]
        for i, s in enumerate(self.steps, 1):
            lines.append(f"  {i}. {s.as_text()}")
        if self.invariant_statement:
            lines.append(f"Expected invariant : {self.invariant_statement}")
        lines.append(f"Observed violation : the objective call succeeds where "
                     f"the invariant requires it to revert")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {"steps": [s.__dict__ for s in self.steps],
                "objective": self.objective,
                "invariant_statement": self.invariant_statement}


def run_sequence(seq: CandidateSequence, *, source_bundle: str, contract: str,
                 constructor_args: str = "", pragma: str = "^0.8.0",
                 toolchain: Optional[foundry.Toolchain] = None) -> ReproResult:
    if not seq.steps:
        return ReproResult(NOT_REPRODUCED, "empty sequence")
    test_src = seq.render_test(contract, constructor_args=constructor_args,
                               pragma=pragma)
    return R.run_test_source(test_src, source_bundle=source_bundle,
                             toolchain=toolchain)


def minimize(seq: CandidateSequence,
             verify: Callable[[CandidateSequence], bool]) -> CandidateSequence:
    """Delta-debug to the smallest sub-sequence `verify` still accepts. The
    LAST step (the objective) is never dropped. `verify(subseq)` returns True
    iff that sub-sequence still reproduces."""
    steps = list(seq.steps)
    changed = True
    while changed and len(steps) > 1:
        changed = False
        for i in range(len(steps) - 2, -1, -1):   # never index len-1 (objective)
            trial = CandidateSequence(steps[:i] + steps[i + 1:], seq.objective,
                                      seq.invariant_statement)
            if verify(trial):
                steps = trial.steps
                changed = True
                break
    return CandidateSequence(steps, seq.objective, seq.invariant_statement)


def enumerate_sequences(*, contract: str, function: str, signature: str = "",
                        call_args: str = "", objective: Optional[dict] = None,
                        invariant_statement: str = "",
                        setup_functions: Optional[list[tuple[str, str, str]]] = None,
                        max_len: int = 3) -> list[CandidateSequence]:
    """Candidate sequences, shortest first:

      * [objective]                              - the bare call
      * [setup_i, objective] for each setup fn   - one prefixed setup call
      * [setup_i, setup_j, objective]            - two setup calls (<= max_len)

    `setup_functions` is [(name, signature, args)]; when omitted, only the bare
    call is produced. The attack-path graph supplies these in the orchestrator.
    """
    objective = objective or {"type": "call_succeeds", "contract": contract,
                              "function": function}
    obj_step = TxStep(contract, function, signature, "attacker", call_args)

    out: list[CandidateSequence] = [
        CandidateSequence([obj_step], objective, invariant_statement)]

    setups = setup_functions or []
    for name, sig, args in setups:
        out.append(CandidateSequence(
            [TxStep(contract, name, sig, "attacker", args, must_succeed=True),
             obj_step], objective, invariant_statement))

    if max_len >= 3:
        for i in range(len(setups)):
            for j in range(len(setups)):
                if i == j:
                    continue
                a, b = setups[i], setups[j]
                out.append(CandidateSequence(
                    [TxStep(contract, a[0], a[1], "attacker", a[2], must_succeed=True),
                     TxStep(contract, b[0], b[1], "attacker", b[2], must_succeed=True),
                     obj_step], objective, invariant_statement))

    return [s for s in out if len(s) <= max_len]


def search(*, source_bundle: str, contract: str, function: str,
           signature: str = "", call_args: str = "", constructor_args: str = "",
           invariant_statement: str = "", objective: Optional[dict] = None,
           setup_functions: Optional[list[tuple[str, str, str]]] = None,
           pragma: str = "^0.8.0", max_len: int = 3,
           toolchain: Optional[foundry.Toolchain] = None
           ) -> tuple[Optional[CandidateSequence], ReproResult]:
    """Try candidate sequences shortest-first; on the first REPRODUCED, minimise
    it. Returns (minimal_sequence_or_None, last_result)."""
    tc = toolchain or foundry.resolve()
    if tc is None:
        return None, ReproResult(PENDING, "no Foundry toolchain reachable")

    candidates = enumerate_sequences(
        contract=contract, function=function, signature=signature,
        call_args=call_args, objective=objective,
        invariant_statement=invariant_statement,
        setup_functions=setup_functions, max_len=max_len)

    last = ReproResult(NOT_REPRODUCED, "no candidate sequence reproduced")
    for cand in sorted(candidates, key=len):
        res = run_sequence(cand, source_bundle=source_bundle, contract=contract,
                           constructor_args=constructor_args, pragma=pragma,
                           toolchain=tc)
        last = res
        if res.status == REPRODUCED:
            def _verify(s: CandidateSequence) -> bool:
                return run_sequence(s, source_bundle=source_bundle,
                                    contract=contract,
                                    constructor_args=constructor_args,
                                    pragma=pragma, toolchain=tc
                                    ).status == REPRODUCED
            minimal = minimize(cand, _verify)
            final = run_sequence(minimal, source_bundle=source_bundle,
                                 contract=contract,
                                 constructor_args=constructor_args,
                                 pragma=pragma, toolchain=tc)
            return minimal, final
    return None, last
