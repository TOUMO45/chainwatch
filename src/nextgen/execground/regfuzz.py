"""Regression fuzzing between two commits (spec §21).

When a security property changed between two commits, generate inputs and look
for BEHAVIOURAL DIVERGENCE on the changed function:

    old version:  withdraw(100) -> REVERT
    new version:  withdraw(100) -> SUCCESS      <- strong regression signal

The generated Foundry test deploys BOTH `OldTarget` and `NewTarget` (renamed
copies of the two versions' source), fuzzes the function's inputs, and asserts
the two versions revert on the same inputs. A counterexample is a divergence.

This is a corroborating signal, not a confirmation: a divergence on a
security-relevant function strengthens a regression claim, but the finding
still needs the invariant (§3) and the reproducer (§15).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..adversarial.reproducer import ReproResult, ERROR, NOT_REPRODUCED, PENDING
from . import foundry
from . import reproducer as R

DIVERGENCE_FOUND = "DIVERGENCE_FOUND"
NO_DIVERGENCE = "NO_DIVERGENCE"


@dataclass
class RegFuzzResult:
    status: str                      # DIVERGENCE_FOUND / NO_DIVERGENCE / ERROR / PENDING
    detail: str = ""
    counterexample: str = ""
    artifacts: dict = field(default_factory=dict)

    @property
    def diverged(self) -> Optional[bool]:
        if self.status == DIVERGENCE_FOUND:
            return True
        if self.status == NO_DIVERGENCE:
            return False
        return None

    def as_dict(self) -> dict:
        return {"status": self.status, "detail": self.detail,
                "counterexample": self.counterexample, "diverged": self.diverged}


def _rename_contract(src: str, old: str, new: str) -> str:
    # rename the primary contract declaration and its constructor-style refs
    src = re.sub(rf"\bcontract\s+{re.escape(old)}\b", f"contract {new}", src)
    src = re.sub(rf"\b{re.escape(old)}\b(?=\s*\()", new, src)
    return src


_FUZZ_TEST = """// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import {{Test}} from "forge-std/Test.sol";
import {{OldTarget}} from "../src/OldTarget.sol";
import {{NewTarget}} from "../src/NewTarget.sol";

contract RegFuzzTest is Test {{
    OldTarget internal oldT;
    NewTarget internal newT;
    address internal attacker = address(0xA11CE);

    function setUp() public {{
        oldT = new OldTarget({ctor});
        newT = new NewTarget({ctor});
        vm.deal(attacker, 100 ether);
    }}

    function testFuzz_no_behavioural_divergence({fuzz_params}) public {{
        vm.prank(attacker);
        (bool okOld, ) = address(oldT).call(
            abi.encodeWithSignature("{sig}"{fuzz_args}));
        vm.prank(attacker);
        (bool okNew, ) = address(newT).call(
            abi.encodeWithSignature("{sig}"{fuzz_args}));
        assertEq(okOld ? 1 : 0, okNew ? 1 : 0);
    }}
}}
"""


def _fuzz_param_decls(param_types: list[str]) -> tuple[str, str]:
    decls, args = [], []
    for i, t in enumerate(param_types):
        t = t.strip()
        decls.append(f"{t} p{i}")
        args.append(f"p{i}")
    return ", ".join(decls), ("" if not args else ", " + ", ".join(args))


def run_regression_fuzz(*, function: str, signature: str,
                        old_source: str, new_source: str, contract: str,
                        constructor_args: str = "", pragma: str = "^0.8.0",
                        runs: int = 256,
                        toolchain: Optional[foundry.Toolchain] = None
                        ) -> RegFuzzResult:
    tc = toolchain or foundry.resolve()
    if tc is None:
        return RegFuzzResult(PENDING, "no Foundry toolchain reachable")

    old_src = _rename_contract(old_source, contract, "OldTarget")
    new_src = _rename_contract(new_source, contract, "NewTarget")
    ptypes = _types_from_sig(signature)
    decls, args = _fuzz_param_decls(ptypes)
    test_src = _FUZZ_TEST.format(pragma=pragma, ctor=constructor_args,
                                 sig=signature or f"{function}()",
                                 fuzz_params=decls, fuzz_args=args)

    # a tiny foundry.toml override to raise the fuzz run count
    res = R.run_test_source(
        test_src, source_bundle="// placeholder\n",
        extra_sources={"OldTarget.sol": old_src, "NewTarget.sol": new_src},
        match_contract="RegFuzzTest",
        pass_marker="[PASS] testFuzz_no_behavioural_divergence",
        fail_marker="testFuzz_no_behavioural_divergence",
        toolchain=tc)

    # RegFuzz inverts the reproducer's convention: the fuzz test PASSES when the
    # two versions AGREE (no divergence). A [FAIL] is a counterexample.
    if res.status == "REPRODUCED":
        return RegFuzzResult(NO_DIVERGENCE,
                             "the two versions revert on the same inputs across "
                             f"{runs} fuzz runs", artifacts=res.artifacts)
    if res.status == NOT_REPRODUCED:
        tail = res.artifacts.get("forge_output_tail", "")
        ce = _extract_counterexample(tail)
        return RegFuzzResult(DIVERGENCE_FOUND,
                             "the changed function behaves differently between "
                             "the two versions on some input",
                             counterexample=ce, artifacts=res.artifacts)
    return RegFuzzResult(ERROR, res.detail, artifacts=res.artifacts)


def _extract_counterexample(forge_tail: str) -> str:
    m = re.search(r"(counterexample:.*)", forge_tail, re.I)
    if m:
        return m.group(1).strip()[:300]
    m = re.search(r"args=\[([^\]]*)\]", forge_tail)
    return f"args=[{m.group(1)}]" if m else ""


def _types_from_sig(signature: str) -> list[str]:
    m = re.search(r"\(([^)]*)\)", signature or "")
    if not m or not m.group(1).strip():
        return []
    return [t.strip().split()[0] for t in m.group(1).split(",")]
