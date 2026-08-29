"""Phase 9 - the blinded deep-hunt reproducer (spec sections 16, 17).

Given ONLY the technical target (contract / function / invariant statement /
objective) plus the minimised `CandidateSequence` - never a hunter narrative -
independently try to reproduce the violation on a local fork / throwaway Foundry
project, and re-check for the SAME violation kind.

Objective coverage:
  * call_succeeds / reinit          -> reuse execground/reproducer's generators
                                       (already end-to-end)
  * conservation_violated /
    entitlement_exceeded             -> a generated test that funds the target,
                                       runs the sequence as an unprivileged
                                       attacker, and asserts the protocol LOST
                                       value while the attacker netted MORE than
                                       they paid in (a concrete, deterministic
                                       signal - not "the call succeeded")
  * oracle_manipulated_transition /
    transfer_side_effect / ltv /
    supply_mismatch / replay        -> honest PENDING with the reason it needs a
                                       forked ecosystem (a real AMM pair, a
                                       backing token, ...). UNKNOWN, never a
                                       guessed CONFIRMED (spec section 33).

`minimize` (delta-debug from execground/sequences) runs before the final
attempt. `make_runner` wires this into `adversarial.reproducer.attempt` so the
Skeptic path stays blinded.
"""

from __future__ import annotations

from typing import Callable, Optional

from ..adversarial.reproducer import (BlindTarget, ReproResult, NOT_REPRODUCED,
                                      PENDING, REPRODUCED)
from ..execground import foundry
from ..execground import reproducer as R
from ..execground.sequences import CandidateSequence, TxStep, minimize
from . import invariants as INV

# recipe types this phase can drive concretely, source-only
_VALUE_RECIPES = frozenset({INV.OBJ_CONSERVATION, INV.OBJ_ENTITLEMENT})
_REUSE_RECIPES = frozenset({INV.OBJ_CALL_SUCCEEDS, INV.OBJ_REINIT})
_FORK_ONLY = {
    INV.OBJ_ORACLE: "needs a forked AMM pair to manipulate the spot price",
    INV.OBJ_PURITY: "needs the real external pair to observe the side effect",
    INV.OBJ_LTV: "needs a forked oracle / collateral market",
    INV.OBJ_SUPPLY: "needs the real backing asset to compare against supply",
    INV.OBJ_REPLAY: "needs a signed authorization / historical request to replay",
    INV.OBJ_STATE_RELATION: "needs a concrete relation oracle to check the state",
    INV.OBJ_UNAUTH_UPGRADE: "needs the proxy + implementation wiring",
}

_SEED_WEI = 100 * 10 ** 18   # fund the target with 100 ETH for a drain test


def _value_extraction_test(t: BlindTarget, seq: CandidateSequence,
                           paid_in_wei: int) -> str:
    steps = "\n".join(_render_step(s, i, len(seq.steps))
                      for i, s in enumerate(seq.steps))
    return f"""// SPDX-License-Identifier: MIT
pragma solidity {t.pragma};

import {{Test}} from "forge-std/Test.sol";
import {{{t.contract}}} from "../src/Target.sol";

contract ReproTest is Test {{
    {t.contract} internal target;
    address internal attacker = address(0xA11CE);
    address internal victim = address(0xB0B);

    function setUp() public {{
        target = new {t.contract}({t.constructor_args});
        vm.deal(address(target), {_SEED_WEI});
        vm.deal(attacker, 200 ether);
        vm.deal(victim, 200 ether);
    }}

    function test_invariant_is_violated() public {{
        uint256 pBefore = address(target).balance;
        uint256 aBefore = attacker.balance;
{steps}
        uint256 pAfter = address(target).balance;
        uint256 aAfter = attacker.balance;
        // conservation / entitlement is VIOLATED exactly when the protocol lost
        // value AND the attacker netted more ETH than they paid in.
        assertTrue(pAfter < pBefore, "protocol did not lose value - invariant holds");
        assertTrue(int256(aAfter) - int256(aBefore) > int256(uint256({paid_in_wei})),
                   "attacker did not net more than they paid in - legitimate");
    }}
}}
"""


def _render_step(s: TxStep, idx: int, total: int) -> str:
    is_obj = idx == total - 1
    caller = {"attacker": "attacker", "victim": "victim",
              "deployer": "address(this)"}.get(s.caller, "attacker")
    enc = (f'abi.encodeWithSignature("{s.sig()}"'
           + (f", {s.args}" if s.args.strip() else "") + ")")
    val = f"{{value: {s.value_wei}}}" if s.value_wei else ""
    lines = []
    if s.caller != "deployer":
        lines.append(f"        vm.prank({caller});")
    lines.append(f"        (bool ok{idx}, ) = address(target).call{val}({enc});")
    if is_obj:
        lines.append(f'        assertTrue(ok{idx}, "objective call reverted - '
                     f'invariant still holds");')
    elif s.must_succeed:
        lines.append(f'        require(ok{idx}, "setup step {idx} failed - '
                     f'precondition unreachable");')
    return "\n".join(lines)


def reproduce(target: BlindTarget, sequence: CandidateSequence, *,
              source_bundle: str, toolchain=None,
              fork_url: Optional[str] = None, fork_block: Optional[int] = None,
              do_minimize: bool = True) -> tuple[Optional[CandidateSequence],
                                                 ReproResult]:
    """Returns (minimal_sequence_or_None, result)."""
    tc = toolchain or foundry.resolve()
    if tc is None:
        return None, ReproResult(PENDING, "no Foundry toolchain reachable "
                                          "(native or WSL); not attempted")

    otype = (target.objective or {}).get("type", "")
    if otype in _FORK_ONLY and not fork_url:
        return None, ReproResult(
            PENDING, f"objective {otype!r}: {_FORK_ONLY[otype]} - source-only "
                     f"reproduction not possible; UNKNOWN, not CONFIRMED")

    floor = R._solc_floor(target.pragma, source_bundle)
    if floor is not None and floor < R._MIN_FORGE_SOLC:
        return None, ReproResult(
            PENDING, f"pragma resolves to solc {'.'.join(map(str, floor))}; a "
                     f"Foundry reproducer needs >= 0.6.2")

    if otype in _REUSE_RECIPES:
        res = R.generate_and_run(target, source_bundle=source_bundle,
                                 toolchain=tc, fork_url=fork_url,
                                 fork_block=fork_block)
        return (sequence if res.status == REPRODUCED else None), res

    if otype in _VALUE_RECIPES:
        paid = sum(s.value_wei for s in sequence.steps
                   if s.caller == "attacker" and s is not sequence.steps[-1])
        paid += sequence.steps[-1].value_wei if sequence.steps else 0

        def _run(seq: CandidateSequence) -> ReproResult:
            src = _value_extraction_test(target, seq, paid)
            return R.run_test_source(src, source_bundle=source_bundle,
                                     toolchain=tc)

        first = _run(sequence)
        if first.status != REPRODUCED:
            return None, first
        minimal = minimize(sequence, lambda s: _run(s).status == REPRODUCED) \
            if do_minimize else sequence
        return minimal, _run(minimal)

    return None, ReproResult(
        PENDING, f"objective {otype!r} has no deep-hunt reproducer generator yet")


def make_runner(sequence: CandidateSequence, *, source_bundle: str,
                **kw) -> Callable[[BlindTarget], ReproResult]:
    """A blinded `runner` for `adversarial.reproducer.attempt`. It re-derives
    the reproduction from `sequence` + `source_bundle` only - never a write-up."""
    def _runner(target: BlindTarget) -> ReproResult:
        _minimal, res = reproduce(target, sequence, source_bundle=source_bundle,
                                  **kw)
        return res
    return _runner
