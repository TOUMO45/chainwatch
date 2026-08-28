"""Automatic minimal PoC generation (spec §15) - local fork only.

Given a blinded target (contract / function / invariant / §3 objective) and a
self-contained Solidity source bundle, generate a MINIMAL Foundry test that:

  1. deploys the vulnerable contract (optionally on a fork at a fixed block)
  2. creates a realistic unprivileged-attacker context
  3. runs the smallest transaction sequence toward the objective
  4. asserts the security invariant is violated

and runs it. A PASS of the generated `test_invariant_is_violated` means the
violation was demonstrated -> REPRODUCED. A revert / FAIL -> NOT_REPRODUCED.

Charter carve-out: the generated test lives in a throwaway `/tmp` project, is
never a reusable attack contract, and is deleted after the run (its source is
kept only as an evidence artifact string). No transaction is broadcast.

Phase 5a handles the `call_succeeds` and `reinit` objectives end to end;
`unauthorized_upgrade` and `state_relation_violated` need proxy wiring / a
parsed relation and return NOT_REPRODUCED / PENDING with a clear reason
(Phase 5b).
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from ..adversarial.reproducer import (BlindTarget, ReproResult, ERROR,
                                      NOT_REPRODUCED, PENDING, REPRODUCED)
from . import foundry

_FOUNDRY_TOML = """[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]
remappings = ["forge-std/=lib/forge-std/src/"]
"""

_TEST_HEADER = """// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import {{Test}} from "forge-std/Test.sol";
import {{{contract}}} from "../src/Target.sol";

contract ReproTest is Test {{
"""


def _sig_no_args(signature: str) -> bool:
    m = re.search(r"\(([^)]*)\)", signature or "")
    return not (m and m.group(1).strip())


def _call_expr(target: BlindTarget) -> str:
    args = target.call_args.strip()
    return f"{target.function}({args})"


def _gen_call_succeeds(t: BlindTarget) -> Optional[str]:
    """Invariant: only an authorized caller may run `t.function`. Violated iff
    an unprivileged EOA's call does not revert."""
    body = _TEST_HEADER.format(pragma=t.pragma, contract=t.contract)
    body += f"""    {t.contract} internal target;
    address internal attacker = address(0xA11CE);

    function setUp() public {{
        target = new {t.contract}({t.constructor_args});
    }}

    function test_invariant_is_violated() public {{
        // an unprivileged EOA calls the once-guarded function
        vm.prank(attacker);
        (bool ok, ) = address(target).call(
            abi.encodeWithSignature("{t.signature or (t.function + '()')}"{_encoded_args(t)})
        );
        // invariant "only an authorized caller may call this" is VIOLATED
        // exactly when that unprivileged call succeeds
        assertTrue(ok, "call reverted - unprivileged caller is still blocked");
    }}
}}
"""
    return body


def _gen_reinit(t: BlindTarget) -> Optional[str]:
    """Invariant: `t.function` initialises at most once. Violated iff a second
    call does not revert."""
    sig = t.signature or f"{t.function}()"
    body = _TEST_HEADER.format(pragma=t.pragma, contract=t.contract)
    body += f"""    {t.contract} internal target;

    function setUp() public {{
        target = new {t.contract}({t.constructor_args});
    }}

    function test_invariant_is_violated() public {{
        (bool ok1, ) = address(target).call(
            abi.encodeWithSignature("{sig}"{_encoded_args(t)}));
        require(ok1, "first initialise call failed - test setup invalid");
        (bool ok2, ) = address(target).call(
            abi.encodeWithSignature("{sig}"{_encoded_args(t)}));
        // "at most once" is VIOLATED exactly when the second call also succeeds
        assertTrue(ok2, "second initialise reverted - one-shot guard holds");
    }}
}}
"""
    return body


def _encoded_args(t: BlindTarget) -> str:
    a = t.call_args.strip()
    return f", {a}" if a else ""


_GENERATORS: dict[str, Callable[[BlindTarget], Optional[str]]] = {
    "call_succeeds": _gen_call_succeeds,
    "reinit": _gen_reinit,
}


def generate_test(target: BlindTarget) -> tuple[Optional[str], str]:
    """Return (test_source, note). test_source is None when the objective is
    not yet supported by a generator."""
    otype = (target.objective or {}).get("type", "")
    gen = _GENERATORS.get(otype)
    if gen is None:
        return None, (f"objective type {otype!r} has no Phase 5a generator "
                      f"(unauthorized_upgrade / state_relation_violated are "
                      f"Phase 5b)")
    src = gen(target)
    return src, "generated"


def run_test_source(test_src: str, *, source_bundle: str,
                    match_contract: str = "ReproTest",
                    pass_marker: str = "[PASS] test_invariant_is_violated",
                    fail_marker: str = "test_invariant_is_violated",
                    extra_sources: Optional[dict] = None,
                    toolchain: Optional[foundry.Toolchain] = None,
                    keep_project: bool = False) -> ReproResult:
    """Scaffold a throwaway Foundry project, drop in `source_bundle` (as
    src/Target.sol), any `extra_sources` (name -> content under src/), and
    `test_src` (as test/Repro.t.sol), then `forge build` + `forge test`.

    REPRODUCED when `pass_marker` is in the output; NOT_REPRODUCED on a matching
    `[FAIL`; ERROR/PENDING otherwise. Used by the single-objective generator,
    the multi-tx sequence runner, and regression fuzzing.
    """
    tc = toolchain or foundry.resolve()
    if tc is None:
        return ReproResult(PENDING, "no Foundry toolchain reachable "
                                    "(native or WSL); not attempted")
    wd = tc.make_tempdir()
    if not wd:
        return ReproResult(ERROR, "could not create a working directory")
    try:
        writes = [
            tc.write_file(f"{wd}/foundry.toml", _FOUNDRY_TOML),
            tc.write_file(f"{wd}/src/Target.sol", source_bundle),
            tc.write_file(f"{wd}/lib/forge-std/src/Test.sol", _MINIMAL_TEST_SHIM),
            tc.write_file(f"{wd}/test/Repro.t.sol", test_src),
        ]
        for name, content in (extra_sources or {}).items():
            writes.append(tc.write_file(f"{wd}/src/{name}", content))
        if not all(writes):
            return ReproResult(ERROR, "failed to write the project files")

        build = tc.run(["forge", "build"], cwd=wd, timeout=240)
        if not build.ok:
            return ReproResult(
                NOT_REPRODUCED,
                "the generated test did not compile (insufficient shape hints)",
                artifacts={"test_source": test_src,
                           "build_output_tail": build.stdout[-2500:]
                           + build.stderr[-1500:]})

        run = tc.run(["forge", "test", "--match-contract", match_contract,
                      "-vv"], cwd=wd, timeout=300)
        out = run.stdout
        art = {"test_source": test_src,
               "forge_output_tail": out[-3500:] + run.stderr[-1000:]}
        if pass_marker in out:
            return ReproResult(REPRODUCED,
                               "the generated local-fork test demonstrated the "
                               "invariant violation", artifacts=art)
        if "[FAIL" in out and fail_marker in out:
            return ReproResult(NOT_REPRODUCED,
                               "the invariant held under the generated sequence",
                               artifacts=art)
        return ReproResult(ERROR, "forge test produced no clear pass/fail",
                           artifacts=art)
    finally:
        if not keep_project:
            tc.rmtree(wd)


def generate_and_run(target: BlindTarget, *, source_bundle: str,
                     toolchain: Optional[foundry.Toolchain] = None,
                     fork_url: Optional[str] = None,
                     fork_block: Optional[int] = None,
                     keep_project: bool = False) -> ReproResult:
    tc = toolchain or foundry.resolve()
    if tc is None:
        return ReproResult(PENDING, "no Foundry toolchain reachable "
                                    "(native or WSL); reproduction not attempted")
    test_src, note = generate_test(target)
    if test_src is None:
        return ReproResult(NOT_REPRODUCED, note)
    return run_test_source(test_src, source_bundle=source_bundle,
                           toolchain=tc, keep_project=keep_project)


def make_runner(source_bundle: str, **kw) -> Callable[[BlindTarget], ReproResult]:
    """A `runner` closure for `adversarial.reproducer.attempt` - wires §15 into
    the §8 blinded-reproduction interface."""
    def _runner(target: BlindTarget) -> ReproResult:
        return generate_and_run(target, source_bundle=source_bundle, **kw)
    return _runner


# A tiny forge-std Test shim so a reproducer can run with no network install.
# Only the members the generated tests use.
_MINIMAL_TEST_SHIM = """// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;
interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function expectRevert() external;
    function roll(uint256) external;
    function warp(uint256) external;
    function deal(address, uint256) external;
}
contract Test {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function assertTrue(bool c) internal pure { require(c, "assertTrue"); }
    function assertTrue(bool c, string memory m) internal pure { require(c, m); }
    function assertEq(uint256 a, uint256 b) internal pure { require(a == b, "assertEq"); }
}
"""
