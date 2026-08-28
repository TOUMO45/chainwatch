"""Phase 5 - automatic minimal PoC generation (src/nextgen/execground/reproducer.py, spec §15).

`generate_test` is pure and always runs. The end-to-end `generate_and_run`
tests compile + run a real Foundry test in a throwaway project and need a
reachable toolchain; they skip visibly otherwise.

Run:  python -m pytest tests/test_nextgen_execground_reproducer.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.adversarial import reproducer as AR  # noqa: E402
from src.nextgen.execground import foundry as F  # noqa: E402
from src.nextgen.execground import reproducer as R  # noqa: E402


def _target(objective_type="call_succeeds", *, sig="setOwner(address)",
            args="address(0xBEEF)"):
    return AR.BlindTarget(
        contract="Vault", function="setOwner",
        invariant_statement="only an authorized caller may set the owner",
        objective={"type": objective_type, "contract": "Vault",
                   "function": "setOwner", "caller": "unprivileged"},
        signature=sig, call_args=args)


VULN_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    function setOwner(address o) external { owner = o; }
}
"""

SAFE_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
    function setOwner(address o) external onlyOwner { owner = o; }
}
"""


# --------------------------------------------------------------------------- #
# pure
# --------------------------------------------------------------------------- #

def test_generate_test_call_succeeds_shape():
    src, note = R.generate_test(_target("call_succeeds"))
    assert src and "test_invariant_is_violated" in src
    assert "vm.prank(attacker)" in src
    assert 'encodeWithSignature("setOwner(address)"' in src


def test_generate_test_reinit_shape():
    src, note = R.generate_test(_target("reinit", sig="initialize(address)"))
    assert src and src.count("call(") == 2                # two initialise calls
    assert "second initialise reverted" in src


def test_generate_test_unsupported_objective():
    src, note = R.generate_test(_target("state_relation_violated"))
    assert src is None
    assert "Phase 5b" in note


def test_no_toolchain_is_pending(monkeypatch):
    monkeypatch.setattr(R.foundry, "resolve", lambda *a, **k: None)
    res = R.generate_and_run(_target(), source_bundle=VULN_SRC)
    assert res.status == AR.PENDING


# --------------------------------------------------------------------------- #
# end to end (needs a reachable toolchain)
# --------------------------------------------------------------------------- #

_HAVE = F.resolve() is not None
_skip = pytest.mark.skipif(not _HAVE, reason="no reachable Foundry toolchain")


@_skip
def test_vulnerable_contract_reproduces_the_violation():
    res = R.generate_and_run(_target(), source_bundle=VULN_SRC)
    assert res.status == AR.REPRODUCED, res.as_dict()
    assert res.agrees is True
    assert "test_source" in res.artifacts


@_skip
def test_safe_contract_does_not_reproduce():
    res = R.generate_and_run(_target(), source_bundle=SAFE_SRC)
    assert res.status == AR.NOT_REPRODUCED, res.as_dict()
    assert res.agrees is False


@_skip
def test_make_runner_wires_into_the_blinded_interface():
    runner = R.make_runner(VULN_SRC)
    res = AR.attempt(_target(), runner=runner)
    assert res.status == AR.REPRODUCED


@_skip
def test_reproduced_result_moves_the_gates():
    from src.nextgen import gates as G
    from src.nextgen import state as S
    res = R.generate_and_run(_target(), source_bundle=VULN_SRC)
    fs = S.FindingState("f")
    G.apply_reproducer(fs, res)
    assert fs.gates["reproducer"] == S.PASS
    assert fs.gates["invariant_violated"] == S.PASS
    assert fs.gates["state_reachable"] == S.PASS
