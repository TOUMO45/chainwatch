"""Phase 5b - stateful multi-transaction sequence search (src/nextgen/execground/sequences.py, spec §5).

Pure: step/sequence rendering, `enumerate_sequences`, `minimize` (ddmin) with a
fake verifier. Gated: `search` end to end where the objective needs a setup tx.

Run:  python -m pytest tests/test_nextgen_sequences.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.adversarial.reproducer import REPRODUCED  # noqa: E402
from src.nextgen.execground import foundry as F  # noqa: E402
from src.nextgen.execground import sequences as Q  # noqa: E402


def test_txstep_renders_prank_and_objective_assert():
    s = Q.TxStep("Vault", "withdraw", "withdraw(uint256)", "attacker", "1 ether")
    txt = s.render(2, is_objective=True)
    assert "vm.prank(address(0xA11CE));" in txt
    assert 'encodeWithSignature("withdraw(uint256)", 1 ether)' in txt
    assert "assertTrue(ok2" in txt


def test_setup_step_requires_success():
    s = Q.TxStep("Vault", "deposit", "deposit()", "attacker", must_succeed=True)
    txt = s.render(0, is_objective=False)
    assert 'require(ok0, "setup step 0 failed")' in txt


def test_enumerate_bare_then_prefixed():
    seqs = Q.enumerate_sequences(
        contract="Vault", function="drain", signature="drain()",
        setup_functions=[("deposit", "deposit()", ""),
                         ("approveAll", "approveAll()", "")],
        max_len=3)
    lengths = sorted(len(s) for s in seqs)
    assert lengths[0] == 1                       # the bare call
    assert 2 in lengths and 3 in lengths
    # bare-call sequence is just the objective
    bare = [s for s in seqs if len(s) == 1][0]
    assert bare.steps[0].function == "drain"


def test_minimize_drops_redundant_setup_steps():
    obj = Q.TxStep("V", "drain", "drain()")
    junk1 = Q.TxStep("V", "noop1", "noop1()", must_succeed=True)
    junk2 = Q.TxStep("V", "noop2", "noop2()", must_succeed=True)
    need = Q.TxStep("V", "deposit", "deposit()", must_succeed=True)
    seq = Q.CandidateSequence([junk1, need, junk2, obj])

    def verify(s: Q.CandidateSequence) -> bool:
        names = {st.function for st in s.steps}
        return {"deposit", "drain"} <= names          # only deposit is required

    out = Q.minimize(seq, verify)
    fns = [s.function for s in out.steps]
    assert fns == ["deposit", "drain"]


def test_minimize_never_drops_the_objective():
    obj = Q.TxStep("V", "drain", "drain()")
    seq = Q.CandidateSequence([obj])
    out = Q.minimize(seq, lambda s: True)
    assert len(out.steps) == 1 and out.steps[0].function == "drain"


def test_candidate_render_test_and_report():
    seq = Q.CandidateSequence(
        [Q.TxStep("Vault", "deposit", "deposit()", must_succeed=True),
         Q.TxStep("Vault", "drain", "drain()")],
        invariant_statement="only an owner may drain")
    src = seq.render_test("Vault")
    assert "contract ReproTest is Test" in src
    assert "test_invariant_is_violated" in src
    rep = seq.as_report()
    assert "Minimal attack sequence:" in rep and "only an owner may drain" in rep


# --------------------------------------------------------------------------- #
# end to end (needs a toolchain)
# --------------------------------------------------------------------------- #

_HAVE = F.resolve() is not None
_skip = pytest.mark.skipif(not _HAVE, reason="no reachable Foundry toolchain")

# drain() reverts unless the caller has deposited first -> a 2-step sequence is
# the minimal reproducer.
SETUP_NEEDED_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += (msg.value == 0 ? 1 : msg.value); }
    function drain() external {
        require(bal[msg.sender] > 0, "deposit first");
        bal[msg.sender] = 0;             // no ownership check - the regression
        selfWreck += 1;
    }
    uint256 public selfWreck;
}
"""


@_skip
def test_search_finds_and_minimises_a_two_step_sequence():
    minimal, result = Q.search(
        source_bundle=SETUP_NEEDED_SRC, contract="Vault", function="drain",
        signature="drain()", invariant_statement="only an owner may drain",
        setup_functions=[("deposit", "deposit()", "")], max_len=3)
    assert result.status == REPRODUCED, result.as_dict()
    assert minimal is not None
    fns = [s.function for s in minimal.steps]
    assert fns == ["deposit", "drain"]          # deposit is required, nothing else


@_skip
def test_search_bare_call_when_no_setup_needed():
    src = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault { address public owner; constructor(){owner=msg.sender;}
 function setOwner(address o) external { owner = o; } }"""
    minimal, result = Q.search(
        source_bundle=src, contract="Vault", function="setOwner",
        signature="setOwner(address)", call_args="address(0xBEEF)",
        setup_functions=[], max_len=3)
    assert result.status == REPRODUCED
    assert minimal is not None and len(minimal.steps) == 1
