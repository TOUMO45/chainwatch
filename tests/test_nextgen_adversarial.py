"""Phase 4 - adversarial validation (src/nextgen/adversarial/*, spec §7/§8).

Pure. Pins: a DISPROVED Skeptic challenge FAILS its gate; a clean sweep only
reaches `independent_validation` PASS when the blinded reproducer already
agrees; the reproducer is PENDING with no runner and never PASSES on its own.

Run:  python -m pytest tests/test_nextgen_adversarial.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import gates as G  # noqa: E402
from src.nextgen import state as S  # noqa: E402
from src.nextgen.adversarial import hunter as H  # noqa: E402
from src.nextgen.adversarial import reproducer as RP  # noqa: E402
from src.nextgen.adversarial import skeptic as SK  # noqa: E402


class _Gate:
    def __init__(self, gate, rationale=""):
        self.gate = gate
        self.rationale = rationale


# --------------------------------------------------------------------------- #
# Skeptic
# --------------------------------------------------------------------------- #

def test_compensating_control_found_disproves_and_fails_the_gate():
    rep = SK.sweep(compensating_report=_Gate(S.FAIL, "internal auth lib"))
    assert rep.disproved is True
    fs = S.FindingState("f")
    G.apply_skeptic(fs, rep)
    assert fs.gates["no_compensating_control"] == S.FAIL
    assert fs.gates["independent_validation"] == S.FAIL
    fine, verdict, _ = S.classify(fs.gates)
    assert verdict == S.VERDICT_REJECTED


def test_no_unprivileged_path_disproves():
    class _P:
        unprivileged = False
    rep = SK.sweep(attack_paths=[_P()])
    ch = [c for c in rep.challenges if c.name == "path_reachability"][0]
    assert ch.outcome == SK.DISPROVED


def test_clean_sweep_without_reproducer_leaves_independent_validation_unknown():
    rep = SK.sweep(compensating_report=_Gate(S.PASS),
                   deployment_facts=_Gate(S.PASS),
                   provenance_chain=_Gate(S.PASS))
    assert rep.disproved is False
    fs = S.FindingState("f")
    G.apply_skeptic(fs, rep)
    assert fs.gates["independent_validation"] == S.GATE_UNKNOWN


def test_clean_sweep_with_reproducer_pass_reaches_independent_validation_pass():
    rep = SK.sweep(compensating_report=_Gate(S.PASS),
                   deployment_facts=_Gate(S.PASS),
                   provenance_chain=_Gate(S.PASS))
    fs = S.FindingState("f")
    fs.set_gate("reproducer", S.PASS)
    G.apply_skeptic(fs, rep)
    assert fs.gates["independent_validation"] == S.PASS


def test_too_few_checks_is_insufficient_coverage():
    rep = SK.sweep(compensating_report=_Gate(S.PASS))   # 1 check
    fs = S.FindingState("f")
    fs.set_gate("reproducer", S.PASS)
    G.apply_skeptic(fs, rep)
    assert fs.gates["independent_validation"] == S.GATE_UNKNOWN


def test_all_inapplicable_when_no_inputs():
    rep = SK.sweep()
    assert all(c.outcome == SK.INAPPLICABLE for c in rep.challenges)
    assert rep.ran == []


# --------------------------------------------------------------------------- #
# Reproducer
# --------------------------------------------------------------------------- #

def _target():
    return RP.BlindTarget(contract="Vault", function="withdraw",
                          invariant_statement="only an authorized user may withdraw",
                          objective={"type": "call_succeeds", "function": "withdraw"})


def test_reproducer_is_pending_without_a_runner():
    res = RP.attempt(_target())
    assert res.status == RP.PENDING
    assert res.agrees is None
    fs = S.FindingState("f")
    G.apply_reproducer(fs, res)
    assert fs.gates["reproducer"] == S.PENDING


def test_reproducer_reproduced_sets_three_gates():
    def runner(_t):
        return RP.ReproResult(RP.REPRODUCED, "attacker balance +147 ETH")
    res = RP.attempt(_target(), runner=runner)
    assert res.agrees is True
    fs = S.FindingState("f")
    G.apply_reproducer(fs, res)
    assert fs.gates["reproducer"] == S.PASS
    assert fs.gates["invariant_violated"] == S.PASS
    assert fs.gates["state_reachable"] == S.PASS


def test_reproducer_not_reproduced_fails_the_gate():
    def runner(_t):
        return RP.ReproResult(RP.NOT_REPRODUCED, "invariant held under the sequence")
    res = RP.attempt(_target(), runner=runner)
    fs = S.FindingState("f")
    G.apply_reproducer(fs, res)
    assert fs.gates["reproducer"] == S.FAIL
    fine, verdict, _ = S.classify(fs.gates)
    assert verdict == S.VERDICT_REJECTED


def test_runner_exception_is_error_not_crash():
    def runner(_t):
        raise RuntimeError("anvil died")
    res = RP.attempt(_target(), runner=runner)
    assert res.status == RP.ERROR and "anvil died" in res.detail


# --------------------------------------------------------------------------- #
# Hunter
# --------------------------------------------------------------------------- #

def test_hunter_assemble_only_touches_supplied_gates():
    fs = S.FindingState("f")
    H.assemble(fs, compensating_report=_Gate(S.PASS, "nothing compensates"))
    assert fs.gates["no_compensating_control"] == S.PASS
    assert fs.gates["reachable_path"] == S.PENDING       # not supplied
