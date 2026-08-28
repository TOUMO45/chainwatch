"""Counterfactual Twin - the orchestrator (src/nextgen/twin/twin.py).

Pure unit tests pin `_classify`/`_select_candidates`/`_impl_at_replay` without
any RPC or fork. One integration test at the bottom runs `.run()` end to end
against a real address and skips visibly without a Foundry toolchain + fork
RPC, same gate as the rest of the Twin's integration tests.

Run:  python -m pytest tests/test_nextgen_twin_twin.py -q
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:  # noqa: BLE001
    pass

from src.nextgen import state as S  # noqa: E402
from src.nextgen.adversarial import reproducer as REPRO  # noqa: E402
from src.nextgen.adversarial import skeptic as SKEP  # noqa: E402
from src.nextgen.deployment import DeploymentFacts  # noqa: E402
from src.nextgen.execground import foundry as F  # noqa: E402
from src.nextgen.twin import model as M  # noqa: E402
from src.nextgen.twin.twin import CounterfactualTwin  # noqa: E402


def _twin() -> CounterfactualTwin:
    return CounterfactualTwin("0x" + "d" * 40, "http://fake", 1, 100)


def _facts(gate=S.PASS) -> DeploymentFacts:
    return DeploymentFacts(address="0xd", gate=gate, rationale="r")


def _skeptic(disproved=False) -> SKEP.SkepticReport:
    rep = SKEP.SkepticReport()
    if disproved:
        rep.challenges.append(SKEP.Challenge("compensating_control", SKEP.DISPROVED, "d"))
    else:
        rep.challenges.append(SKEP.Challenge("compensating_control", SKEP.NOT_DISPROVED, ""))
    return rep


def _repro(status) -> REPRO.ReproResult:
    return REPRO.ReproResult(status, "d")


def test_classify_confirmed_when_everything_lines_up():
    tw = _twin()
    verdict, reason = tw._classify(_facts(S.PASS), _skeptic(False), _repro(REPRO.REPRODUCED))
    assert verdict == M.TWIN_CONFIRMED


def test_classify_rejected_when_skeptic_disproves():
    tw = _twin()
    verdict, reason = tw._classify(_facts(S.PASS), _skeptic(True), _repro(REPRO.REPRODUCED))
    assert verdict == M.TWIN_REJECTED
    assert "Skeptic" in reason


def test_classify_rejected_when_implementation_no_longer_live():
    tw = _twin()
    verdict, reason = tw._classify(_facts(S.FAIL), _skeptic(False), _repro(REPRO.REPRODUCED))
    assert verdict == M.TWIN_REJECTED


def test_classify_rejected_when_reproducer_disagrees():
    tw = _twin()
    verdict, reason = tw._classify(_facts(S.PASS), _skeptic(False), _repro(REPRO.NOT_REPRODUCED))
    assert verdict == M.TWIN_REJECTED


def test_classify_unknown_when_reproducer_pending_no_toolchain():
    tw = _twin()
    verdict, reason = tw._classify(_facts(S.PASS), _skeptic(False), _repro(REPRO.PENDING))
    assert verdict == M.TWIN_UNKNOWN


def test_classify_unknown_when_deployment_gate_unknown():
    tw = _twin()
    verdict, reason = tw._classify(_facts(S.GATE_UNKNOWN), _skeptic(False),
                                   _repro(REPRO.REPRODUCED))
    assert verdict == M.TWIN_UNKNOWN


def test_classify_priority_skeptic_beats_a_would_be_confirm():
    """Even when deployment+reproducer both agree, a Skeptic disproof wins -
    matches skeptic.py's own doc: the Skeptic never PASSES a gate, but a
    DISPROVED outcome is terminal."""
    tw = _twin()
    verdict, _ = tw._classify(_facts(S.PASS), _skeptic(True), _repro(REPRO.REPRODUCED))
    assert verdict == M.TWIN_REJECTED


def _fp(sel, n_success=1) -> M.FunctionFingerprint:
    fp = M.FunctionFingerprint(address="0xd", selector=sel)
    fp.n_success = n_success
    return fp


def _tx(h, sel, block=100) -> M.TxRecord:
    return M.TxRecord(hash=h, block=block, tx_index=0, sender="0xa", to="0xd",
                      value=0, input=sel, selector=sel, status=True)


def test_select_candidates_prefers_selectors_with_a_boundary():
    tw = _twin()
    tw.max_txs_to_mutate = 5
    col = M.Collection(address="0xd", chain_id=1, from_block=1, to_block=100)
    col.txs = [_tx("0x1", "0xaaa"), _tx("0x2", "0xbbb")]
    bounds = [M.Boundary(kind=M.AUTHORIZATION, statement="x", selector="0xaaa")]
    out = tw._select_candidates(col, {}, bounds)
    assert [t.selector for t in out] == ["0xaaa"]


def test_select_candidates_falls_back_to_all_when_no_boundary_mined():
    tw = _twin()
    col = M.Collection(address="0xd", chain_id=1, from_block=1, to_block=100)
    col.txs = [_tx("0x1", "0xaaa"), _tx("0x2", "0xbbb")]
    out = tw._select_candidates(col, {}, [])
    assert {t.selector for t in out} == {"0xaaa", "0xbbb"}


def test_select_candidates_dedupes_by_selector_keeping_most_recent():
    tw = _twin()
    col = M.Collection(address="0xd", chain_id=1, from_block=1, to_block=100)
    col.txs = [_tx("0x1", "0xaaa", block=50), _tx("0x2", "0xaaa", block=99)]
    out = tw._select_candidates(col, {}, [])
    assert len(out) == 1 and out[0].hash == "0x2"


def test_select_candidates_respects_the_budget():
    tw = _twin()
    tw.max_txs_to_mutate = 2
    col = M.Collection(address="0xd", chain_id=1, from_block=1, to_block=100)
    col.txs = [_tx(f"0x{i}", f"0xsel{i}") for i in range(10)]
    out = tw._select_candidates(col, {}, [])
    assert len(out) == 2


def test_impl_at_replay_picks_the_sample_at_or_before_the_fork_block():
    tw = _twin()
    col = M.Collection(address="0xd", chain_id=1, from_block=1, to_block=1000)
    col.impl_samples = [(1, "0xold"), (500, "0xnew")]
    mut = M.Mutation(kind=M.ACTOR_SUBSTITUTION, base_tx="0x", selector="0x1",
                     statement="s", fork_block=600)
    assert tw._impl_at_replay(col, mut) == "0xnew"


def test_impl_at_replay_falls_back_to_the_latest_sample_when_none_precede_it():
    tw = _twin()
    col = M.Collection(address="0xd", chain_id=1, from_block=1, to_block=1000)
    col.impl_samples = [(500, "0xonly")]
    mut = M.Mutation(kind=M.ACTOR_SUBSTITUTION, base_tx="0x", selector="0x1",
                     statement="s", fork_block=10)
    assert tw._impl_at_replay(col, mut) == "0xonly"


# --------------------------------------------------------------------- integration

_FORK_RPC = os.environ.get("CHAINWATCH_FORK_RPC") or os.environ.get("RPC_URL")
_TC = F.resolve()
_CAN = _TC is not None and F.anvil_available() and bool(_FORK_RPC)


@pytest.mark.skipif(not _CAN, reason="needs a Foundry toolchain with anvil and a fork RPC")
def test_twin_run_end_to_end_against_real_weth():
    """WETH: a real, extremely high-traffic address. Not a claim that a
    violation WILL be found (WETH is battle-tested) - the assertion is that
    the full ten-phase pipeline runs to a real verdict without raising, and
    that verdict is one of the three the spec defines."""
    weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    from src.nextgen.twin.rpc import RpcClient
    live = RpcClient(_FORK_RPC, timeout=20)
    head = live.block_number()
    # A narrow window: WETH is high-traffic enough that even ~20 blocks give
    # real transactions to fingerprint/mutate/replay, while keeping this test
    # fast and reliable to re-run (a wide window here previously took several
    # minutes of real RPC + multiple AnvilFork spin-ups for no extra proof
    # value - the assertion is "the pipeline completes to a real verdict",
    # not "against a specific amount of history").
    tw = CounterfactualTwin(weth, _FORK_RPC, head - 20, head,
                           max_txs_to_mutate=2, max_mutations_per_tx=2)
    res = tw.run()
    assert res.verdict in (M.TWIN_CONFIRMED, M.TWIN_REJECTED, M.TWIN_UNKNOWN)
    assert res.collection is not None
    assert res.reason
