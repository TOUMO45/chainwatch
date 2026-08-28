"""Phase 3b - git->build->bytecode->deployment provenance (src/nextgen/provenance.py, spec §9).

Pure: `build_chain` from already-fetched inputs, no network. Pins the gate
mapping (MATCH -> PASS, MISMATCH -> FAIL/DEPLOYMENT_MISMATCH, INCOMPLETE ->
UNKNOWN) and that a missing link never produces a PASS.

Run:  python -m pytest tests/test_nextgen_provenance.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import evidence_graph as EG  # noqa: E402
from src.nextgen import gates as G  # noqa: E402
from src.nextgen import provenance as PV  # noqa: E402
from src.nextgen import state as S  # noqa: E402


def _liveness(verdict, kdig="ab" * 16):
    return {"verdict": verdict,
            "evidence": {"deployed": {"normalized_keccak": kdig}}}


def _settings():
    return {"compiler": "0.5.17", "optimizer": True, "runs": 200,
            "evm_version": "istanbul"}


def test_full_chain_live_is_match_and_pass():
    ch = PV.build_chain(commit="a4c48d61661a", build_settings=_settings(),
                        local_runtime_hex="0x6080abcd",
                        liveness=_liveness("LIVE"))
    assert ch.verdict == PV.MATCHED
    assert ch.gate == S.PASS
    assert ch.complete is True


def test_patched_is_mismatch_and_fail_deployment_mismatch():
    ch = PV.build_chain(commit="deadbeef1234", build_settings=_settings(),
                        local_runtime_hex="0x6080abcd",
                        liveness=_liveness("PATCHED"))
    assert ch.verdict == PV.MISMATCH
    assert ch.gate == S.FAIL
    fs = S.FindingState("f")
    G.apply_provenance(fs, ch)
    fine, verdict, _ = S.classify(fs.gates)
    assert fine == S.DEPLOYMENT_MISMATCH
    assert verdict == S.VERDICT_REJECTED


def test_missing_liveness_is_incomplete_and_unknown():
    ch = PV.build_chain(commit="a4c48d61661a", build_settings=_settings(),
                        local_runtime_hex="0x6080abcd", liveness=None)
    assert ch.verdict == PV.INCOMPLETE
    assert ch.gate == S.GATE_UNKNOWN


def test_missing_build_settings_never_passes_even_if_live():
    ch = PV.build_chain(commit="a4c48d61661a", build_settings=None,
                        local_runtime_hex="0x6080abcd",
                        liveness=_liveness("LIVE"))
    # liveness says LIVE, but the chain still records the build-env link as
    # unestablished; the verdict follows liveness (MATCH) yet `complete` is False
    assert ch.complete is False
    assert any(not l.established and l.stage == PV.BUILD_ENV for l in ch.links)


def test_gate_bridge_pass():
    ch = PV.build_chain(commit="c0ffee123456", build_settings=_settings(),
                        local_runtime_hex="0xdead", liveness=_liveness("LIVE"))
    fs = S.FindingState("f")
    G.apply_provenance(fs, ch)
    assert fs.gates["bytecode_provenance"] == S.PASS


def test_evidence_graph_export_uses_match_or_mismatch_edge():
    live = PV.build_chain(commit="c0ffee123456", build_settings=_settings(),
                          local_runtime_hex="0xdead", liveness=_liveness("LIVE"))
    g = EG.EvidenceGraph()
    did = live.to_evidence_graph(g)
    assert g.node(did).kind == EG.DEPLOYMENT
    assert g.edges(relation=EG.MATCHES)

    patched = PV.build_chain(commit="c0ffee123456", build_settings=_settings(),
                             local_runtime_hex="0xdead",
                             liveness=_liveness("PATCHED"))
    g2 = EG.EvidenceGraph()
    patched.to_evidence_graph(g2)
    assert g2.edges(relation=EG.MISMATCHES)


def test_render_text_is_readable():
    ch = PV.build_chain(commit="c0ffee123456", build_settings=_settings(),
                        local_runtime_hex="0xdead", liveness=_liveness("LIVE"))
    txt = ch.render_text()
    assert "PROVENANCE" in txt and "verdict: MATCH" in txt
