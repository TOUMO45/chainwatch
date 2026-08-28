"""Phase 0 - the security evidence graph (src/nextgen/evidence_graph.py, spec §18).

Fast - pure data. Pins the property that makes the graph worth having: an
LLM-hypothesis node is not evidence, and the graph can say which claims are
unsupported (spec §22).

Run:  python -m pytest tests/test_nextgen_evidence_graph.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import evidence_graph as EG  # noqa: E402


def test_add_node_and_edge_and_read_back():
    g = EG.EvidenceGraph()
    c = g.add_node(EG.COMMIT, "8f72a9c removes onlyOwner",
                   established_by="history.py", data={"hash": "8f72a9c"})
    f = g.add_node(EG.FINDING, "Vault.withdraw unguarded",
                   established_by="nextgen.timemachine")
    g.add_edge(f, EG.DERIVED_FROM, c)
    assert g.node(c).data["hash"] == "8f72a9c"
    assert g.neighbors(f, relation=EG.DERIVED_FROM) == [c]
    assert len(g.edges(relation=EG.DERIVED_FROM)) == 1


def test_unknown_kind_and_relation_are_rejected():
    g = EG.EvidenceGraph()
    with pytest.raises(ValueError):
        g.add_node("WISHFUL", "x", established_by="history.py")
    a = g.add_node(EG.COMMIT, "a", established_by="history.py")
    b = g.add_node(EG.FINDING, "b", established_by="history.py")
    with pytest.raises(ValueError):
        g.add_edge(a, "IMPLIES", b)


def test_edge_endpoints_must_exist():
    g = EG.EvidenceGraph()
    a = g.add_node(EG.COMMIT, "a", established_by="history.py")
    with pytest.raises(KeyError):
        g.add_edge(a, EG.DERIVED_FROM, "ghost")


def test_established_by_must_be_known_producer_or_explicit_hypothesis():
    g = EG.EvidenceGraph()
    with pytest.raises(ValueError):
        g.add_node(EG.INVARIANT, "made up", established_by="vibes")
    # the two allowed shapes:
    g.add_node(EG.INVARIANT, "det", established_by="nextgen.invariants")
    g.add_node(EG.INVARIANT, "hyp", established_by=EG.LLM_HYPOTHESIS)


def test_llm_hypothesis_node_is_not_evidence():
    g = EG.EvidenceGraph()
    n = g.add_node(EG.ATTACK_PATH, "attacker calls init() then withdraw()",
                   established_by=EG.LLM_HYPOTHESIS)
    assert g.node(n).is_evidence() is False


def test_unsupported_lists_ungrounded_hypotheses_only():
    g = EG.EvidenceGraph()
    grounded_hyp = g.add_node(EG.ATTACK_PATH, "path A", established_by=EG.LLM_HYPOTHESIS)
    loose_hyp = g.add_node(EG.ATTACK_PATH, "path B", established_by=EG.LLM_HYPOTHESIS)
    proof = g.add_node(EG.REPRODUCER, "fork run #1", established_by="foundry")
    g.add_edge(proof, EG.SUPPORTS, grounded_hyp)

    loose = {n.id for n in g.unsupported()}
    assert loose_hyp in loose
    assert grounded_hyp not in loose


def test_a_hypothesis_supported_only_by_another_hypothesis_stays_unsupported():
    g = EG.EvidenceGraph()
    h1 = g.add_node(EG.INVARIANT, "h1", established_by=EG.LLM_HYPOTHESIS)
    h2 = g.add_node(EG.INVARIANT, "h2", established_by=EG.LLM_HYPOTHESIS)
    g.add_edge(h1, EG.SUPPORTS, h2)
    assert h2 in {n.id for n in g.unsupported()}


def test_contradictions_surface_skeptic_edges():
    g = EG.EvidenceGraph()
    claim = g.add_node(EG.FINDING, "withdraw is unguarded", established_by="rules")
    rebut = g.add_node(EG.COMPENSATING_CONTROL, "internal auth lib checks msg.sender",
                       established_by="nextgen.compensating")
    g.add_edge(rebut, EG.CONTRADICTS, claim)
    assert (rebut, claim) in g.contradictions()


def test_trace_returns_the_chain_to_a_source():
    g = EG.EvidenceGraph()
    producer = g.add_node(EG.BYTECODE, "runtime hash A", established_by="liveness.py")
    dep = g.add_node(EG.DEPLOYMENT, "0xDEF impl", established_by="liveness.py")
    finding = g.add_node(EG.FINDING, "live regression", established_by="nextgen.provenance")
    g.add_edge(finding, EG.DERIVED_FROM, dep)
    g.add_edge(dep, EG.MATCHES, producer)
    paths = g.trace(finding)
    assert paths and paths[0][0] == finding
    assert any("MATCHES ->" in step for step in paths[0])


def test_trace_is_cycle_safe():
    g = EG.EvidenceGraph()
    a = g.add_node(EG.FINDING, "a", established_by="rules")
    b = g.add_node(EG.FINDING, "b", established_by="rules")
    g.add_edge(a, EG.DERIVED_FROM, b)
    g.add_edge(b, EG.DERIVED_FROM, a)
    paths = g.trace(a)   # must terminate
    assert any("cycle" in step for path in paths for step in path)


def test_round_trips_through_dict():
    g = EG.EvidenceGraph()
    c = g.add_node(EG.COMMIT, "c", established_by="history.py", data={"hash": "abc"})
    f = g.add_node(EG.FINDING, "f", established_by="rules")
    g.add_edge(f, EG.DERIVED_FROM, c)
    g2 = EG.EvidenceGraph.from_dict(g.as_dict())
    assert g2.node(c).data == {"hash": "abc"}
    assert g2.neighbors(f, relation=EG.DERIVED_FROM) == [c]


def test_render_text_flags_unsupported_hypotheses():
    g = EG.EvidenceGraph()
    g.add_node(EG.ATTACK_PATH, "ungrounded guess", established_by=EG.LLM_HYPOTHESIS)
    txt = g.render_text()
    assert "UNSUPPORTED HYPOTHESES" in txt
    assert "ungrounded guess" in txt


def test_auto_id_is_stable_for_same_content():
    g1 = EG.EvidenceGraph()
    g2 = EG.EvidenceGraph()
    id1 = g1.add_node(EG.COMMIT, "same", established_by="history.py", data={"h": 1})
    id2 = g2.add_node(EG.COMMIT, "same", established_by="history.py", data={"h": 1})
    assert id1 == id2
