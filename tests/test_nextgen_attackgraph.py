"""Phase 3 - the attack-path / protocol graph (src/nextgen/attackgraph.py, spec §4/§12).

Layer 1 here is pure: hand-built `ProtocolGraph` + `find_attack_paths` +
`apply_attackgraph` gate mapping. Layer 2 (`build_graph` from real compiled
Solidity) is in test_nextgen_attackgraph_build.py, slither-gated.

Run:  python -m pytest tests/test_nextgen_attackgraph.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import attackgraph as AG  # noqa: E402
from src.nextgen import evidence_graph as EG  # noqa: E402
from src.nextgen import gates as G  # noqa: E402
from src.nextgen import state as S  # noqa: E402


def _fn(g, contract, name, *, external=True, guarded=False, sensitive=()):
    return g.add_node(AG.FUNCTION, f"{contract}.{name}", contract=contract,
                      function=name, external=external, guarded=guarded,
                      mutates_sensitive=bool(sensitive),
                      sensitive_vars=tuple(sensitive))


def test_unprivileged_direct_path_to_a_sensitive_writer():
    g = AG.ProtocolGraph()
    f = _fn(g, "Vault", "setOwner", guarded=False, sensitive=("owner",))
    g.add_edge(g.eoa, AG.CALL, f)
    paths = AG.find_attack_paths(g)
    assert len(paths) == 1
    assert paths[0].unprivileged is True
    assert paths[0].reaches == f
    assert paths[0].crosses_contracts is False


def test_guarded_entry_point_yields_a_privileged_only_path():
    g = AG.ProtocolGraph()
    f = _fn(g, "Vault", "setOwner", guarded=True, sensitive=("owner",))
    g.add_edge(g.eoa, AG.CALL, f, guarded=True)
    paths = AG.find_attack_paths(g)
    assert len(paths) == 1
    assert paths[0].unprivileged is False


def test_cross_contract_path_is_flagged():
    g = AG.ProtocolGraph()
    entry = _fn(g, "Router", "route", guarded=False)
    sink = _fn(g, "Vault", "pull", guarded=False, sensitive=("_balances",))
    g.add_edge(g.eoa, AG.CALL, entry)
    g.add_edge(entry, AG.CALL, sink)
    paths = AG.find_attack_paths(g)
    assert paths and paths[0].unprivileged is True
    assert paths[0].crosses_contracts is True
    assert AG.CALL in paths[0].edge_kinds


def test_callback_mediated_path_reaches_an_otherwise_unreachable_sink():
    # `settle` has no direct EOA entry; it is reachable only after `flash`
    # hands control to an attacker contract, which then calls it.
    g = AG.ProtocolGraph()
    a = _fn(g, "Pool", "flash", guarded=False)
    atk = g.add_node(AG.CALLBACK_SINK, "attacker contract")
    b = _fn(g, "Vault", "settle", external=False, guarded=False,
            sensitive=("debt",))
    g.add_edge(g.eoa, AG.CALL, a)
    g.add_edge(a, AG.CALLBACK, atk, note="attacker regains control")
    g.add_edge(atk, AG.CALL, b)
    paths = AG.find_attack_paths(g)
    reach_b = [p for p in paths if p.reaches == b]
    assert reach_b and reach_b[0].unprivileged is True
    assert AG.CALLBACK in reach_b[0].edge_kinds
    assert reach_b[0].crosses_contracts is True


def test_no_sensitive_sink_means_no_path():
    g = AG.ProtocolGraph()
    f = _fn(g, "View", "peek", guarded=False, sensitive=())
    g.add_edge(g.eoa, AG.CALL, f)
    assert AG.find_attack_paths(g) == []


def test_target_function_filter():
    g = AG.ProtocolGraph()
    x = _fn(g, "C", "harmless", sensitive=())
    y = _fn(g, "C", "danger", sensitive=("owner",))
    g.add_edge(g.eoa, AG.CALL, x)
    g.add_edge(g.eoa, AG.CALL, y)
    paths = AG.find_attack_paths(g, target_contract="C", target_function="danger")
    assert len(paths) == 1 and paths[0].reaches == y


def test_max_depth_is_respected():
    g = AG.ProtocolGraph()
    prev = g.eoa
    nodes = []
    for i in range(10):
        n = _fn(g, "Chain", f"f{i}", sensitive=("owner",) if i == 9 else ())
        g.add_edge(prev, AG.CALL, n)
        prev = n
        nodes.append(n)
    assert AG.find_attack_paths(g, max_depth=3) == []
    deep = AG.find_attack_paths(g, max_depth=12)
    assert deep and deep[0].reaches == nodes[-1]


def test_unknown_kinds_are_rejected():
    g = AG.ProtocolGraph()
    with pytest.raises(ValueError):
        g.add_node("WITCH", "x")
    a = _fn(g, "C", "f")
    with pytest.raises(ValueError):
        g.add_edge(g.eoa, "TELEPORT", a)


def test_evidence_graph_export():
    g = AG.ProtocolGraph()
    f = _fn(g, "Vault", "setOwner", sensitive=("owner",))
    g.add_edge(g.eoa, AG.CALL, f)
    paths = AG.find_attack_paths(g)
    eg = EG.EvidenceGraph()
    ids = AG.to_evidence_graph(paths, g, eg)
    assert ids and eg.node(ids[0]).kind == EG.ATTACK_PATH
    assert eg.node(ids[0]).established_by == "nextgen.attackgraph"


# --------------------------------------------------------------------------- #
# gate mapping
# --------------------------------------------------------------------------- #

def test_gate_pass_on_unprivileged_path():
    g = AG.ProtocolGraph()
    f = _fn(g, "Vault", "setOwner", sensitive=("owner",))
    g.add_edge(g.eoa, AG.CALL, f)
    fs = S.FindingState("x")
    G.apply_attackgraph(fs, AG.find_attack_paths(g))
    assert fs.gates["reachable_path"] == S.PASS


def test_gate_fail_when_only_guarded_paths():
    g = AG.ProtocolGraph()
    f = _fn(g, "Vault", "setOwner", guarded=True, sensitive=("owner",))
    g.add_edge(g.eoa, AG.CALL, f, guarded=True)
    fs = S.FindingState("x")
    G.apply_attackgraph(fs, AG.find_attack_paths(g))
    assert fs.gates["reachable_path"] == S.FAIL
    fine, verdict, _ = S.classify(fs.gates)
    assert fine == S.UNREACHABLE and verdict == S.VERDICT_REJECTED


def test_gate_fail_when_no_path():
    g = AG.ProtocolGraph()
    _fn(g, "V", "peek", sensitive=())
    fs = S.FindingState("x")
    G.apply_attackgraph(fs, AG.find_attack_paths(g))
    assert fs.gates["reachable_path"] == S.FAIL
