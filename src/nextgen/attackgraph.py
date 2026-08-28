"""The attack-path / protocol security graph (spec §4, §12).

A dangerous function existing is not a vulnerability. The attacker must have a
VALID PATH from an externally controlled entry point to the security-sensitive
state. This module builds that graph from a Slither compilation and answers:

    can an unprivileged EOA travel from an external entry point to a function
    that mutates sensitive state, without traversing a msg.sender guard?

    EOA --CALL--> Vault.deposit --CALL--> Router.swap --CALLBACK--> EOA
        --CALL--> Vault.withdraw   (mutates shares/balances)

Nodes model protocol roles (EOA, CONTRACT, PROXY, IMPLEMENTATION, ORACLE,
TOKEN, BRIDGE, GOVERNANCE, VAULT, POOL, CALLBACK_SINK); edges model the moves
an attacker can make (CALL, DELEGATECALL, STATICCALL, TRANSFER, APPROVE,
PERMIT, UPGRADE, INITIALIZE, CALLBACK, ORACLE_READ, BRIDGE_MESSAGE,
GOVERNANCE_EXECUTION). A guard on an edge means the attacker cannot traverse it
unless they already hold the role.

Phase 3 scope: reachability (does a path EXIST). Whether the path's state
preconditions can actually be met, and whether a run of it violates an
invariant, are execution questions - the `state_reachable` and
`invariant_violated` gates, filled in Phase 5.

`slither` is needed only to CALL `build_graph`; the graph object and the
search are pure.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Optional

from . import evidence_graph as EG

# --------------------------------------------------------------------------- #
# node / edge vocabulary
# --------------------------------------------------------------------------- #

EOA = "EOA"
CONTRACT = "CONTRACT"
PROXY = "PROXY"
IMPLEMENTATION = "IMPLEMENTATION"
LIBRARY = "LIBRARY"
ORACLE = "ORACLE"
TOKEN = "TOKEN"
BRIDGE = "BRIDGE"
GOVERNANCE = "GOVERNANCE"
VAULT = "VAULT"
POOL = "POOL"
CALLBACK_SINK = "CALLBACK_SINK"
FUNCTION = "FUNCTION"          # a specific external/public entry point

NODE_KINDS = frozenset({
    EOA, CONTRACT, PROXY, IMPLEMENTATION, LIBRARY, ORACLE, TOKEN, BRIDGE,
    GOVERNANCE, VAULT, POOL, CALLBACK_SINK, FUNCTION,
})

CALL = "CALL"
DELEGATECALL = "DELEGATECALL"
STATICCALL = "STATICCALL"
TRANSFER = "TRANSFER"
APPROVE = "APPROVE"
PERMIT = "PERMIT"
UPGRADE = "UPGRADE"
INITIALIZE = "INITIALIZE"
CALLBACK = "CALLBACK"
ORACLE_READ = "ORACLE_READ"
BRIDGE_MESSAGE = "BRIDGE_MESSAGE"
GOVERNANCE_EXECUTION = "GOVERNANCE_EXECUTION"

EDGE_KINDS = frozenset({
    CALL, DELEGATECALL, STATICCALL, TRANSFER, APPROVE, PERMIT, UPGRADE,
    INITIALIZE, CALLBACK, ORACLE_READ, BRIDGE_MESSAGE, GOVERNANCE_EXECUTION,
})

# edges an unprivileged attacker can traverse to MOVE THROUGH the protocol
_TRAVERSABLE = frozenset({CALL, DELEGATECALL, CALLBACK, INITIALIZE, UPGRADE,
                          GOVERNANCE_EXECUTION, BRIDGE_MESSAGE})

_ORACLE_HINT = ("latestanswer", "latestrounddata", "getprice", "consult",
                "getamountout", "price0cumulative", "peek", "latest")
_BRIDGE_HINT = ("relaymessage", "finalizedeposit", "finalizewithdrawal",
                "processmessage", "receivemessage", "_executemessage")
_GOV_HINT = ("propose", "queue", "castvote", "execute", "executetransaction")
_VAULT_HINT = ("deposit", "withdraw", "redeem", "mintshares", "totalassets")
_POOL_HINT = ("swap", "addliquidity", "removeliquidity", "mint", "burn",
              "flashloan", "flash")


@dataclass
class GNode:
    id: str
    kind: str
    label: str
    contract: str = ""
    function: str = ""
    external: bool = False
    guarded: bool = False           # msg.sender guard on this entry point
    mutates_sensitive: bool = False
    sensitive_vars: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label,
                "contract": self.contract, "function": self.function,
                "external": self.external, "guarded": self.guarded,
                "mutates_sensitive": self.mutates_sensitive,
                "sensitive_vars": list(self.sensitive_vars)}


@dataclass
class GEdge:
    src: str
    dst: str
    kind: str
    guarded: bool = False           # traversal requires a role the attacker lacks
    note: str = ""

    def as_dict(self) -> dict:
        return {"src": self.src, "dst": self.dst, "kind": self.kind,
                "guarded": self.guarded, "note": self.note}


class ProtocolGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, GNode] = {}
        self.edges: list[GEdge] = []
        self.eoa = self._add(GNode("eoa", EOA, "unprivileged attacker (EOA)"))

    def _add(self, n: GNode) -> str:
        self.nodes[n.id] = n
        return n.id

    def add_node(self, kind: str, label: str, **kw) -> str:
        if kind not in NODE_KINDS:
            raise ValueError(f"unknown node kind {kind!r}")
        nid = kw.pop("node_id", None) or _nid(kind, label, kw.get("contract", ""),
                                              kw.get("function", ""))
        if nid not in self.nodes:
            self._add(GNode(nid, kind, label, **kw))
        return nid

    def add_edge(self, src: str, kind: str, dst: str, *, guarded: bool = False,
                 note: str = "") -> None:
        if kind not in EDGE_KINDS:
            raise ValueError(f"unknown edge kind {kind!r}")
        if src not in self.nodes or dst not in self.nodes:
            raise KeyError("edge endpoint is not a node")
        self.edges.append(GEdge(src, dst, kind, guarded, note))

    def out_edges(self, nid: str) -> list[GEdge]:
        return [e for e in self.edges if e.src == nid]

    def as_dict(self) -> dict:
        return {"nodes": [n.as_dict() for n in self.nodes.values()],
                "edges": [e.as_dict() for e in self.edges]}


def _nid(*parts: str) -> str:
    raw = "|".join(str(p) for p in parts)
    return "n-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


# --------------------------------------------------------------------------- #
# building the graph from Slither
# --------------------------------------------------------------------------- #

def _classify_contract(c) -> str:
    fns = {(f.name or "").lower() for f in c.functions}
    names = {(getattr(v, "name", "") or "").lower() for v in c.state_variables}
    if "upgradeto" in fns or "_implementation" in fns or "implementation" in names \
            or "_authorizeupgrade" in fns:
        return PROXY
    if any(h in fns for h in _ORACLE_HINT):
        return ORACLE
    if any(h in fns for h in _BRIDGE_HINT):
        return BRIDGE
    if any(h in fns for h in _GOV_HINT) and "execute" in fns:
        return GOVERNANCE
    if {"totalsupply"} & fns and ("_balances" in names or "balanceof" in fns):
        if any(h in fns for h in _VAULT_HINT):
            return VAULT
        return TOKEN
    if any(h in fns for h in _VAULT_HINT):
        return VAULT
    if any(h in fns for h in _POOL_HINT):
        return POOL
    return CONTRACT


def _sensitive_vars(c) -> set[str]:
    from src.rules import _shared
    out: set[str] = set()
    try:
        out |= {getattr(v, "name", "") for v in _shared.access_control_state_vars(c)}
    except Exception:  # noqa: BLE001
        pass
    for v in c.state_variables:
        nm = (getattr(v, "name", "") or "")
        low = nm.lower()
        if any(k in low for k in ("owner", "admin", "_balances", "totalsupply",
                                  "implementation", "role", "governance",
                                  "pendingowner", "authorized")):
            out.add(nm)
    return {x for x in out if x}


def _guarded(fn, contract) -> bool:
    from src.rules import _shared
    try:
        return _shared.constrains_msg_sender(fn, contract)
    except Exception:  # noqa: BLE001
        return False


def _writes(fn) -> set[str]:
    try:
        return {getattr(v, "name", "") for v in fn.all_state_variables_written()}
    except Exception:  # noqa: BLE001
        return set()


def _attacker_controlled_destination(ir, fn) -> bool:
    """True if the call target is something the attacker can set - a function
    parameter, or a non-constant state var with an unguarded writer."""
    dest = getattr(ir, "destination", None)
    if dest is None:
        return False
    try:
        params = {p.name for p in fn.parameters}
    except Exception:  # noqa: BLE001
        params = set()
    name = getattr(dest, "name", None)
    return bool(name and name in params)


def build_graph(slither_obj) -> ProtocolGraph:
    from slither.slithir.operations import (
        HighLevelCall, LowLevelCall, LibraryCall, InternalCall,
    )

    g = ProtocolGraph()
    contracts = list(getattr(slither_obj, "contracts_derived", slither_obj.contracts))

    # contract + function nodes
    fn_node: dict[tuple[str, str], str] = {}
    csens: dict[str, set[str]] = {}
    cnode: dict[str, str] = {}
    for c in contracts:
        kind = _classify_contract(c)
        cid = g.add_node(kind, c.name, contract=c.name)
        cnode[c.name] = cid
        csens[c.name] = _sensitive_vars(c)
        for fn in c.functions:
            if getattr(fn, "is_constructor", False) or not getattr(fn, "is_implemented", True):
                continue
            ext = fn.visibility in ("external", "public")
            wrote = _writes(fn)
            sens = tuple(sorted(wrote & csens[c.name]))
            fid = g.add_node(FUNCTION, f"{c.name}.{fn.name}", contract=c.name,
                             function=fn.name, external=ext,
                             guarded=_guarded(fn, c),
                             mutates_sensitive=bool(sens), sensitive_vars=sens)
            fn_node[(c.name, fn.name)] = fid
            if ext:
                node = g.nodes[fid]
                is_init = (fn.name or "").lower().startswith("initialize")
                kind_edge = INITIALIZE if is_init else CALL
                g.add_edge(g.eoa, kind_edge, fid, guarded=node.guarded,
                           note=("guard on msg.sender" if node.guarded else ""))
            # contract "contains" its function (for path readability)
            g.add_edge(cid, CALL, fid, note="declares")

    # inter-function edges from call IR
    by_name: dict[str, list] = {}
    for c in contracts:
        by_name.setdefault(c.name, [])
    for c in contracts:
        for fn in c.functions:
            src_fid = fn_node.get((c.name, fn.name))
            if src_fid is None:
                continue
            for node in getattr(fn, "nodes", []):
                for ir in node.irs:
                    _edge_from_ir(g, ir, fn, c, src_fid, fn_node, cnode,
                                  contracts, HighLevelCall, LowLevelCall,
                                  LibraryCall, InternalCall)
    return g


def _edge_from_ir(g, ir, fn, c, src_fid, fn_node, cnode, contracts,
                  HighLevelCall, LowLevelCall, LibraryCall, InternalCall) -> None:
    target = getattr(ir, "function", None)
    tname = getattr(ir, "function_name", None) or getattr(target, "name", None)

    if isinstance(ir, LowLevelCall):
        low = (str(tname) or "").lower()
        kind = DELEGATECALL if "delegate" in low else (
            STATICCALL if "static" in low else CALL)
        if _attacker_controlled_destination(ir, fn):
            g.add_edge(src_fid, CALLBACK, g.eoa,
                       note="external call to an attacker-supplied address "
                            "-> attacker regains control")
        return

    if isinstance(ir, (InternalCall, LibraryCall)):
        if isinstance(target, object) and getattr(target, "name", None):
            tc = getattr(getattr(target, "contract", None), "name", c.name)
            dst = fn_node.get((tc, target.name))
            if dst and dst != src_fid:
                g.add_edge(src_fid, CALL, dst, note="internal")
        return

    if isinstance(ir, HighLevelCall):
        # resolve to a concrete function node if the callee contract is in-unit
        tc = getattr(getattr(target, "contract", None), "name", None)
        if tc and target is not None and getattr(target, "name", None):
            dst = fn_node.get((tc, target.name))
            if dst is None:
                dst = g.add_node(CONTRACT, tc, contract=tc)
            g.add_edge(src_fid, CALL, dst,
                       note=f"calls {tc}.{getattr(target, 'name', '?')}")
            if _attacker_controlled_destination(ir, fn):
                g.add_edge(dst if g.nodes[dst].kind != FUNCTION else src_fid,
                           CALLBACK, g.eoa, note="callee is attacker-controlled")
        else:
            # unresolved external interface call - a synthetic sink, classified
            # by the method name where we can
            low = (str(tname) or "").lower()
            kind = (ORACLE if low in _ORACLE_HINT else
                    TOKEN if low in ("transfer", "transferfrom", "approve") else
                    CONTRACT)
            sink = g.add_node(kind, f"external:{tname}", function=str(tname))
            edge = (ORACLE_READ if kind == ORACLE else
                    TRANSFER if low in ("transfer", "transferfrom") else
                    APPROVE if low == "approve" else CALL)
            g.add_edge(src_fid, edge, sink, note="unresolved external call")
        return


# --------------------------------------------------------------------------- #
# reachability search
# --------------------------------------------------------------------------- #

@dataclass
class AttackPath:
    nodes: list[str]
    edges: list[GEdge]
    unprivileged: bool
    crosses_contracts: bool
    reaches: str                    # the sink node id

    @property
    def edge_kinds(self) -> list[str]:
        return [e.kind for e in self.edges]

    def render(self, graph: "ProtocolGraph") -> str:
        parts = []
        for i, nid in enumerate(self.nodes):
            parts.append(graph.nodes[nid].label)
            if i < len(self.edges):
                g = "*" if self.edges[i].guarded else ""
                parts.append(f" --{self.edges[i].kind}{g}--> ")
        tag = "UNPRIVILEGED" if self.unprivileged else "needs a role"
        xc = " (cross-contract)" if self.crosses_contracts else ""
        return f"[{tag}{xc}] " + "".join(parts)

    def as_dict(self) -> dict:
        return {"nodes": self.nodes, "edge_kinds": self.edge_kinds,
                "unprivileged": self.unprivileged,
                "crosses_contracts": self.crosses_contracts,
                "reaches": self.reaches}


def find_attack_paths(graph: ProtocolGraph, *, target_contract: str = "",
                      target_function: str = "", max_depth: int = 8,
                      max_paths: int = 25) -> list[AttackPath]:
    """BFS from the EOA over traversable edges to every sensitive sink (or to a
    specific target function if named). A path is `unprivileged` iff it
    traversed no guarded edge."""
    want_specific = bool(target_function)
    results: list[AttackPath] = []
    # queue items: (node_id, path_nodes, path_edges, hit_guard, contracts_seen)
    q: deque = deque()
    q.append((graph.eoa, [graph.eoa], [], False, set()))
    seen_states: set[tuple] = set()

    while q and len(results) < max_paths:
        nid, pnodes, pedges, hit_guard, cseen = q.popleft()
        if len(pnodes) > max_depth + 1:
            continue
        node = graph.nodes[nid]

        if node.kind == FUNCTION and len(pnodes) > 1:
            is_target = (not want_specific and node.mutates_sensitive) or (
                want_specific and node.contract == (target_contract or node.contract)
                and node.function == target_function)
            if is_target:
                results.append(AttackPath(
                    nodes=list(pnodes), edges=list(pedges),
                    unprivileged=not hit_guard,
                    crosses_contracts=len(cseen | {node.contract}) > 1,
                    reaches=nid))
                if want_specific:
                    continue

        for e in graph.out_edges(nid):
            if e.kind not in _TRAVERSABLE:
                continue
            if e.dst in pnodes:                 # simple-path only
                continue
            st = (e.dst, len(pnodes), hit_guard or e.guarded)
            if st in seen_states:
                continue
            seen_states.add(st)
            ncseen = set(cseen)
            dn = graph.nodes[e.dst]
            if dn.contract:
                ncseen.add(dn.contract)
            q.append((e.dst, pnodes + [e.dst], pedges + [e],
                      hit_guard or e.guarded, ncseen))

    results.sort(key=lambda p: (not p.unprivileged, len(p.nodes)))
    return results


def to_evidence_graph(paths: Iterable[AttackPath], graph: ProtocolGraph,
                      g: EG.EvidenceGraph) -> list[str]:
    ids: list[str] = []
    for i, p in enumerate(paths):
        nid = g.add_node(EG.ATTACK_PATH, p.render(graph),
                         established_by="nextgen.attackgraph",
                         data={"unprivileged": p.unprivileged,
                               "crosses_contracts": p.crosses_contracts,
                               "edge_kinds": p.edge_kinds,
                               "reaches": graph.nodes[p.reaches].label})
        ids.append(nid)
    return ids


def render_paths(paths: list[AttackPath], graph: ProtocolGraph) -> str:
    if not paths:
        return "ATTACK-PATH GRAPH\n=================\n\n  no path from an " \
               "unprivileged EOA reaches a sensitive sink"
    lines = ["ATTACK-PATH GRAPH", "=" * 17, ""]
    for i, p in enumerate(paths, 1):
        lines.append(f"  {i}. {p.render(graph)}")
    return "\n".join(lines)
