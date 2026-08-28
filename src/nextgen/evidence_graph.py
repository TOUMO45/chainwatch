"""The security evidence graph (spec §18).

A finding is not stored as prose. It is stored as a graph of typed evidence
nodes and the relationships between them, so that **every statement in the final
report traces back to the thing that produced it** - a git walk, a compiler
run, a fork execution, an independent validator - or is explicitly marked as an
LLM hypothesis, which is *not* evidence.

    FINDING
      |
      +-- DERIVED_FROM --> COMMIT ------ PRODUCED_BY --> "history.py"
      +-- DERIVED_FROM --> INVARIANT --- VIOLATED_BY --> REPRODUCER
      +-- DERIVED_FROM --> DEPLOYMENT -- MATCHES ------> BYTECODE
      |
      +-- SUPPORTED_BY --> VALIDATION (skeptic: failed to disprove)

The graph answers two questions the classic report cannot:

  * `trace(node)` - what chain of established facts leads here?
  * `unsupported(...)` - which claims rest on an LLM hypothesis with no
    deterministic node supporting them? Those must never reach a report as
    fact (spec §22).

Pure data + pure functions. No I/O, no model, no chain access. Serialises to a
plain dict for the corpus and the report layer.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# --------------------------------------------------------------------------- #
# Node kinds. Mirrors the spec §18 diagram plus what later phases produce.
# --------------------------------------------------------------------------- #

FINDING = "FINDING"
COMMIT = "COMMIT"
CHANGED_LINE = "CHANGED_LINE"
VULNERABLE_IMPL = "VULNERABLE_IMPL"
BUILD_ENV = "BUILD_ENV"
INVARIANT = "INVARIANT"
SECURITY_PROPERTY = "SECURITY_PROPERTY"
ATTACK_PATH = "ATTACK_PATH"
STATE_PRECONDITION = "STATE_PRECONDITION"
COMPENSATING_CONTROL = "COMPENSATING_CONTROL"
REPRODUCER = "REPRODUCER"
INVARIANT_VIOLATION = "INVARIANT_VIOLATION"
DEPLOYMENT = "DEPLOYMENT"
BYTECODE = "BYTECODE"
ECONOMIC_MODEL = "ECONOMIC_MODEL"
VALIDATION = "VALIDATION"
RESULT = "RESULT"

NODE_KINDS: frozenset[str] = frozenset({
    FINDING, COMMIT, CHANGED_LINE, VULNERABLE_IMPL, BUILD_ENV, INVARIANT,
    SECURITY_PROPERTY, ATTACK_PATH, STATE_PRECONDITION, COMPENSATING_CONTROL,
    REPRODUCER, INVARIANT_VIOLATION, DEPLOYMENT, BYTECODE, ECONOMIC_MODEL,
    VALIDATION, RESULT,
})

# --------------------------------------------------------------------------- #
# Edge relations. Directed: (src) --relation--> (dst).
# --------------------------------------------------------------------------- #

DERIVED_FROM = "DERIVED_FROM"
PRODUCED_BY = "PRODUCED_BY"
SUPPORTS = "SUPPORTS"
CONTRADICTS = "CONTRADICTS"
MATCHES = "MATCHES"
MISMATCHES = "MISMATCHES"
VIOLATES = "VIOLATES"
REACHES = "REACHES"
GUARDS = "GUARDS"
REFUTES = "REFUTES"

RELATIONS: frozenset[str] = frozenset({
    DERIVED_FROM, PRODUCED_BY, SUPPORTS, CONTRADICTS, MATCHES, MISMATCHES,
    VIOLATES, REACHES, GUARDS, REFUTES,
})

# --------------------------------------------------------------------------- #
# How a node's content was established. This is the trust label, and it is the
# whole point of the graph: a node established by "llm-hypothesis" is a lead,
# never a fact. Only the deterministic producers below may back a report claim.
# --------------------------------------------------------------------------- #

DETERMINISTIC_PRODUCERS: frozenset[str] = frozenset({
    "history.py", "rules", "verdict.py", "liveness.py", "verified.py",
    "exploit_proof.py", "exposure.py", "anchor.py",
    "nextgen.timemachine", "nextgen.invariants", "nextgen.attackgraph",
    "nextgen.provenance", "nextgen.deployment", "nextgen.compensating",
    "nextgen.execground", "nextgen.benchmark",
    "foundry", "anvil", "solc", "slither",
})

LLM_HYPOTHESIS = "llm-hypothesis"


@dataclass
class EvidenceNode:
    """One established (or hypothesised) fact.

    `established_by` - a member of DETERMINISTIC_PRODUCERS, or LLM_HYPOTHESIS.
                      Anything else is rejected: an unlabelled node is not
                      allowed to masquerade as evidence.
    `data`          - the machine-checkable payload (a commit hash, a bytecode
                      digest, a fork trace id, ...). Keep it small and literal.
    """

    id: str
    kind: str
    label: str
    established_by: str
    data: dict = field(default_factory=dict)
    at: float = field(default_factory=time.time)

    def is_evidence(self) -> bool:
        return self.established_by in DETERMINISTIC_PRODUCERS

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label,
                "established_by": self.established_by, "data": self.data,
                "at": self.at}


@dataclass
class EvidenceEdge:
    src: str
    dst: str
    relation: str

    def as_dict(self) -> dict:
        return {"src": self.src, "dst": self.dst, "relation": self.relation}


class EvidenceGraph:
    """A small directed multigraph. Deterministic, serialisable, no dependencies."""

    def __init__(self) -> None:
        self._nodes: dict[str, EvidenceNode] = {}
        self._edges: list[EvidenceEdge] = []

    # -- construction ---------------------------------------------------- #

    def add_node(self, kind: str, label: str, *, established_by: str,
                 data: Optional[dict] = None, node_id: Optional[str] = None) -> str:
        if kind not in NODE_KINDS:
            raise ValueError(f"unknown node kind {kind!r}")
        if established_by not in DETERMINISTIC_PRODUCERS and established_by != LLM_HYPOTHESIS:
            raise ValueError(
                f"established_by={established_by!r} is neither a known "
                f"deterministic producer nor {LLM_HYPOTHESIS!r}")
        nid = node_id or self._auto_id(kind, label, data or {})
        self._nodes[nid] = EvidenceNode(nid, kind, label, established_by,
                                        dict(data or {}))
        return nid

    def add_edge(self, src: str, relation: str, dst: str) -> None:
        if relation not in RELATIONS:
            raise ValueError(f"unknown relation {relation!r}")
        for end in (src, dst):
            if end not in self._nodes:
                raise KeyError(f"edge endpoint {end!r} is not a node")
        self._edges.append(EvidenceEdge(src, dst, relation))

    @staticmethod
    def _auto_id(kind: str, label: str, data: dict) -> str:
        raw = f"{kind}|{label}|{sorted(data.items())}"
        return f"{kind.lower()}-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"

    # -- reads --------------------------------------------------------------- #

    def node(self, nid: str) -> Optional[EvidenceNode]:
        return self._nodes.get(nid)

    def nodes(self, kind: Optional[str] = None) -> list[EvidenceNode]:
        return [n for n in self._nodes.values() if kind is None or n.kind == kind]

    def edges(self, *, src: Optional[str] = None, dst: Optional[str] = None,
              relation: Optional[str] = None) -> list[EvidenceEdge]:
        out = self._edges
        if src is not None:
            out = [e for e in out if e.src == src]
        if dst is not None:
            out = [e for e in out if e.dst == dst]
        if relation is not None:
            out = [e for e in out if e.relation == relation]
        return list(out)

    def neighbors(self, nid: str, *, relation: Optional[str] = None) -> list[str]:
        return [e.dst for e in self.edges(src=nid, relation=relation)]

    def trace(self, nid: str, *, relations: Iterable[str] = (DERIVED_FROM, MATCHES,
                                                             VIOLATES, REACHES,
                                                             PRODUCED_BY, SUPPORTS)
              ) -> list[list[str]]:
        """Every path of `relations` edges from `nid` to a source node (one with
        no outgoing edge of those relations). The chain that backs this claim.
        """
        rels = set(relations)
        paths: list[list[str]] = []

        def walk(cur: str, acc: list[str], seen: frozenset[str]) -> None:
            nxt = [e for e in self._edges if e.src == cur and e.relation in rels]
            if not nxt:
                paths.append(acc)
                return
            for e in nxt:
                if e.dst in seen:            # cycle guard
                    paths.append(acc + [f"(cycle -> {e.dst})"])
                    continue
                walk(e.dst, acc + [f"{e.relation} -> {e.dst}"],
                     seen | {e.dst})

        walk(nid, [nid], frozenset({nid}))
        return paths

    def unsupported(self) -> list[EvidenceNode]:
        """LLM-hypothesis nodes with no SUPPORTS edge from a deterministic node.

        These are leads that have not been grounded. A report may mention them
        as open questions; it may not state them as fact (spec §22).
        """
        backed: set[str] = set()
        for e in self._edges:
            if e.relation == SUPPORTS:
                src = self._nodes.get(e.src)
                if src and src.is_evidence():
                    backed.add(e.dst)
        return [n for n in self._nodes.values()
                if n.established_by == LLM_HYPOTHESIS and n.id not in backed]

    def contradictions(self) -> list[tuple[str, str]]:
        """(src, dst) pairs joined by CONTRADICTS / MISMATCHES / REFUTES - the
        Skeptic's edges. A finding with an un-answered contradiction is not
        clean."""
        bad = {CONTRADICTS, MISMATCHES, REFUTES}
        return [(e.src, e.dst) for e in self._edges if e.relation in bad]

    # -- serialisation ----------------------------------------------------- #

    def as_dict(self) -> dict:
        return {"nodes": [n.as_dict() for n in self._nodes.values()],
                "edges": [e.as_dict() for e in self._edges]}

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceGraph":
        g = cls()
        for n in d.get("nodes", []):
            g._nodes[n["id"]] = EvidenceNode(
                n["id"], n["kind"], n["label"], n["established_by"],
                dict(n.get("data") or {}), n.get("at", time.time()))
        for e in d.get("edges", []):
            g._edges.append(EvidenceEdge(e["src"], e["dst"], e["relation"]))
        return g

    def render_text(self) -> str:
        """A flat, deterministic listing for a report appendix."""
        lines = ["EVIDENCE GRAPH", "=" * 14, ""]
        for n in sorted(self._nodes.values(), key=lambda x: (x.kind, x.id)):
            tag = "evidence" if n.is_evidence() else "HYPOTHESIS (not evidence)"
            lines.append(f"[{n.kind}] {n.id}")
            lines.append(f"    {n.label}")
            lines.append(f"    established by: {n.established_by}  ({tag})")
            if n.data:
                lines.append(f"    data: {n.data}")
        lines.append("")
        for e in self._edges:
            lines.append(f"  {e.src}  --{e.relation}-->  {e.dst}")
        loose = self.unsupported()
        if loose:
            lines += ["", "UNSUPPORTED HYPOTHESES (must not appear as fact):"]
            lines += [f"  - {n.id}: {n.label}" for n in loose]
        return "\n".join(lines)
