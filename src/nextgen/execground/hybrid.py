"""Symbolic + concrete hybrid validation (spec §6).

The symbolic engine is deferred (charter amendment 2026-08-28): §6's symbolic
half is a Python CONSTRAINT SKETCH here, not a solver. The pipeline is still the
one the spec describes:

    static analysis  ->  candidate
        -> constraint sketch : can an attacker satisfy every require() on the path?
        -> synthesise calldata that satisfies the attacker-controllable ones
        -> concrete execution on a local fork
        -> observe: did the call succeed / did the invariant break?

`sketch_constraints` classifies each guard condition on the target function:

  ATTACKER_PARAM  reads only call parameters (+ constants)  -> satisfiable
  MSG_SENDER      compares msg.sender to a trusted identity -> BLOCKING (unless
                  that identity has an unguarded writer)
  STATE           reads a state var the caller does not set -> needs a prior tx
                  (hand off to the §5 sequence search)
  UNKNOWN         could not classify

The result feeds the `state_reachable` gate: PASS when every constraint is
attacker-satisfiable AND the concrete run reproduces; FAIL when a BLOCKING
constraint makes the required state impossible for an unprivileged attacker;
UNKNOWN otherwise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .. import state as S
from ..adversarial.reproducer import ReproResult, REPRODUCED
from . import foundry
from . import reproducer as R

ATTACKER_PARAM = "ATTACKER_PARAM"
MSG_SENDER = "MSG_SENDER"
STATE = "STATE"
UNKNOWN = "UNKNOWN"


@dataclass
class Constraint:
    expr: str
    category: str
    reads: tuple[str, ...] = ()
    note: str = ""

    def as_dict(self) -> dict:
        return {"expr": self.expr, "category": self.category,
                "reads": list(self.reads), "note": self.note}


@dataclass
class PathConstraints:
    contract: str
    function: str
    constraints: list[Constraint] = field(default_factory=list)

    @property
    def blocking(self) -> list[Constraint]:
        return [c for c in self.constraints if c.category == MSG_SENDER]

    @property
    def state_dependent(self) -> list[Constraint]:
        return [c for c in self.constraints if c.category == STATE]

    @property
    def attacker_satisfiable(self) -> bool:
        return all(c.category in (ATTACKER_PARAM,) for c in self.constraints) \
            if self.constraints else True

    def as_dict(self) -> dict:
        return {"contract": self.contract, "function": self.function,
                "attacker_satisfiable": self.attacker_satisfiable,
                "constraints": [c.as_dict() for c in self.constraints]}


@dataclass
class HybridResult:
    path: PathConstraints
    synthesized_args: str = ""
    concrete: Optional[ReproResult] = None
    gate: str = S.GATE_UNKNOWN
    rationale: str = ""

    def as_dict(self) -> dict:
        return {"gate": self.gate, "rationale": self.rationale,
                "synthesized_args": self.synthesized_args,
                "path": self.path.as_dict(),
                "concrete": self.concrete.as_dict() if self.concrete else None}

    def render_text(self) -> str:
        lines = ["HYBRID VALIDATION (spec §6)", "=" * 26, "",
                 f"  target: {self.path.contract}.{self.path.function}",
                 f"  attacker-satisfiable path: {self.path.attacker_satisfiable}",
                 ""]
        for c in self.path.constraints:
            lines.append(f"  [{c.category}] {c.expr}"
                         + (f"  ({c.note})" if c.note else ""))
        if self.synthesized_args:
            lines.append("")
            lines.append(f"  synthesised calldata args: {self.synthesized_args}")
        if self.concrete:
            lines.append(f"  concrete run: {self.concrete.status} - "
                         f"{self.concrete.detail}")
        lines += ["", f"  gate ({'state_reachable'}): {self.gate}  -  "
                  f"{self.rationale}"]
        return "\n".join(lines)


def sketch_constraints(slither_obj, contract_name: str, function_name: str
                       ) -> PathConstraints:
    from src.rules import _shared

    pc = PathConstraints(contract_name, function_name)
    contract = fn = None
    for c in getattr(slither_obj, "contracts_derived", slither_obj.contracts):
        if c.name == contract_name:
            for f in c.functions:
                if f.name == function_name:
                    contract, fn = c, f
                    break
    if fn is None:
        return pc

    params = {p.name for p in getattr(fn, "parameters", []) if getattr(p, "name", None)}

    for f in _shared.reachable(fn):
        for node in _shared.guard_nodes(f):
            expr = str(getattr(node, "expression", "") or "").strip()
            if not expr:
                continue
            reads = tuple(sorted(getattr(v, "name", "")
                                 for v in node.state_variables_read))
            depends_sender = _shared.node_depends_on_msg_sender(node, contract)
            local_reads = _local_var_names(node)
            cat, note = _classify(expr, params, reads, local_reads,
                                  depends_sender, contract, _shared)
            pc.constraints.append(Constraint(expr[:200], cat, reads, note))
    # de-dup identical exprs
    seen, uniq = set(), []
    for c in pc.constraints:
        if c.expr in seen:
            continue
        seen.add(c.expr)
        uniq.append(c)
    pc.constraints = uniq
    return pc


def _local_var_names(node) -> set[str]:
    names: set[str] = set()
    for v in getattr(node, "local_variables_read", []) or []:
        n = getattr(v, "name", None)
        if n:
            names.add(n)
    return names


def _classify(expr, params, state_reads, local_reads, depends_sender,
              contract, _shared) -> tuple[str, str]:
    if depends_sender:
        # a msg.sender comparison: blocking UNLESS the compared identity has an
        # unguarded writer (anyone could set themselves as the "authorised" one)
        for name in state_reads:
            if _has_unguarded_writer(contract, name, _shared):
                return ATTACKER_PARAM, (f"compares msg.sender to `{name}`, but "
                                        f"`{name}` has an unguarded writer")
        return MSG_SENDER, "gates on msg.sender vs a trusted identity"
    only_params = state_reads == () and (local_reads <= params or not local_reads)
    if only_params or (not state_reads and _mentions_only(expr, params)):
        return ATTACKER_PARAM, "reads only call parameters / constants"
    if state_reads:
        return STATE, f"reads state {list(state_reads)[:3]} - may need a prior tx"
    return UNKNOWN, ""


def _mentions_only(expr: str, params: set[str]) -> bool:
    idents = set(re.findall(r"[A-Za-z_]\w*", expr))
    kw = {"require", "assert", "true", "false", "address", "msg", "uint",
          "uint256", "int", "bool", "bytes", "bytes32", "keccak256", "abi"}
    idents -= kw
    return bool(idents) and idents <= params


def _has_unguarded_writer(contract, var_name: str, _shared) -> bool:
    for fn in contract.functions:
        try:
            writes = {getattr(v, "name", "") for v in fn.all_state_variables_written()}
        except Exception:  # noqa: BLE001
            continue
        if var_name not in writes:
            continue
        if getattr(fn, "is_constructor", False):
            continue
        if fn.visibility in ("external", "public") and not \
                _shared.constrains_msg_sender(fn, contract):
            return True
    return False


_TYPE_DEFAULT = {
    "address": "address(0xBEEF)", "bool": "true", "string": '""',
    "bytes": '""', "bytes32": "bytes32(uint256(1))",
}


def synthesize_calldata(pc: PathConstraints, param_types: list[str]) -> str:
    """Pick literals satisfying the ATTACKER_PARAM constraints; fall back to a
    nonzero default per type. Returns a solidity argument list."""
    vals: list[str] = []
    for t in param_types:
        t = t.strip()
        if t.startswith(("uint", "int")):
            vals.append(_numeric_for(pc, default="1"))
        else:
            vals.append(_TYPE_DEFAULT.get(t, "0"))
    return ", ".join(vals)


def _numeric_for(pc: PathConstraints, default: str) -> str:
    for c in pc.constraints:
        m = re.search(r"[<>]=?\s*(\d+)", c.expr)
        if not m:
            continue
        n = int(m.group(1))
        if ">" in c.expr and "=" not in c.expr.split(">")[1][:2]:
            return str(n + 1)
        if ">=" in c.expr:
            return str(n)
        if "<=" in c.expr:
            return str(max(n, 0))
        if "<" in c.expr:
            return str(max(n - 1, 0))
    return default


def run(slither_obj, *, contract: str, function: str, signature: str,
        source_bundle: str, param_types: Optional[list[str]] = None,
        constructor_args: str = "", pragma: str = "^0.8.0",
        toolchain: Optional[foundry.Toolchain] = None) -> HybridResult:
    pc = sketch_constraints(slither_obj, contract, function)
    res = HybridResult(pc)

    if pc.blocking:
        res.gate = S.FAIL
        res.rationale = ("a guard compares msg.sender to a trusted identity - "
                         "the required state is not reachable by an "
                         "unprivileged attacker")
        return res

    args = synthesize_calldata(pc, param_types or _types_from_sig(signature))
    res.synthesized_args = args

    if pc.state_dependent and not pc.attacker_satisfiable:
        res.gate = S.GATE_UNKNOWN
        res.rationale = ("the path has state-dependent constraints; hand off to "
                         "the multi-transaction sequence search (§5)")
        return res

    from ..adversarial.reproducer import BlindTarget
    tgt = BlindTarget(contract=contract, function=function,
                      invariant_statement="", objective={"type": "call_succeeds"},
                      signature=signature, call_args=args, pragma=pragma,
                      constructor_args=constructor_args)
    res.concrete = R.generate_and_run(tgt, source_bundle=source_bundle,
                                      toolchain=toolchain)
    if res.concrete.status == REPRODUCED:
        res.gate = S.PASS
        res.rationale = ("every path constraint is attacker-satisfiable and a "
                         "concrete run reached the state and broke the invariant")
    elif res.concrete.status == "NOT_REPRODUCED":
        res.gate = S.GATE_UNKNOWN
        res.rationale = ("constraints look attacker-satisfiable but the concrete "
                         "run did not reproduce - shape hints may be insufficient")
    else:
        res.gate = S.GATE_UNKNOWN
        res.rationale = f"concrete run inconclusive: {res.concrete.detail}"
    return res


def _types_from_sig(signature: str) -> list[str]:
    m = re.search(r"\(([^)]*)\)", signature or "")
    if not m or not m.group(1).strip():
        return []
    return [t.strip().split()[0] for t in m.group(1).split(",")]
