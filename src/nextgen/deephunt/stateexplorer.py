"""Phase 4 - prioritized, bounded state exploration (spec sections 9, 21).

Deep Hunt stops thinking `function -> input` and starts thinking
`state -> action -> state' -> action -> ... -> invariant`. This module turns the
`ProtocolModel` + the discovered invariants into a SMALL, RANKED set of
candidate transaction sequences worth executing - never a blind enumeration.

Ranking (spec section 21): a target function's own risk score, plus a bump for
the strength of the invariant it threatens and for an unguarded state mutation.
Setup prefixes come from the model's state-machine relations and the
`deposit / approve / mint / stake` family, risk-ranked.

Reuses `execground/sequences` wholesale - `TxStep`, `CandidateSequence`,
`enumerate_sequences`, and `minimize` (delta-debugging, objective step never
dropped) - so a sequence planned here runs through the exact same Foundry
harness the regression pipeline already uses. Deterministic without the LLM;
the optional `use_llm` hook only appends proposals whose every step names a real
function in the model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from src.nextgen.execground.sequences import (  # noqa: F401 - minimize re-exported
    CandidateSequence, TxStep, enumerate_sequences, minimize,
)
from . import invariants as INV
from . import llm_hypotheses
from . import protocolmodel as PM

_SETUP_HINTS = ("deposit", "approve", "mint", "stake", "addliquidity", "supply",
                "wrap", "provide", "lock")

_STRENGTH_BUMP = {"strong": 6, "medium": 3, "weak": 1}


@dataclass
class ExplorationTarget:
    invariant_id: str
    contract: str
    function: str
    objective: dict
    priority: int
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"invariant_id": self.invariant_id, "contract": self.contract,
                "function": self.function, "objective": self.objective,
                "priority": self.priority, "reasons": list(self.reasons)}


# --------------------------------------------------------------------------- #
# ranking
# --------------------------------------------------------------------------- #

def rank_targets(model: PM.ProtocolModel,
                 invs: list) -> list[ExplorationTarget]:
    fn_by_qual = {f"{f.contract}.{f.name}": f for f in model.all_functions()}
    rows: list[ExplorationTarget] = []
    for inv in invs:
        if inv.status == INV.IM.REJECTED:
            continue
        recipe = (inv.predicate or {}).get("test_recipe") or {}
        c = recipe.get("contract") or inv.contract
        fns = list(inv.functions) or (
            [recipe["function"]] if recipe.get("function") else [])
        for fn in fns:
            if not fn:
                continue
            fm = fn_by_qual.get(f"{c}.{fn}") or model.function(c, fn)
            base = fm.risk if fm else 0
            reasons = [f"threatens invariant {inv.source} ({inv.strength})"]
            bump = _STRENGTH_BUMP.get(inv.strength, 2)
            if fm and fm.risk:
                reasons.append(f"risk {fm.risk}: "
                               + ", ".join(fm.risk_factors[:3]))
            if fm and not fm.access_controlled and fm.state_changing:
                bump += 3
                reasons.append("no caller-identity guard on a state mutation")
            if fm and not fm.external:
                bump -= 4                       # internal - harder to drive
            rows.append(ExplorationTarget(
                invariant_id=inv.id, contract=c, function=fn, objective=recipe,
                priority=base + bump, reasons=tuple(reasons)))

    best: dict[tuple, ExplorationTarget] = {}
    for t in rows:
        k = (t.contract, t.function, t.objective.get("type"))
        if k not in best or t.priority > best[k].priority:
            best[k] = t
    return sorted(best.values(),
                  key=lambda t: (-t.priority, t.contract, t.function))


# --------------------------------------------------------------------------- #
# sequence planning
# --------------------------------------------------------------------------- #

def plan_sequences(model: PM.ProtocolModel, invs: list, *, budget: int = 24,
                   use_llm: bool = False) -> list[CandidateSequence]:
    if not getattr(model, "compiled", False):
        return []
    targets = rank_targets(model, invs)
    stmt_by_id = {i.id: i.statement for i in invs}
    out: list[CandidateSequence] = []
    seen: set[tuple] = set()

    for t in targets:
        if len(out) >= budget:
            break
        fm = model.function(t.contract, t.function)
        sig = fm.signature if fm else f"{t.function}()"
        call_args = _default_args(fm) if fm else ""
        setups = _setup_functions(model, t.contract, exclude=t.function)
        cands = enumerate_sequences(
            contract=t.contract, function=t.function, signature=sig,
            call_args=call_args, objective=t.objective or {
                "type": "call_succeeds", "contract": t.contract,
                "function": t.function},
            invariant_statement=stmt_by_id.get(t.invariant_id, ""),
            setup_functions=setups, max_len=3)
        for c in cands:
            key = (t.contract, tuple((s.function, s.args) for s in c.steps),
                   c.objective.get("type"))
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
            if len(out) >= budget:
                break

    if use_llm and len(out) < budget:
        out.extend(_llm_sequences(model, invs, budget - len(out)))
    return out[:budget]


def _setup_functions(model: PM.ProtocolModel, target_contract: str, *,
                     exclude: str) -> list[tuple[str, str, str]]:
    """[(name, signature, args)] setup steps to try as prefixes, risk-ranked,
    drawn from state-machine relations first then the deposit/approve family."""
    ordered: list = []
    seen: set[str] = set()

    rel_fns = {r.function.split(".", 1)[-1]
               for r in model.relations
               if r.function.startswith(target_contract + ".")
               and r.kind in (PM.REL_DEPOSIT_SHARES, PM.REL_STAKE_REWARDS,
                              PM.REL_BORROW_DEBT)}
    for f in model.ranked_functions():
        if f.contract != target_contract or f.name == exclude:
            continue
        low = f.name.lower()
        if f.name in rel_fns or any(h in low for h in _SETUP_HINTS):
            if f.name in seen:
                continue
            seen.add(f.name)
            ordered.append((f.name, f.signature, _default_args(f)))
    return ordered[:4]


def _default_args(fm) -> str:
    if fm is None or not fm.params:
        return ""
    parts: list[str] = []
    for p in fm.params:
        t = (p.type or "").split()[0].split("[")[0]
        if t.startswith(("uint", "int")):
            parts.append("1000000000000000000")          # 1e18
        elif t == "address":
            parts.append("address(0xA11CE)")
        elif t == "bool":
            parts.append("true")
        elif t.startswith("bytes32"):
            parts.append("bytes32(0)")
        elif t.startswith("bytes"):
            parts.append('hex""')
        elif t == "string":
            parts.append('""')
        else:
            parts.append("0")
    return ", ".join(parts)


def _llm_sequences(model: PM.ProtocolModel, invs: list,
                   n: int) -> list[CandidateSequence]:
    if n <= 0:
        return []
    real = {f.name: f for f in model.all_functions()}
    inv_stmt = invs[0].statement if invs else ""
    out: list[CandidateSequence] = []
    for item in llm_hypotheses.propose_sequences(model, inv_stmt):
        names = [str(s).split(".")[-1] for s in item.get("steps", [])]
        if not names or not all(nm in real for nm in names):
            continue
        steps = []
        for k, nm in enumerate(names):
            fm = real[nm]
            steps.append(TxStep(fm.contract, nm, fm.signature, "attacker",
                                _default_args(fm),
                                must_succeed=(k < len(names) - 1)))
        out.append(CandidateSequence(
            steps, {"type": "invariant_violated"}, inv_stmt))
        if len(out) >= n:
            break
    return out


# --------------------------------------------------------------------------- #

def summarize(seqs: Iterable[CandidateSequence]) -> str:
    seqs = list(seqs)
    if not seqs:
        return "STATE EXPLORATION\n================\n\n  (no sequences planned)"
    lines = ["STATE EXPLORATION", "=" * 16, "",
             f"  {len(seqs)} candidate sequence(s)"]
    for i, s in enumerate(seqs[:12], 1):
        chain = " -> ".join(st.function for st in s.steps)
        lines.append(f"  {i:>2}. [{s.objective.get('type', '?')}] {chain}")
    return "\n".join(lines)
