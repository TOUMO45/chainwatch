"""Phase 7 - counterfactual sequence mutation (spec section 10).

The Twin (`twin/mutate.py`) mutates REAL historical traces. Deep Hunt has no
trace to start from - it mutates the GENERATED `CandidateSequence`s from Phase 4.
The mutation KINDS are the same idea (actor / amount-boundary / repetition /
reorder / timing / authorization / oracle-state); the carrier is a variant
`CandidateSequence`, so every mutation runs through the exact same Foundry
harness (`execground/sequences` -> Phase 9 reproducer) as an unmutated one.

Mutations whose touched state intersects a target invariant's variables are
weighted up - "prioritise mutations that affect an invariant" (spec section 10).
Timing / oracle-state mutations only fire when the model actually has an oracle
dependency or the invariant is an oracle-assumption one; the extra objective
keys (`warp_seconds`, `oracle_manipulation`) are read by the Phase 9 reproducer.
Nothing here executes or decides.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

from src.nextgen.execground.sequences import CandidateSequence, TxStep
from . import invariants as INV
from . import protocolmodel as PM

# mutation kinds (names align with twin.model where the concept matches)
M_ACTOR = "ACTOR_SUBSTITUTION"
M_AMOUNT = "AMOUNT_BOUNDARY"
M_REPETITION = "REPETITION"
M_REORDER = "REORDER"
M_TIMING = "TIMING"
M_ORACLE = "ORACLE_STATE"
M_AUTH = "AUTHORIZATION_SWAP"

MUTATION_KINDS = frozenset({M_ACTOR, M_AMOUNT, M_REPETITION, M_REORDER, M_TIMING,
                            M_ORACLE, M_AUTH})

# 0, 1, 2, uint256 max  (spec section 10: "test near 0 / 1 / max / threshold+-1")
_MAX_U256 = str(2 ** 256 - 1)
_BOUNDARY_AMOUNTS = ("0", "1", "2", _MAX_U256)


@dataclass
class MutatedSequence:
    kind: str
    statement: str
    sequence: CandidateSequence
    weight: float = 1.0
    touched_invariant: str = ""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "statement": self.statement,
                "weight": self.weight, "touched_invariant": self.touched_invariant,
                "sequence": self.sequence.as_dict()}


def _split_args(s: str) -> list[str]:
    s = (s or "").strip()
    if not s:
        return []
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def mutate_sequence(seq: CandidateSequence, model: PM.ProtocolModel,
                    invariants: list, *,
                    target_invariant=None) -> list[MutatedSequence]:
    if not seq.steps:
        return []
    obj = seq.steps[-1]
    stmt = seq.invariant_statement
    out: list[MutatedSequence] = []

    def _seq(steps, objective=None):
        return CandidateSequence(list(steps), objective or dict(seq.objective),
                                 stmt)

    # -- ACTOR: run the objective from a different unprivileged actor --------
    for actor in ("victim",):
        steps = list(seq.steps[:-1]) + [replace(obj, caller=actor)]
        out.append(MutatedSequence(
            M_ACTOR, f"objective call from '{actor}' instead of 'attacker'",
            _seq(steps)))

    # -- AMOUNT: sweep boundary values through each integer arg of the objective
    fm = model.function(obj.contract, obj.function)
    if fm is not None and fm.params:
        base = _split_args(obj.args)
        for pi, p in enumerate(fm.params):
            t = (p.type or "").split()[0]
            if not (t.startswith(("uint", "int"))):
                continue
            for bv in _BOUNDARY_AMOUNTS:
                args = list(base) + ["0"] * max(0, pi + 1 - len(base))
                args[pi] = bv
                steps = list(seq.steps[:-1]) + [
                    replace(obj, args=", ".join(args))]
                out.append(MutatedSequence(
                    M_AMOUNT, f"{obj.function} arg #{pi} ({t}) -> "
                    f"{bv if len(bv) < 12 else 'max uint256'}", _seq(steps)))

    # -- REPETITION: call the objective twice back to back -----------------
    out.append(MutatedSequence(
        M_REPETITION, f"{obj.function}() called twice in one transaction",
        _seq(list(seq.steps) + [replace(obj)])))

    # -- REORDER: swap the first two setup steps -------------------------
    if len(seq.steps) >= 3:
        s = list(seq.steps)
        s[0], s[1] = s[1], s[0]
        out.append(MutatedSequence(M_REORDER, "the two setup steps reordered",
                                   _seq(s)))

    # -- TIMING / ORACLE: only when an oracle actually feeds this ----------
    recipe = ((target_invariant.predicate or {}).get("test_recipe", {})
              if target_invariant is not None else {})
    oracle_relevant = (recipe.get("type") == INV.OBJ_ORACLE
                       or any(d.kind in (PM.DEP_ORACLE, PM.DEP_AMM)
                              for d in model.dependencies))
    if oracle_relevant:
        o1 = dict(seq.objective)
        o1["warp_seconds"] = 86_400
        out.append(MutatedSequence(
            M_TIMING, "advance the fork 1 day before the objective "
            "(stale oracle round)", _seq(seq.steps, o1)))
        o2 = dict(seq.objective)
        o2["oracle_manipulation"] = ("same-block flash swap on the priced pair "
                                     "before the objective")
        out.append(MutatedSequence(
            M_ORACLE, "manipulate the spot price feeding the objective",
            _seq(seq.steps, o2)))

    # -- AUTHORIZATION_SWAP: differential - does the deployer path behave
    #    differently? (a caller-identity dependence the attacker version hides)
    out.append(MutatedSequence(
        M_AUTH, "objective call from the deployer (differential auth check)",
        _seq(list(seq.steps[:-1]) + [replace(obj, caller="deployer")])))

    # -- weight: bump mutations that touch a target invariant's variables ---
    inv_vars = set(getattr(target_invariant, "variables", ()) or ())
    for m in out:
        touched: set[str] = set()
        for st in m.sequence.steps:
            f2 = model.function(st.contract, st.function)
            if f2:
                touched |= set(f2.writes)
        if inv_vars and (inv_vars & touched):
            m.weight = 2.0
            m.touched_invariant = getattr(target_invariant, "id", "")

    out.sort(key=lambda m: (-m.weight, m.kind))
    return out


def mutate_all(seqs: list[CandidateSequence], model: PM.ProtocolModel,
               invariants: list, *, budget: int = 60) -> list[MutatedSequence]:
    inv_by_stmt = {i.statement: i for i in invariants}
    out: list[MutatedSequence] = []
    seen: set[tuple] = set()
    for s in seqs:
        ti = inv_by_stmt.get(s.invariant_statement)
        for m in mutate_sequence(s, model, invariants, target_invariant=ti):
            key = (m.kind, tuple((st.function, st.args, st.caller)
                                 for st in m.sequence.steps),
                   repr(sorted((m.sequence.objective or {}).items(),
                               key=lambda kv: str(kv[0]))))
            if key in seen:
                continue
            seen.add(key)
            out.append(m)
            if len(out) >= budget:
                return out
    return out


def summarize(muts: list[MutatedSequence]) -> str:
    if not muts:
        return "COUNTERFACTUAL MUTATIONS\n" + "=" * 23 + "\n\n  (none)"
    by_kind: dict[str, int] = {}
    for m in muts:
        by_kind[m.kind] = by_kind.get(m.kind, 0) + 1
    lines = ["COUNTERFACTUAL MUTATIONS", "=" * 23, "",
             f"  {len(muts)} mutation(s): "
             + ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items()))]
    for m in muts[:10]:
        chain = " -> ".join(st.function for st in m.sequence.steps)
        lines.append(f"  [{m.kind}] (w{m.weight}) {m.statement}  ::  {chain}")
    return "\n".join(lines)
