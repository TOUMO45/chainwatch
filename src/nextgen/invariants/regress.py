"""The invariant regression engine (spec §3).

Given two versions' VALIDATED invariant sets, find the invariants that held in
the old version and are gone or weakened in the new one - and, for each, state
the concrete state an exploit would have to reach. That target becomes the
objective a reproducer tries to satisfy in a later phase; it is not, on its
own, a finding.

    old: "mint() requires MINTER_ROLE"      (VALIDATED)
    new: "mint() has no authorization"      (absent)
    ->  InvariantRegression(kind=ACCESS_CONTROL, type=REMOVED,
           search_target = "an unprivileged caller's mint() call succeeds")

Only invariants that were `usable` (VALIDATED / USED) in the OLD set are
considered - a lead that was never validated cannot "regress".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import model as M

REMOVED = "REMOVED"
WEAKENED = "WEAKENED"


@dataclass
class SearchTarget:
    """The concrete state to look for. `objective` is structured so a later
    phase can drive a fork search from it without re-parsing the prose."""

    description: str
    objective: dict
    preconditions: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"description": self.description, "objective": self.objective,
                "preconditions": list(self.preconditions)}


@dataclass
class InvariantRegression:
    invariant_id: str
    kind: str
    statement: str
    regression_type: str               # REMOVED | WEAKENED
    contract: str
    functions: tuple[str, ...]
    old_form: Optional[dict]
    new_form: Optional[dict]
    search_target: SearchTarget
    note: str = ""

    def as_dict(self) -> dict:
        return {"invariant_id": self.invariant_id, "kind": self.kind,
                "statement": self.statement,
                "regression_type": self.regression_type,
                "contract": self.contract, "functions": list(self.functions),
                "old_form": self.old_form, "new_form": self.new_form,
                "search_target": self.search_target.as_dict(), "note": self.note}


def diff_invariants(old: M.InvariantSet,
                    new: M.InvariantSet) -> list[InvariantRegression]:
    new_index = new.index_by_subject()
    out: list[InvariantRegression] = []

    for inv in old.usable():
        counterpart = new_index.get(inv.subject_key)
        if counterpart is None or not counterpart.usable:
            out.append(_regression(inv, counterpart, REMOVED,
                                   "present and validated in the old version, "
                                   + ("absent in the new version"
                                      if counterpart is None
                                      else f"present but only {counterpart.status} "
                                           "in the new version")))
            continue
        why = _weakened(inv, counterpart)
        if why:
            out.append(_regression(inv, counterpart, WEAKENED, why))

    return out


def _regression(old_inv: M.CandidateInvariant,
                new_inv: Optional[M.CandidateInvariant],
                kind: str, note: str) -> InvariantRegression:
    return InvariantRegression(
        invariant_id=old_inv.id, kind=old_inv.kind, statement=old_inv.statement,
        regression_type=kind, contract=old_inv.contract,
        functions=tuple(old_inv.functions),
        old_form=old_inv.predicate, new_form=new_inv.predicate if new_inv else None,
        search_target=_target_for(kind, old_inv, new_inv), note=note)


def _weakened(old_inv: M.CandidateInvariant,
              new_inv: M.CandidateInvariant) -> Optional[str]:
    """A same-subject invariant that still holds but constrains LESS."""
    op, npred = old_inv.predicate or {}, new_inv.predicate or {}

    if old_inv.source in (M.SOURCE_GUARD, M.SOURCE_ROLE):
        og = set(op.get("guards") or op.get("roles") or [])
        ng = set(npred.get("guards") or npred.get("roles") or [])
        if og and (not ng or ng < og):
            return (f"authorization constraints reduced from {sorted(og)} to "
                    f"{sorted(ng) or 'none'}")
        return None

    if old_inv.source == M.SOURCE_INIT:
        if op.get("cardinality") == "once" and npred.get("cardinality") not in (
                "once", None):
            return (f"initialisation cardinality relaxed: "
                    f"{op.get('cardinality')} -> {npred.get('cardinality')}")
        return None

    if old_inv.source in (M.SOURCE_SUPPLY, M.SOURCE_ACCOUNTING, M.SOURCE_SOLVENCY):
        ob, nb = op.get("bound"), npred.get("bound")
        if ob and ob != nb:
            return f"accounting bound changed: {ob!r} -> {(nb or 'none')!r}"
        if op.get("paths_update_supply") and not npred.get("paths_update_supply"):
            return "a mint/burn path no longer updates total supply in lockstep"
        return None

    if old_inv.source == M.SOURCE_UPGRADE:
        oa, na = op.get("authorized_by"), npred.get("authorized_by")
        if oa and oa != na:
            return f"upgrade authorisation changed: {oa!r} -> {(na or 'none')!r}"
        return None

    # generic: a predicate key disappeared
    lost = set(op) - set(npred)
    if lost:
        return f"predicate lost constraint(s): {sorted(lost)}"
    return None


def _target_for(regression_type: str, old_inv: M.CandidateInvariant,
                new_inv: Optional[M.CandidateInvariant]) -> SearchTarget:
    c, fns = old_inv.contract, list(old_inv.functions)
    fn = fns[0] if fns else "<function>"

    if old_inv.kind == M.ACCESS_CONTROL:
        return SearchTarget(
            description=f"an unprivileged EOA's call to {c}.{fn}() succeeds "
                        f"(state changes, no revert)",
            objective={"type": "call_succeeds", "contract": c, "function": fn,
                       "caller": "unprivileged"},
            preconditions=[f"the caller holds none of "
                           f"{sorted((old_inv.predicate or {}).get('roles') or (old_inv.predicate or {}).get('guards') or ['the removed guard'])}"])

    if old_inv.kind == M.STATE_MACHINE and old_inv.source == M.SOURCE_INIT:
        return SearchTarget(
            description=f"{c}.{fn}() can be called a second time after it has "
                        f"already been initialised",
            objective={"type": "reinit", "contract": c, "function": fn},
            preconditions=[f"{c} is already initialised"])

    if old_inv.kind in (M.ACCOUNTING, M.ECONOMIC):
        rel = (old_inv.predicate or {}).get("relation") \
            or (old_inv.predicate or {}).get("bound") \
            or old_inv.statement
        return SearchTarget(
            description=f"a reachable state where the relation `{rel}` is false",
            objective={"type": "state_relation_violated", "contract": c,
                       "relation": rel},
            preconditions=["attacker starts from a realistic funded position"])

    if old_inv.kind == M.DEPLOYMENT and old_inv.source == M.SOURCE_UPGRADE:
        return SearchTarget(
            description=f"a non-governance caller upgrades {c}'s implementation",
            objective={"type": "unauthorized_upgrade", "contract": c},
            preconditions=["caller is not the prior upgrade authority"])

    return SearchTarget(
        description=f"a reachable state that violates: {old_inv.statement}",
        objective={"type": "invariant_violated", "contract": c,
                   "statement": old_inv.statement},
        preconditions=[])
