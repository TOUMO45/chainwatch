"""The INFERRED -> TESTED -> VALIDATED discipline (spec §2).

An inferred invariant is a lead. `validate` re-checks it against the compiled
code and promotes it one step at a time:

  INFERRED -> TESTED       the structural pattern still holds at this version
  TESTED   -> VALIDATED    ...and nothing in the same contract contradicts it

Anything that fails the re-check is REJECTED (terminal). A contradiction found
at the TESTED->VALIDATED step does NOT reject the invariant - it records the
contradiction and leaves the invariant at TESTED (not usable), because a
contradiction is itself a signal worth carrying forward, not noise to discard.

Phase 2 scope: the re-checks are same-contract and structural. Cross-contract
contradiction hunting (an unguarded entry point in ANOTHER contract that
reaches the protected state) is Rule 10 / attack-graph territory and is wired
in a later phase.
"""

from __future__ import annotations

from typing import Optional

from . import model as M


def _find_fn(contract, name: str):
    for fn in contract.functions:
        if fn.name == name:
            return fn
    return None


def _find_contract(slither_obj, name: str):
    for c in getattr(slither_obj, "contracts_derived", slither_obj.contracts):
        if c.name == name:
            return c
    return None


def _writes(fn) -> set:
    try:
        return {getattr(v, "canonical_name", getattr(v, "name", ""))
                for v in fn.all_state_variables_written()}
    except Exception:  # noqa: BLE001
        return set()


def validate(inv: M.CandidateInvariant, slither_obj) -> None:
    """Advance / reject `inv` in place against `slither_obj`."""
    if inv.status not in (M.INFERRED, M.TESTED):
        return
    from src.rules import _shared

    contract = _find_contract(slither_obj, inv.contract)
    if contract is None:
        inv.reject("contract not present at this version")
        return
    fn = _find_fn(contract, inv.functions[0]) if inv.functions else None

    if inv.source in (M.SOURCE_GUARD, M.SOURCE_ROLE):
        if fn is None:
            inv.reject("guarded function not present at this version")
            return
        if not _shared.constrains_msg_sender(fn, contract):
            inv.reject("no msg.sender guard reachable from the function anymore")
            return
        _step(inv, M.TESTED, "msg.sender guard still in force")
        contra = _sibling_unguarded(contract, fn, _shared)
        if contra:
            inv.contradiction = contra
            inv.notes.append(f"held at TESTED: {contra}")
            return
        _step(inv, M.VALIDATED, "no unguarded sibling writes the same state")
        return

    if inv.source == M.SOURCE_INIT:
        if fn is None or not _shared.has_init_guard(fn):
            inv.reject("one-shot init guard not present anymore")
            return
        _step(inv, M.TESTED, "one-shot init guard still present")
        others = [f for f in contract.functions
                  if f is not fn and (f.name or "").lower().startswith("initialize")
                  and not _shared.has_init_guard(f)]
        if others:
            inv.contradiction = (f"sibling initializer(s) without a one-shot "
                                 f"guard: {sorted(f.name for f in others)}")
            inv.notes.append(f"held at TESTED: {inv.contradiction}")
            return
        _step(inv, M.VALIDATED, "no unguarded sibling initializer")
        return

    if inv.source == M.SOURCE_UPGRADE:
        if fn is None:
            inv.reject("upgrade function not present anymore")
            return
        guards = _guard_names(fn, contract, _shared)
        if not guards:
            # An upgrade hook with no msg.sender/role guard - whether an
            # `external upgradeTo` or an empty `internal _authorizeUpgrade`
            # (the classic UUPS footgun) - does not establish an authorisation
            # invariant. It is REJECTED, not held.
            inv.reject("no authorisation guard on the upgrade path at this "
                       "version")
            return
        _step(inv, M.TESTED, f"upgrade path authorised by {guards}")
        _step(inv, M.VALIDATED, "authorisation present on the upgrade path")
        return

    if inv.source in (M.SOURCE_SUPPLY, M.SOURCE_ACCOUNTING):
        _step(inv, M.TESTED, "ERC20 supply/balance shape still present")
        if (inv.predicate or {}).get("paths_update_supply"):
            _step(inv, M.VALIDATED, "mint/burn update supply and balances "
                                    "together")
        else:
            inv.contradiction = ("a mint/burn path does not update total supply "
                                 "in lockstep with balances")
            inv.notes.append(f"held at TESTED: {inv.contradiction}")
        return

    if inv.source == M.SOURCE_REQUIRE:
        expr = (inv.predicate or {}).get("expr", "")
        if fn is None:
            inv.reject("function not present anymore")
            return
        still = any(expr[:60] in str(getattr(n, "expression", "") or "")
                    for n in getattr(fn, "nodes", [])
                    if n.contains_require_or_assert())
        if not still:
            inv.reject("the require/assert condition is gone")
            return
        _step(inv, M.TESTED, "condition still checked")
        _step(inv, M.VALIDATED, "low-strength code invariant re-confirmed")
        return

    # unknown source: leave INFERRED, note it
    inv.notes.append("no validator for this source; stays INFERRED")


def validate_all(iset: M.InvariantSet, slither_obj) -> M.InvariantSet:
    for inv in iset.invariants:
        try:
            validate(inv, slither_obj)
        except Exception as exc:  # noqa: BLE001
            inv.notes.append(f"validation error, left as-is: {type(exc).__name__}")
    return iset


def validate_all_from_source(iset: M.InvariantSet, text: str) -> M.InvariantSet:
    from .._solc import slither_for_source
    return validate_all(iset, slither_for_source(text))


# --------------------------------------------------------------------------- #

def _step(inv: M.CandidateInvariant, to: str, note: str) -> None:
    order = (M.INFERRED, M.TESTED, M.VALIDATED, M.USED)
    while order.index(inv.status) < order.index(to):
        inv.advance(order[order.index(inv.status) + 1], note=note)


def _guard_names(fn, contract, _shared) -> list[str]:
    out: set[str] = set()
    for m in getattr(fn, "modifiers", []):
        n = getattr(m, "name", None)
        if n:
            out.add(n)
    try:
        for node in _shared.guard_nodes(fn):
            if _shared.node_depends_on_msg_sender(node, contract):
                out.add("inline:msg.sender")
    except Exception:  # noqa: BLE001
        pass
    return sorted(out)


def _sibling_unguarded(contract, fn, _shared) -> Optional[str]:
    """A different external, state-changing function on the same contract that
    writes some of the same state and is NOT msg.sender-guarded - the 'only
    authorized' claim is already violated by it."""
    target = _writes(fn)
    if not target:
        return None
    for other in contract.functions:
        if other is fn or other.visibility not in ("external", "public"):
            continue
        if getattr(other, "is_constructor", False):
            continue
        if not (_writes(other) & target):
            continue
        if _shared.constrains_msg_sender(other, contract):
            continue
        return (f"{contract.name}.{other.name}() writes the same state "
                f"({sorted(_writes(other) & target)[:3]}) without a msg.sender "
                f"guard")
    return None
