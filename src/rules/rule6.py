"""RULE 6 - SC05: Input Validation regression.

Trigger (RULES.md): a require/revert/custom-error guard on a function PARAMETER
present at N-1 is absent at N. Guards on `msg.sender` are Rule 1's (access
control), not Rule 6's, and are deferred.

All analysis is semantic (Slither AST/IR + contract-level data dependency), never
text or name matching. A parameter is "guarded" when some guard node reachable
from the function - its own body, its modifiers, or a function it always calls -
has a condition data-dependent on that parameter and NOT on msg.sender. This one
predicate makes every exclusion fall out:

  6.1 check moved into a modifier on the same function   -> the modifier's guard
      still depends on the parameter (reachable set includes modifiers), so the
      parameter stays guarded at N.
  6.2 check enforced downstream in an always-called fn    -> the callee's guard is
      data-dependent on the caller's parameter (contract-level dependency
      propagates through the internal call), so the parameter stays guarded at N.
  6.3 the parameter was removed entirely                  -> the function's
      signature (full_name) changed, so the N-1 function has no N match and is
      never compared.
  6.5 check replaced by an equivalent custom error         -> `if (cond) revert E()`
      is a conditional guard node with the same parameter dependency, so the
      parameter stays guarded at N (semantic, not text).
  6.7 test/mock path                                       -> segment-based
      source_path match, quiet.
  Rule 1 boundary: a guard on msg.sender is discarded from the parameter-guard
      set (node_depends_on_msg_sender), so removing it never fires Rule 6; Rule 1
      handles it (N6-06 defers, Rule 1 fires via also_fires).

Highest-severity sub-case (RULES.md): removal of a slippage/minAmountOut or
deadline check on a swap path surfaces as an ordinary parameter-guard loss on a
state-changing function and fires CONFIRMED (P6-02); no special-casing needed.

DESIGN-L1 (LIMITATIONS.md): before.sol and after.sol are separate Slither
compilations, so Parameter/Variable objects are distinct instances across
commits. The per-commit comparison is therefore done on parameter NAMES (stable
strings), never on Slither object identity - `guarded_b - guarded_a` is a set
difference over names. All within-commit data-dependency work uses same-
compilation objects only.

Exclusion 6.4 (type change makes the check redundant) and 6.6 (enforced by the
type system / validated struct at the call boundary) are not yet implemented - no
fixture exercises them, and shipping an untested exclusion trades a false
positive for a silent false negative. Tracked for when a fixture exists.
"""

from pathlib import Path

from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.declarations import Function, Structure
from slither.core.solidity_types import UserDefinedType
from slither.core.variables.local_variable import LocalVariable

from ._shared import (
    accept_finding,
    emit,
    external_call_return_taint,
    guard_checks_call_return,
    guard_nodes,
    is_test_path_segments,
    node_depends_on_msg_sender,
    parse,
    reachable,
)
from .rule1 import _candidate_map, _writes_state_or_moves_value

RULE_ID = "6"


def _is_storage_struct_pointer_local(v) -> bool:
    """True iff `v` is a local storage pointer to a struct — the ERC-7201
    namespaced-storage `$` shape (assigned via `assembly { $.slot := SLOT }`).

    RC-OZ5-R6 (LIMITATIONS.md): Slither's `is_dependent(local_ptr, param,
    contract)` over-approximates to True for such locals, so a rate-limit
    guard that reads only `block.timestamp` + `$.namespacedMember` is falsely
    treated as parameter-validating. This predicate gates the `is_dependent`
    fallback in `_param_guarded_names` so a sole hit through a storage-struct
    pointer is not counted; a direct read of the parameter (or of a plain
    state variable) is unaffected and still counts.

    Rule-6-specific: no other rule feeds parameters into `is_dependent`
    today. If one does, promote to `_shared.py` at that point.
    """
    if not isinstance(v, LocalVariable):
        return False
    if not getattr(v, "is_storage", False):
        return False
    vtype = getattr(v, "type", None)
    return isinstance(vtype, UserDefinedType) and isinstance(vtype.type, Structure)


def _param_guarded_names(fn: Function, contract) -> set:
    """Names of fn's parameters that have a parameter-dependent guard reachable
    from fn (its body, modifiers, and always-called internal callees), excluding
    guards that depend on msg.sender (those are Rule 1's).

    Returns NAMES (strings), not Parameter objects, so the result can be compared
    across the before/after compilations without hitting the cross-commit object
    identity trap (DESIGN-L1).
    """
    params = list(fn.parameters)
    if not params:
        return set()
    guarded: set = set()
    for f in reachable(fn):
        taint = external_call_return_taint(f)
        for node in guard_nodes(f):
            # Rule 1 boundary: a guard constraining msg.sender is access control,
            # not input validation - it contributes no parameter guard here.
            if node_depends_on_msg_sender(node, contract):
                continue
            # Rule 5 boundary: a guard checking an external-call RETURN value is
            # SC06 (unchecked external call), not input validation, even though
            # the return may be data-dependent on a parameter (the call args).
            if guard_checks_call_return(node, taint):
                continue
            reads = node.variables_read
            for p in params:
                if p.name in guarded:
                    continue
                # Direct read of the parameter always counts.
                if any(v == p for v in reads):
                    guarded.add(p.name)
                    continue
                # Fallback: any read data-dependent on the parameter (covers
                # modifier args, downstream call args, and a state var the
                # parameter was just written into - e.g. the set-once
                # `require(vault == address(0))` after `vault = _vault`).
                # RC-OZ5-R6: an is_dependent hit through a storage-struct
                # pointer local (ERC-7201 `$`) is a Slither over-approximation
                # and is NOT accepted on its own — such a local must be paired
                # with a real read path (the parameter itself, or a plain
                # state variable that is_dependent trusts).
                for v in reads:
                    if _is_storage_struct_pointer_local(v):
                        continue
                    if is_dependent(v, p, contract):
                        guarded.add(p.name)
                        break
    return guarded


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 6 fires on this before/after pair."""
    # Exclusion 6.7: test/mock path, matched on repo-relative source_path by
    # whole segments (shared with Rules 1.6 / 2a.2.8 / 2b). A fixture that
    # declares no source_path falls back to after_path, whose fixtures-r6/...
    # segments match no marker.
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)

    before_map = _candidate_map(before)
    after_map = _candidate_map(after)

    for key, (fn_b, contract_b) in before_map.items():
        # Same function must still exist at N (matched by contract + signature).
        # A signature change - e.g. the parameter removed entirely - means no
        # match here, which is exactly exclusion 6.3.
        if key not in after_map:
            continue
        fn_a, contract_a = after_map[key]

        # Only worth protecting if the function still writes state / moves value
        # at N; a check on a parameter of a read-only function guards nothing.
        if not _writes_state_or_moves_value(fn_a):
            continue

        guarded_b = _param_guarded_names(fn_b, contract_b)
        if not guarded_b:
            continue
        guarded_a = _param_guarded_names(fn_a, contract_a)

        # DESIGN-L1: diff by parameter NAME (strings from two separate
        # compilations), never by Slither object identity.
        if guarded_b - guarded_a:
            # DESIGN-L2: only attribute to a declaration in a file actually
            # changed in this commit.
            if not accept_finding(fn_a, case_meta):
                continue
            lost = sorted(guarded_b - guarded_a)
            emit(
                case_meta, RULE_ID, decl=fn_a,
                detail=(
                    f"{contract_a.name}.{fn_a.full_name} validated parameter(s) "
                    f"{', '.join(lost)} at commit N-1 and no longer does at commit N, "
                    f"while still writing state or moving value"
                ),
                evidence={
                    "owasp": "SC05", "unguarded_parameters": lost,
                    "guarded_before": sorted(guarded_b),
                    "guarded_after": sorted(guarded_a),
                    "visibility_after": fn_a.visibility,
                    "writes_state_after": _writes_state_or_moves_value(fn_a),
                },
            )
            return True

    return False
