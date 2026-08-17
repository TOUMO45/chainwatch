"""Shared control-flow / ordering foundation for the reentrancy rules (SC08).

Everything here is Slither IR/CFG based - no regex on source text, no modifier
name matching (CHARTER.md rule 4, RULES.md Rule 2 note). Rule 2a uses it now;
Rule 2b (CEI ordering broken between commits) will reuse the same primitives:

  * external_call_nodes / has_external_call - IR-level external-call detection
  * state_writes_after_calls / cei_correct   - CFG ordering of state writes
                                               relative to each external call
  * all_call_dests_trusted_immutable         - exclusion 2.3 support
  * own_guard_state_reads                     - direct- vs read-only-reentrancy
  * has_setclear_mutex                        - structural nonReentrant / manual
                                               mutex detection (guard present?)

Ordering note: state_writes_after_calls walks the forward CFG (node.sons) from
each external-call node, so branches are handled, not just straight-line code.
A write reachable from a call ONLY through a loop back-edge is a known ambiguity
(the same write may also precede the call on the first iteration); the current
fixtures are loop-free and 2b will refine this. This is deliberately CFG-based,
not a source-line comparison.
"""

from collections import defaultdict

from slither.core.declarations import Function, SolidityVariable
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Assignment,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Send,
    Transfer,
)
from slither.slithir.variables import Constant, ReferenceVariable

from ._shared import guard_nodes, reachable

# Low-level value/data calls plus typed high-level calls. LibraryCall is a
# HighLevelCall subclass but targets same-codebase library code reached by an
# internal jump/delegatecall an attacker cannot supply, so it is NOT an external
# re-entry vector (RULES.md 2.4 spirit) and is excluded below.
_CALL_OPS = (LowLevelCall, Send, Transfer, HighLevelCall)


def _dest_origin(ir):
    """Resolve a call IR's destination to its underlying variable/origin."""
    dest = getattr(ir, "destination", None)
    if isinstance(dest, ReferenceVariable):
        return dest.points_to_origin
    return dest


def is_external_call_ir(ir) -> bool:
    """True iff `ir` is an external call an attacker's contract could be the
    callee of: any low-level .call/.send/.transfer, or a typed high-level call
    to an address other than this contract. Library calls are excluded."""
    if isinstance(ir, LibraryCall):
        return False
    if isinstance(ir, (LowLevelCall, Send, Transfer)):
        return True
    if isinstance(ir, HighLevelCall):
        origin = _dest_origin(ir)
        # A call dispatched to this very contract is not an outward call.
        if isinstance(origin, SolidityVariable) and str(origin) == "this":
            return False
        return True
    return False


def external_call_nodes(fn: Function) -> list:
    """[(node, ir)] for each external call in fn's OWN body, in CFG node order."""
    out = []
    for node in fn.nodes:
        for ir in node.irs:
            if is_external_call_ir(ir):
                out.append((node, ir))
                break
    return out


def has_external_call(fn: Function) -> bool:
    return bool(external_call_nodes(fn))


def _forward_reachable(start_nodes) -> set:
    """All nodes reachable by following CFG successors (node.sons) from the
    successors of each start node - i.e. strictly after the start node."""
    seen: set = set()
    stack = []
    for n in start_nodes:
        stack.extend(n.sons)
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(n.sons)
    return seen


def state_writes_after_calls(fn: Function) -> set:
    """State variables written at a node that is strictly after some external
    call on the forward CFG. Empty when there are no external calls."""
    call_nodes = [node for node, _ in external_call_nodes(fn)]
    if not call_nodes:
        return set()
    after = _forward_reachable(call_nodes)
    out: set = set()
    for node in after:
        out.update(node.state_variables_written)
    return out


def after_call_writes_resolved(fn: Function, _seen: set | None = None) -> set:
    """`state_writes_after_calls`, plus the writes fn DELEGATES to.

    `state_writes_after_calls` is body-local: it walks fn's own CFG and never
    enters an internal call. For a function whose body IS a delegation -
    `registry.sync(); super.refresh();` - it returns the EMPTY set, and callers
    then read that emptiness as a fact about ordering. It is not: there are no
    writes to HAVE an ordering. That single confusion produced two findings in
    opposite directions - RC-INLINE1 (rule 2b fired on a refactor) and
    RC-INLINE2 (rule 2a stayed silent on a real violation).

    Slither resolves `super.X()` to its target: the call is an `InternalCall`
    whose `.function` is the real `Function`. Verified against the IR before
    this was written.

    TWO CASES, and collapsing them is the trap:

      1. The internal call is forward-reachable from an external call in fn.
         The callee therefore RUNS after that call, so EVERY write it makes is
         after a call, whatever its own internal ordering is.
      2. Otherwise, ordering is decided inside the callee, and the same
         question recurses into it.

    Case 2 is what keeps `fixtures-r2a-inline/negative/N2ai-01` quiet - a
    delegation that precedes the caller's own external call, to a parent that
    writes before its own. A resolver that unconditionally counted every write
    of every callee would fire there and be wrong.

    Lives here, beside its siblings, rather than in one rule module: both rule
    2a (`cei_correct`) and rule 2b need the identical fact, and rule 2a cannot
    import rule 2b - rule 2b already imports rule 2a, so that edge would be a
    cycle. Duplicating this much subtle CFG logic in two modules invites the
    copies to drift.
    """
    if _seen is None:
        _seen = set()
    if fn in _seen:
        return set()          # recursion guard: mutual/self internal calls
    _seen.add(fn)

    out = set(state_writes_after_calls(fn))

    call_nodes = [node for node, _ in external_call_nodes(fn)]
    after_nodes = _forward_reachable(call_nodes) if call_nodes else set()

    for node in fn.nodes:
        for ir in node.irs:
            if not isinstance(ir, InternalCall):
                continue
            callee = getattr(ir, "function", None)
            if not isinstance(callee, Function) or callee in _seen:
                continue
            if node in after_nodes:
                for reached in reachable(callee):
                    out.update(reached.state_variables_written)
            else:
                out.update(after_call_writes_resolved(callee, _seen))
    return out


def cei_correct(fn: Function) -> bool:
    """Exclusion 2.2: no state write occurs after any external call - i.e. every
    state write the function makes precedes every external call. Vacuously true
    when the function makes no external call (2.1 handles that separately).

    RC-INLINE2: this asks `after_call_writes_resolved`, not the body-local
    version. A function that delegates its body to a parent with a real CEI
    violation has an EMPTY local after-call write set, and answering from that
    returned "provably correct" for a function that is provably nothing of the
    sort - a SILENT MISS, the dangerous direction. Locked by
    `fixtures-r2a-inline/positive/P2ai-01`.

    Deliberately NOT "False whenever an internal call exists": that trades a
    silent miss for a false-positive flood and is locked against by
    `fixtures-r2a-inline/negative/N2ai-02`, where the delegated parent writes
    no state at all and CEI really is correct.
    """
    if not has_external_call(fn):
        return True
    return not after_call_writes_resolved(fn)


def all_call_dests_trusted_immutable(fn: Function) -> bool:
    """Exclusion 2.3: every external call's destination resolves to an
    immutable/constant state variable (a trusted address fixed at construction),
    so no attacker-controlled callee remains."""
    calls = external_call_nodes(fn)
    if not calls:
        return False
    for _node, ir in calls:
        origin = _dest_origin(ir)
        if not (
            isinstance(origin, StateVariable)
            and (origin.is_immutable or origin.is_constant)
        ):
            return False
    return True


def own_guard_state_reads(fn: Function) -> set:
    """State variables read directly in fn's OWN guard nodes (require/if/assert).
    Used to tell a directly-reentrant function (a var checked in its own guard is
    written after the call, so re-entry bypasses the check -> CONFIRMED) from a
    read-only case (the after-call writes feed only an external view -> CANDIDATE).
    """
    out: set = set()
    for node in fn.nodes:
        if node.is_conditional(include_loop=False) or node.contains_require_or_assert():
            out.update(node.state_variables_read)
    return out


def _const_value_key(rvalue):
    """A hashable identity for a compile-time-constant rvalue, or None.

    Two forms both count as compile-time constants: a literal `Constant`
    (a manual mutex's `locked = true/false`) and a `constant`-declared state
    variable (OZ ReentrancyGuard's `_status = _ENTERED / _NOT_ENTERED`, which
    Slither keeps as a StateVariable reference, NOT an inlined Constant - see
    the IR check that drove this design)."""
    if isinstance(rvalue, Constant):
        return ("const", rvalue.value)
    if isinstance(rvalue, StateVariable) and rvalue.is_constant:
        return ("cvar", rvalue.canonical_name)
    return None


def _gated_const_assigns(fn: Function) -> tuple[set, dict]:
    """(state vars read directly in a guard node, {state var: set of distinct
    compile-time-constant values assigned to it}) over fn's reachable scope
    (its body + modifiers + their internal calls)."""
    reach = reachable(fn)
    gated: set = set()
    for f in reach:
        for node in guard_nodes(f):
            gated.update(node.state_variables_read)
    const_assigns: dict = defaultdict(set)
    for f in reach:
        for node in f.nodes:
            for ir in node.irs:
                if not isinstance(ir, Assignment):
                    continue
                lv = ir.lvalue
                origin = (
                    lv.points_to_origin if isinstance(lv, ReferenceVariable) else lv
                )
                if not isinstance(origin, StateVariable):
                    continue
                key = _const_value_key(getattr(ir, "rvalue", None))
                if key is not None:
                    const_assigns[origin].add(key)
    return gated, const_assigns


def _has_oneshot_init_gate(fn: Function) -> bool:
    """True iff `fn` carries a one-shot init/one-time gate: a gated storage flag
    written to a SINGLE compile-time constant (monotonic close - it can pass only
    once and never reopens). OZ's `initializer` sets `_initialized = 1` and gates
    on it, so this matches an initializer; it does NOT match a reentrancy mutex,
    whose gated flag toggles between two constants and so reopens.

    This is the discriminator that lets has_setclear_mutex exclude OZ's
    initializer (whose `_initializing` bool DOES toggle true/false and would
    otherwise look like a mutex) without excluding a hand-rolled `bool locked`
    lock (which the existing has_init_guard heuristic wrongly swallowed, because
    `locked` is gated and written to constants just like an init flag)."""
    gated, const_assigns = _gated_const_assigns(fn)
    return any(len(const_assigns.get(v, ())) == 1 for v in gated)


def has_setclear_mutex(fn: Function) -> bool:
    """True iff `fn` is protected by a set-then-clear storage mutex - either
    OpenZeppelin's `nonReentrant` modifier or a hand-rolled `bool locked`
    lock - detected structurally, never by name.

    Signature: a storage variable that is (a) read directly in a guard node and
    (b) assigned at least two DISTINCT compile-time-constant values across fn's
    reachable scope. A two-state lock reopens (locked -> unlocked), which is
    exactly two distinct constants on the gated variable; nonReentrant's
    `_status` toggles _ENTERED/_NOT_ENTERED, the manual mutex toggles true/false.
    Both OZ constants (`_ENTERED` etc.) and bool literals count as compile-time
    constants (see _const_value_key).

    Constructors and one-shot init gates are excluded first: an initializer
    monotonically closes and is Rule 3b's territory, so its guard loss must never
    be reported here as a reentrancy regression.
    """
    if not isinstance(fn, Function):
        return False
    if fn.is_constructor or _has_oneshot_init_gate(fn):
        return False
    gated, const_assigns = _gated_const_assigns(fn)
    return any(len(const_assigns.get(v, ())) >= 2 for v in gated)
