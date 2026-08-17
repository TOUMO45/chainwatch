"""RULE 2b - SC08: Reentrancy CEI ordering broken between commits.

Trigger (RULES.md Rule 2, sub-rule 2b): at commit N-1 every state write to a
variable the function reads preceded every external call; at commit N at least
one such write moved to AFTER an external call. This is a REGRESSION in ordering
- the change between commits - not a pre-existing broken state.

All ordering analysis is reused from _cfg.py (the shared foundation built for
2a); nothing here re-implements write-vs-call ordering. The 2b signal is the
DIFFERENCE between the two commits' orderings:

    moved = state_writes_after_calls(N) - state_writes_after_calls(N-1)

A variable in `moved` went from before-every-call at N-1 to after-a-call at N.
A variable after the call in BOTH commits is in both sets, cancels out, and is
NOT a regression (N2b-02).

BOUNDARY WITH 2a (agreed, enforced): 2a has priority. If the guard status also
changed in this commit (a set-then-clear mutex present at N-1 and absent at N,
or vice-versa), 2b defers so the single regression is reported once, by 2a
(N2b-01). Detected structurally via has_setclear_mutex at each commit.

Verdict routing (same three-verdict model as 2a, so the scorer's existing
FIRE / CANDIDATE / quiet handling applies unchanged):
  * moved var is read in the function's OWN guard  -> directly reentrant,
    re-entry bypasses the check                     -> True  (CONFIRMED)
  * moved var read only by a repo view/pure fn      -> read-only reentrancy,
    2.10 (cannot prove a third party reads it)       -> "candidate"
  * moved var not read in any exploitable path       -> 2.9 no exploitable
    (not a guard var, not read by a view)            -> quiet

Exclusions handled:
  2.8  test/mock path (segment-based source_path)          -> quiet
  2.9  moved var unread by the function and by any view     -> quiet
  2.10 moved var read only by a view (read-only reentrancy) -> CANDIDATE
  2a-priority boundary: guard status changed this commit    -> defer to 2a

Known limitation (documented, precision-safe): a moved var read back only by a
DIFFERENT state-changing function (neither this function's guard nor a view) is
currently routed to quiet under 2.9. Extending the re-entry-path read set to all
external entry points is a later refinement; erring toward quiet keeps precision
1.00 (RULES.md: misses acceptable, false alarms are not). No current fixture
exercises that shape.
"""

from pathlib import Path

from slither.core.declarations import Function
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Binary,
    BinaryType,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    SolidityCall,
)

from ._cfg import (
    after_call_writes_resolved,
    has_external_call,
    has_setclear_mutex,
    own_guard_state_reads,
    state_writes_after_calls,
)
from ._shared import (
    MSG_SENDER,
    accept_finding,
    emit,
    guard_nodes,
    is_test_path_segments,
    parse,
    reachable,
)
from .rule2a import _candidate_map, _reads_by_repo_view

RULE_ID = "2b"


_ADMIN_CMP_OPS = (BinaryType.EQUAL, BinaryType.NOT_EQUAL)
_CALL_OPS = (HighLevelCall, InternalCall, LibraryCall, SolidityCall)


def _returns_bool(ir) -> bool:
    """True iff this call's sole return value is a bool - the signature of an
    authority PREDICATE (`hasRole`, `isOperator`, `canCall`) as opposed to a
    value LOOKUP (`balanceOf`, `allowance`) that happens to take an address."""
    fn = getattr(ir, "function", None)
    returns = getattr(fn, "return_type", None) if fn is not None else None
    if not returns:
        return False
    return len(returns) == 1 and str(returns[0]) == "bool"


def _authority_call_lvalues(fn) -> set:
    """lvalues of calls in `fn` that ask an authority whether msg.sender may act:
    the call takes msg.sender as an argument AND answers with a bool.

    The bool requirement is load-bearing, not cosmetic. `balanceOf(msg.sender)`
    also passes msg.sender to a call whose result reaches a guard, but it
    constrains HOW MUCH the caller may take rather than WHETHER this caller is
    authorised. Accepting it would silence genuine CEI regressions on ordinary
    anyone-callable functions (fixture P2b-role-01 measures exactly that).
    """
    out: set = set()
    for node in fn.nodes:
        for ir in node.irs:
            if not isinstance(ir, _CALL_OPS) or ir.lvalue is None:
                continue
            args = list(getattr(ir, "arguments", []) or [])
            if any(a == MSG_SENDER for a in args) and _returns_bool(ir):
                out.add(ir.lvalue)
    return out


def _admin_gated(fn) -> bool:
    """True iff fn is gated on the CALLER'S AUTHORITY, in either form Solidity
    commonly uses:

      1. identity equality - `msg.sender == owner` / `!= admin`, i.e. a
         require/if comparing msg.sender against an address held in state; or
      2. authority predicate - `acl.hasRole(ROLE, msg.sender)`, a call taking
         msg.sender and returning bool whose result gates the function.

    RC-4 / RC-ROLE (Rule 2b): the 2b threat model is a hostile external caller
    who re-enters during a callback (module docstring). A function only the
    admin can enter has no such caller - the admin is the sole re-entry vector
    and re-entering from the same admin does not exploit the ordering. Suppress
    direct-reentrancy fires there; the read-only (2.10) path is unaffected.

    Form 2 was added after the PHASE 5 walker measured Reserve's
    Upgrade4_2_0.castSpell (commit 92ff272f) still firing: it is governance-only
    but gates via `main.hasRole(MAIN_OWNER_ROLE, msg.sender)`, which form 1
    cannot see. The STEP-4 fixture used the equality form and so passed while
    the real-world case did not - a fixture-fidelity gap now locked by
    fixtures-r2b-role/N2b-role-01.

    Neither form matches a guard that merely INDEXES by msg.sender
    (`owed[msg.sender] > 0`): there msg.sender sits inside an Index op, not as a
    direct operand of the equality, and the looked-up value is numeric rather
    than a bool authority verdict.
    """
    for f in reachable(fn):
        authority = _authority_call_lvalues(f)
        for node in guard_nodes(f):
            for ir in node.irs:
                # Form 1: msg.sender == <state address>
                if isinstance(ir, Binary) and ir.type in _ADMIN_CMP_OPS:
                    reads = list(getattr(ir, "read", []))
                    if any(r == MSG_SENDER for r in reads) and any(
                        isinstance(r, StateVariable) for r in reads
                    ):
                        return True
                # Form 2: guard consumes an authority predicate's bool verdict.
                if any(r in authority for r in getattr(ir, "read", [])):
                    return True
    return False


def run(before_path: Path, after_path: Path, case_meta: dict):
    """Returns True (fire), "candidate" (read-only, 2.10), or False (quiet)."""
    # Exclusion 2.8: test/mock path, matched on repo-relative source_path by
    # whole segments (shared with Rule 1.6 / 2a.2.8). A fixture that declares no
    # source_path falls back to after_path, whose fixtures-r2b/... segments match
    # no marker.
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)

    before_map = _candidate_map(before)
    after_map = _candidate_map(after)

    for key, (fn_b, _contract_b) in before_map.items():
        # Same function must still exist at N (matched by contract + signature).
        if key not in after_map:
            continue
        fn_a, contract_a = after_map[key]

        # No external call at N means no call to order writes against (2.1
        # territory; there is nothing for 2b to reason about).
        if not has_external_call(fn_a):
            continue

        # 2a-priority boundary: if the guard status changed this commit, defer.
        # A mutex present at N-1 and absent at N is a 2a finding (guard removed);
        # 2b must not also fire on the same regression (N2b-01).
        if has_setclear_mutex(fn_b) != has_setclear_mutex(fn_a):
            continue

        # Ordering at each commit, straight from the shared foundation. The two
        # sets come from two SEPARATE Slither compilations (before vs after), so
        # their StateVariable objects are distinct instances and cannot be
        # compared by identity - diff by canonical_name, a stable cross-commit
        # key. `moved` keeps the AFTER-commit objects so the downstream guard /
        # view checks (also after-commit) intersect correctly.
        # RC-INLINE1: both sides go through the delegation-resolving version, so
        # a body that delegates at N-1 is compared against what it actually
        # does, not against the empty set its own body happens to contain.
        after_at_n1_names = {v.canonical_name for v in after_call_writes_resolved(fn_b)}
        after_at_n = after_call_writes_resolved(fn_a)
        # Variables that went from before-every-call (N-1) to after-a-call (N).
        moved = {v for v in after_at_n if v.canonical_name not in after_at_n1_names}
        if not moved:
            # No write crossed the call between commits. Covers N2b-02 (already
            # after the call at N-1, so present in both sets and cancelled).
            continue

        # DESIGN-L2: only attribute a fire to a declaration in a file actually
        # changed in this commit.
        if not accept_finding(fn_a, case_meta):
            continue

        # Directly reentrant: a variable this function checks in its OWN guard is
        # now written after the call, so a re-entrant call reads stale state and
        # bypasses the check (P2b-01, P2b-02). RC-4: skip when the function is
        # admin-gated on the caller's authority (identity equality OR an
        # authority predicate) — the caller set is narrowed to a trusted admin,
        # so re-entry is not an attacker vector.
        moved_names = sorted(v.canonical_name for v in moved)
        if moved & own_guard_state_reads(fn_a) and not _admin_gated(fn_a):
            emit(
                case_meta, RULE_ID, decl=fn_a,
                detail=(
                    f"{contract_a.name}.{fn_a.full_name} moved a state write across an "
                    f"external call between commits (CEI ordering broken); the moved "
                    f"variable is read by this function's own guard, so re-entry reads "
                    f"stale state and bypasses the check"
                ),
                evidence={
                    "owasp": "SC08", "cei_ordering_broken": True,
                    "visibility_after": fn_a.visibility,
                    "writes_state_after": bool(moved),
                    "moved_after_call": moved_names,
                    "bypassable_guard_vars": sorted(
                        v.canonical_name for v in (moved & own_guard_state_reads(fn_a))
                    ),
                    "admin_gated": False,
                },
            )
            return True

        # 2.10 read-only reentrancy: the moved writes are not what guards this
        # function, but a repo-declared view reads them, so an outside protocol
        # could observe inconsistent state mid-call. Not provable from one repo
        # -> CANDIDATE, never CONFIRMED (N2b-05).
        if _reads_by_repo_view(contract_a, moved):
            emit(
                case_meta, RULE_ID, decl=fn_a, severity="CANDIDATE",
                detail=(
                    f"{contract_a.name}.{fn_a.full_name} moved a state write across an "
                    f"external call between commits; the moved state is not this "
                    f"function's own guard but IS read by a view, so an outside protocol "
                    f"can observe mid-call state (read-only reentrancy)"
                ),
                evidence={
                    "owasp": "SC08", "cei_ordering_broken": True,
                    "visibility_after": fn_a.visibility,
                    "writes_state_after": bool(moved),
                    "moved_after_call": moved_names, "read_only_reentrancy": True,
                },
            )
            return "candidate"

        # 2.9: the moved variable is not read in any exploitable re-entry path
        # (not a guard var here, not read by a view), so its stale value during
        # re-entry is not exploitable (N2b-03) -> quiet.
        continue

    return False
