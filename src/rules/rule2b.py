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

from ._cfg import (
    has_external_call,
    has_setclear_mutex,
    own_guard_state_reads,
    state_writes_after_calls,
)
from ._shared import is_test_path_segments, parse
from .rule2a import _candidate_map, _reads_by_repo_view

RULE_ID = "2b"


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
        after_at_n1_names = {v.canonical_name for v in state_writes_after_calls(fn_b)}
        after_at_n = state_writes_after_calls(fn_a)
        # Variables that went from before-every-call (N-1) to after-a-call (N).
        moved = {v for v in after_at_n if v.canonical_name not in after_at_n1_names}
        if not moved:
            # No write crossed the call between commits. Covers N2b-02 (already
            # after the call at N-1, so present in both sets and cancelled).
            continue

        # Directly reentrant: a variable this function checks in its OWN guard is
        # now written after the call, so a re-entrant call reads stale state and
        # bypasses the check (P2b-01, P2b-02).
        if moved & own_guard_state_reads(fn_a):
            return True

        # 2.10 read-only reentrancy: the moved writes are not what guards this
        # function, but a repo-declared view reads them, so an outside protocol
        # could observe inconsistent state mid-call. Not provable from one repo
        # -> CANDIDATE, never CONFIRMED (N2b-05).
        if _reads_by_repo_view(contract_a, moved):
            return "candidate"

        # 2.9: the moved variable is not read in any exploitable re-entry path
        # (not a guard var here, not read by a view), so its stale value during
        # re-entry is not exploitable (N2b-03) -> quiet.
        continue

    return False
