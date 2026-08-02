"""RULE 2a - SC08: Reentrancy guard removed.

Trigger (RULES.md Rule 2, sub-rule 2a): a function that carried `nonReentrant`
(or an equivalent set-then-clear storage mutex) at commit N-1 does not at commit
N, AND still contains an external call.

Detection is semantic (Slither IR/CFG via _cfg.py), never modifier-name based.
"Guard present" = has_setclear_mutex: a storage flag read in a guard and toggled
between two distinct compile-time constants (nonReentrant's _status, or a manual
`bool locked`). The same test at N-1 and N gives the guard-removed signal.

Exclusions handled (RULES.md 2.1-2.10):
  2.1  no external call remains in the function at N        -> quiet
  2.2  CEI provably correct (all state writes precede every
       external call at N)                                  -> quiet
  2.3  sole external-call target is an immutable/constant
       trusted address set at construction                 -> quiet
  2.5  function is view/pure at N (no state to corrupt)     -> quiet
  2.8  test/mock path (segment-based source_path match)     -> quiet
  2.10 read-only reentrancy: an external call precedes a
       state write that only an external view reads (the
       function is not itself directly re-enterable)        -> CANDIDATE, never
                                                               a plain CONFIRMED
                                                               fire

Verdict values returned to the scorer:
  True         -> CONFIRMED regression (fires)
  "candidate"  -> read-only reentrancy, capped at CANDIDATE (2.10). A single-repo
                  tool cannot prove a third-party protocol reads the view during
                  the re-entrancy window, so this is never auto-confirmed.
  False        -> quiet

Not yet covered (no fixture exercises it, so left for later without a silent
guess): 2.4 same-repo provably-non-reentrant callee, 2.6 guard relocated to the
sole entry point, 2.7 gas-stipend transfer/send, 2.9 written-after var unread on
the re-entry path.
"""

from pathlib import Path

from ._cfg import (
    all_call_dests_trusted_immutable,
    cei_correct,
    has_external_call,
    has_setclear_mutex,
    own_guard_state_reads,
    state_writes_after_calls,
)
from ._shared import declared_in_repo, is_test_path_segments, parse

RULE_ID = "2a"


def _candidate_map(slither_obj) -> dict:
    """{(contract name, function full_name): (fn, contract)} for repo-declared,
    implemented, non-constructor functions. full_name carries the signature so
    overloads match exactly across commits (same convention as Rule 1)."""
    out: dict = {}
    for contract in slither_obj.contracts_derived:
        for fn in contract.functions:
            if fn.is_constructor or not fn.is_implemented or fn.is_shadowed:
                continue
            if not declared_in_repo(fn):
                continue
            out[(contract.name, fn.full_name)] = (fn, contract)
    return out


def _reads_by_repo_view(contract, variables: set) -> bool:
    """True iff some repo-declared view/pure function reads any of `variables`.

    Only explicitly-defined view/pure functions count - a public state variable's
    auto-generated getter is not materialised as a Slither function, and inherited
    library views (e.g. OZ's _reentrancyGuardEntered) are filtered by
    declared_in_repo, so this keys on getters the contract's own source defines.
    """
    for fn in contract.functions:
        if not (fn.view or fn.pure):
            continue
        if not declared_in_repo(fn):
            continue
        if set(fn.state_variables_read) & variables:
            return True
    return False


def run(before_path: Path, after_path: Path, case_meta: dict):
    """Returns True (fire), "candidate" (read-only, 2.10), or False (quiet)."""
    # Exclusion 2.8: test/mock path, matched on repo-relative source_path by
    # whole segments (shared with Rule 1.6). A fixture that declares no
    # source_path falls back to after_path, whose fixtures-r2/... segments match
    # no marker.
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)

    before_map = _candidate_map(before)
    after_map = _candidate_map(after)

    for key, (fn_b, _contract_b) in before_map.items():
        # Guard present at N-1?
        if not has_setclear_mutex(fn_b):
            continue
        # Same function still present at N (matched by contract + signature)?
        if key not in after_map:
            continue
        fn_a, contract_a = after_map[key]
        # Guard still present at N -> not removed -> quiet.
        if has_setclear_mutex(fn_a):
            continue

        # --- Guard removed. Apply the exclusion set. ---

        # 2.5: view/pure at N - nothing to corrupt.
        if fn_a.view or fn_a.pure:
            continue
        # 2.1: no external call remains - nothing to re-enter through.
        if not has_external_call(fn_a):
            continue
        # 2.3: sole call target is an immutable/constant trusted address.
        if all_call_dests_trusted_immutable(fn_a):
            continue
        # 2.2: CEI provably correct - all state writes precede every call.
        if cei_correct(fn_a):
            continue

        # CEI is broken (a state write follows an external call). Decide between
        # a CONFIRMED direct reentrancy and a CANDIDATE read-only reentrancy.
        writes_after = state_writes_after_calls(fn_a)
        own_guard_vars = own_guard_state_reads(fn_a)

        # Directly reentrant: a variable this function checks in its OWN guard is
        # written after the call, so a re-entrant call bypasses the check.
        if writes_after & own_guard_vars:
            return True

        # 2.10 read-only reentrancy: the after-call writes are not what guards
        # this function, but an external (repo-declared) view reads them, so an
        # outside protocol could observe inconsistent state mid-call. Cannot be
        # proven exploitable from a single repo -> CANDIDATE, never CONFIRMED.
        if _reads_by_repo_view(contract_a, writes_after):
            return "candidate"

        # CEI broken with no read-only surface and no self-guard bypass: still a
        # genuine guard-removal regression.
        return True

    return False
