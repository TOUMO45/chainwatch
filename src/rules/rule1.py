"""RULE 1 - SC01: Access Control regression.

Trigger (RULES.md): a function that had a msg.sender access constraint at commit
N-1 has none at commit N.

All analysis is semantic (Slither AST/IR + data dependency). No regex on source,
no modifier name matching - the whole msg.sender-constraint test is reused from
_shared.constrains_msg_sender, the same data-dependency analysis Rule 3a uses, so
exclusions 1.1 (renamed modifier, identical body) and 1.2 (inline
require(msg.sender...) replacement) fall out for free: a renamed modifier or an
inline check still gates on msg.sender, so constrains_msg_sender stays True at N
and the rule stays quiet.

BOUNDARY WITH RULE 3 (exclusion 1.10 + the upgrade case): Rule 1 covers ordinary
state-changing / value-moving functions ONLY. Upgrade-authorization functions
(_authorizeUpgrade, upgradeTo, ...) are Rule 3a's; initializer/constructor
functions are Rule 3b's. Rule 1 defers on all of them so an upgrade or
initializer regression is reported once, by Rule 3, not double-counted. This is
what keeps Rule 1 quiet on N1-05 (_authorizeUpgrade losing onlyOwner is a Rule
3a positive).

Exclusions handled:
  1.1  renamed modifier, identical body      -> constrains_msg_sender (semantic)
  1.2  inline require(msg.sender...) added    -> constrains_msg_sender (semantic)
  1.3  visibility narrowed to internal/private -> not externally reachable at N
  1.4  became view/pure                        -> writes no state / moves no value at N
  1.6  test/mock path                          -> segment-based source_path match
  1.10 constructor / initializer function      -> deferred to Rule 3b
  upgrade-authorization function               -> deferred to Rule 3a (keeps N1-05 quiet)
"""

from pathlib import Path

from slither.core.declarations import Function

from ._shared import (
    constrains_msg_sender,
    declared_in_repo,
    has_init_guard,
    is_test_path_segments,
    parse,
    reachable,
)
from .rule3a import TARGET_FUNCTIONS as UPGRADE_FUNCTIONS

RULE_ID = "1"


def _is_rule3_territory(fn: Function) -> bool:
    """True iff `fn` belongs to Rule 3, not Rule 1 (exclusion 1.10 + upgrade case).

    A constructor, an upgrade-authorization hook, or an initializer-guarded
    function is Rule 3a/3b's responsibility. Detected structurally: the upgrade
    hooks by the same target-name set Rule 3a triggers on (a fixed protocol API,
    not a heuristic modifier name), the initializer by its one-shot init guard
    (has_init_guard, structural), the constructor by its Slither flag.
    """
    if fn.is_constructor:
        return True
    if fn.name in UPGRADE_FUNCTIONS:
        return True
    if has_init_guard(fn):
        return True
    return False


def _writes_state_or_moves_value(fn: Function) -> bool:
    """CONFIRMED requirement: the function must write state or move value.

    A function that only reads (view/pure) has nothing for an access modifier to
    protect, so its loss is not a regression (exclusion 1.4). "Moves value" is
    detected via Slither's can_send_eth (ETH out through a call/transfer/send);
    "writes state" via the transitive set of state variables written.
    """
    if fn.all_state_variables_written():
        return True
    try:
        if fn.can_send_eth():
            return True
    except Exception:
        pass
    return False


def _externally_reachable(fn: Function, contract) -> bool:
    """Exclusion 1.3: the function is reachable as an external entry point at N.

    Directly external/public, or reached transitively from an external/public
    function that is itself unprotected (a protected caller would mean the
    protection simply moved upstream, not vanished).
    """
    if fn.visibility in ("external", "public"):
        return True
    for other in contract.functions:
        if other == fn or other.visibility not in ("external", "public"):
            continue
        if fn in reachable(other) and not constrains_msg_sender(other, contract):
            return True
    return False


def _candidate_map(slither_obj) -> dict:
    """{(contract name, function full_name): (fn, contract)} for repo-declared,
    implemented, non-constructor functions. full_name carries the signature so
    overloads are matched exactly across commits."""
    out: dict = {}
    for contract in slither_obj.contracts_derived:
        for fn in contract.functions:
            if fn.is_constructor or not fn.is_implemented or fn.is_shadowed:
                continue
            if not declared_in_repo(fn):
                continue
            out[(contract.name, fn.full_name)] = (fn, contract)
    return out


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 1 fires on this before/after pair."""
    # Exclusion 1.6: test/mock path, matched on repo-relative source_path by
    # whole segments (finding 3x-L1). In a real repo walk this is the file's
    # path; a fixture that declares no source_path falls back to after_path,
    # whose fixtures-r1/... segments match no marker.
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)

    before_map = _candidate_map(before)
    after_map = _candidate_map(after)

    for key, (fn_b, contract_b) in before_map.items():
        # Exclusion 1.10 + upgrade case: defer to Rule 3a/3b. Checked on the
        # BEFORE function so an initializer that loses its guard (Rule 3b
        # positive) never enters Rule 1.
        if _is_rule3_territory(fn_b):
            continue
        # Had a msg.sender constraint at N-1?
        if not constrains_msg_sender(fn_b, contract_b):
            continue
        # Was it worth protecting at N-1 (wrote state / moved value)?
        if not _writes_state_or_moves_value(fn_b):
            continue

        # Same function at N (matched by contract + signature).
        if key not in after_map:
            # Removed or renamed away: no surviving external entry point with a
            # lost constraint (covers 1.12 deletion and a rename to internal).
            continue
        fn_a, contract_a = after_map[key]

        # Defensive: still Rule 3 territory at N (e.g. gained an init guard).
        if _is_rule3_territory(fn_a):
            continue
        # Exclusions 1.1 / 1.2 (and 3a.1-style inline timelock): still gated on
        # msg.sender at N -> protection intact or merely relocated -> quiet.
        if constrains_msg_sender(fn_a, contract_a):
            continue
        # Exclusion 1.4: no longer changes state / moves value at N.
        if not _writes_state_or_moves_value(fn_a):
            continue
        # Exclusion 1.3: no longer externally reachable at N.
        if not _externally_reachable(fn_a, contract_a):
            continue

        return True

    return False
