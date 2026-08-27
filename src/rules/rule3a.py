"""RULE 3a - SC10: Upgrade authorization weakened.

Trigger (RULES.md): the access constraint on _authorizeUpgrade, upgradeTo,
upgradeToAndCall, or the proxy admin setter changed such that the caller set
widened.

Detection is semantic, per charter rule 4 and the RULES.md warning that
modifier name-matching is the largest FP source:

  A function is "msg.sender-constrained" iff somewhere in its reachable set
  (the function itself, its modifiers, and everything they call internally,
  transitively) there is a conditional / require / assert node whose condition
  is data-dependent on msg.sender (Slither contract-level data dependency,
  which propagates through temporaries and internal-call returns such as
  OpenZeppelin's _msgSender()).

Two independent trigger shapes, reported separately (`"trigger"` in evidence):

  "constraint-removed" (original). Fires iff a target function was constrained
  at N-1 and is unconstrained at N.

  "caller-set-widened" (3a-L2, closed 2026-08-26). RULES.md's own trigger text
  is broader than the original implementation: "the caller set widened", not
  merely "the constraint disappeared". `onlyOwner` replaced by an inline
  `require(msg.sender == admin)` keeps `constrains_msg_sender` True on both
  sides - the first trigger correctly stays quiet - but if `admin` has no
  protection of its own (anyone can call a setter that points it at
  themselves), the caller set is unrestricted in practice, identically to the
  modifier having been deleted outright. Detected by reusing Rule 10's own
  gate-variable analysis (`_classify`): the guard's comparison target is
  "illusory" iff it has an UNGUARDED run-time writer - the same "unguarded
  writer" concept Rule 10 was built around, applied here to what an
  access-control check compares msg.sender against, rather than to what an
  access-control check itself guards.

Exclusions handled:
  3a.1 timelock/multisig: an inline require(msg.sender == timelock) still
       counts as a msg.sender constraint, so the caller set did not become
       unrestricted and the rule stays quiet. Also covers the
       caller-set-widened shape: a comparison target with only a
       msg.sender-constrained (or one-shot) writer is never illusory.
  3a.2 upgrade path removed entirely: the target function no longer exists at
       commit N -> nothing widened -> quiet.
  3a.3 test/mock path: standard path patterns -> quiet.
"""

from pathlib import Path

from ._shared import (
    accept_finding,
    constrains_msg_sender,
    declared_in_repo,
    emit,
    external_entry_points,
    guard_nodes,
    is_test_path_segments,
    node_depends_on_msg_sender,
    parse,
    reachable,
)
from .rule10 import _classify

RULE_ID = "3a"

# The trigger's explicit target list: UUPS upgrade hooks and proxy admin setters.
TARGET_FUNCTIONS = {
    "_authorizeUpgrade",
    "upgradeTo",
    "upgradeToAndCall",
    "changeAdmin",
    "changeProxyAdmin",
}


def _illusory_constraint_targets(fn, contract) -> set:
    """Canonical names of state variables a msg.sender guard reachable from
    `fn` compares against, restricted to the ones that offer no real
    protection: an UNGUARDED run-time writer exists, so anyone can set the
    "authorized" identity to themselves before the guard ever runs.

    Reuses Rule 10's own `_classify(contract, var_name)` unchanged - the same
    (one-shot writers, unguarded writers) split Rule 10 already trusts for
    "is this variable's value under anyone's control". A variable with only a
    one-shot writer (constructor, or an `initializer`-guarded function - the
    shape OpenZeppelin's own `_owner` uses) or only msg.sender-constrained
    writers is never illusory; only the presence of a genuinely unguarded
    writer makes it so.
    """
    targets: set = set()
    for f in reachable(fn):
        for node in guard_nodes(f):
            if node_depends_on_msg_sender(node, contract):
                targets.update(v.canonical_name for v in node.state_variables_read)
    illusory: set = set()
    for name in targets:
        _oneshot, unguarded = _classify(contract, name)
        if unguarded:
            illusory.add(name)
    return illusory


def _target_functions(slither_obj):
    """{(contract_name, function_name): (fn, contract)} for target functions
    declared in the analyzed file itself (not in node_modules)."""
    out = {}
    for contract in slither_obj.contracts_derived:
        for fn in contract.functions:
            if fn.name not in TARGET_FUNCTIONS:
                continue
            if fn.is_shadowed or not fn.is_implemented:
                continue
            if not declared_in_repo(fn):
                continue
            out[(contract.name, fn.name)] = (fn, contract)
    return out


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 3a fires on this before/after pair."""
    # Exclusion 3a.3: not production code. In a real repo walk this receives
    # the repo-relative path; fixture dirs ("fixtures/...") match no marker.
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)

    targets_before = _target_functions(before)
    targets_after = _target_functions(after)

    for key, (fn_b, contract_b) in targets_before.items():
        if not constrains_msg_sender(fn_b, contract_b):
            continue  # was not constrained before; nothing to weaken
        if key not in targets_after:
            # Exclusion 3a.2: the upgrade path / target function no longer
            # exists at commit N. Nothing widened.
            continue
        fn_a, contract_a = targets_after[key]
        if not constrains_msg_sender(fn_a, contract_a):
            # DESIGN-L2: only attribute to a declaration in a file actually
            # changed in this commit.
            if not accept_finding(fn_a, case_meta):
                continue
            # Constrained at N-1, unconstrained at N. Any remaining msg.sender
            # check (e.g. an inline timelock require, exclusion 3a.1) would
            # have kept constrains_msg_sender True.
            emit(
                case_meta, RULE_ID, decl=fn_a,
                detail=(
                    f"upgrade-authorization function {contract_a.name}.{fn_a.name} was "
                    f"constrained on msg.sender at commit N-1 and is not at commit N: "
                    f"the upgrade path is open to any caller"
                ),
                evidence={
                    "owasp": "SC10", "trigger": "constraint-removed",
                    "upgrade_function": fn_a.name,
                    "constrained_before": True, "constrained_after": False,
                    "visibility_after": fn_a.visibility,
                    "writes_state_after": bool(fn_a.all_state_variables_written()),
                    # 3a-L4: UUPS's _authorizeUpgrade is internal BY DESIGN and
                    # is reached through the inherited public upgradeTo /
                    # upgradeToAndCall. Establish that here, from the real call
                    # graph, so verdict.py never has to infer it.
                    "reachable_via_after": external_entry_points(contract_a, fn_a),
                    # Rule 3a fires ONLY on upgrade-authorization
                    # functions - that is its whole trigger domain - so it
                    # can assert this as a fact rather than leave verdict.py
                    # to infer it (3a-L4).
                    "upgrade_path": True,
                },
            )
            return True

        # 3a-L2: the constraint SURVIVED (constrains_msg_sender True on both
        # sides) - check whether what it compares against became illusory.
        illusory_before = _illusory_constraint_targets(fn_b, contract_b)
        if illusory_before:
            continue  # already illusory at N-1: not a regression introduced here
        illusory_after = _illusory_constraint_targets(fn_a, contract_a)
        if not illusory_after:
            continue  # still a real constraint at N: nothing widened
        if not accept_finding(fn_a, case_meta):
            continue
        target_names = ", ".join(sorted(illusory_after))
        emit(
            case_meta, RULE_ID, decl=fn_a,
            detail=(
                f"upgrade-authorization function {contract_a.name}.{fn_a.name} still "
                f"checks msg.sender at commit N, but the comparison target "
                f"({target_names}) now has an unguarded run-time writer: anyone can "
                f"set it to themselves first, then pass the check - the caller set "
                f"is unrestricted in practice"
            ),
            evidence={
                "owasp": "SC10", "trigger": "caller-set-widened",
                "upgrade_function": fn_a.name,
                "illusory_targets": sorted(illusory_after),
                "target_protected_before": True, "target_protected_after": False,
                "visibility_after": fn_a.visibility,
                "writes_state_after": bool(fn_a.all_state_variables_written()),
                "reachable_via_after": external_entry_points(contract_a, fn_a),
                    # Rule 3a fires ONLY on upgrade-authorization
                    # functions - that is its whole trigger domain - so it
                    # can assert this as a fact rather than leave verdict.py
                    # to infer it (3a-L4).
                    "upgrade_path": True,
            },
        )
        return True
    return False
