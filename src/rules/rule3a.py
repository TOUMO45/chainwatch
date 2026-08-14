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

Fires iff a target function was constrained at N-1 and is unconstrained at N.

Exclusions handled:
  3a.1 timelock/multisig: an inline require(msg.sender == timelock) still
       counts as a msg.sender constraint, so the caller set did not become
       unrestricted and the rule stays quiet.
  3a.2 upgrade path removed entirely: the target function no longer exists at
       commit N -> nothing widened -> quiet.
  3a.3 test/mock path: standard path patterns -> quiet.
"""

from pathlib import Path

from ._shared import accept_finding, constrains_msg_sender, declared_in_repo, is_test_path, parse

RULE_ID = "3a"

# The trigger's explicit target list: UUPS upgrade hooks and proxy admin setters.
TARGET_FUNCTIONS = {
    "_authorizeUpgrade",
    "upgradeTo",
    "upgradeToAndCall",
    "changeAdmin",
    "changeProxyAdmin",
}


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
    if is_test_path(case_meta.get("source_path", after_path)):
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
            return True
    return False
