"""RULE 3a — SC10: Upgrade authorization weakened.

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

  NOTE: we deliberately do NOT use slither's Function.is_protected() — its
  implementation short-circuits on the modifier NAME "onlyOwner"
  (slither/core/declarations/function.py), which is exactly the name-matching
  RULES.md forbids.

Fires iff a target function was constrained at N-1 and is unconstrained at N.

Exclusions handled:
  3a.1 timelock/multisig: an inline require(msg.sender == timelock) still
       counts as a msg.sender constraint, so the caller set did not become
       unrestricted and the rule stays quiet. (Widened-in-name/narrowed-in-
       practice nuance is a human CANDIDATE question, not a finding.)
  3a.2 upgrade path removed entirely: the target function no longer exists at
       commit N -> nothing widened -> quiet.
  3a.3 test/mock path: standard path patterns -> quiet.
"""

import logging
from pathlib import Path

from slither import Slither
from slither.core.declarations import Function, SolidityVariableComposed
from slither.analyses.data_dependency.data_dependency import is_dependent

RULE_ID = "3a"

# The trigger's explicit target list: UUPS upgrade hooks and proxy admin setters.
TARGET_FUNCTIONS = {
    "_authorizeUpgrade",
    "upgradeTo",
    "upgradeToAndCall",
    "changeAdmin",
    "changeProxyAdmin",
}

TEST_PATH_MARKERS = ("test/", "tests/", "mock/", "mocks/", "script/", "scripts/")
TEST_NAME_MARKERS = ("Mock", "Harness")

REMAPS = [
    "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
    "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
]

MSG_SENDER = SolidityVariableComposed("msg.sender")

for _name in ("CryticCompile", "Slither", "Printers", "Detectors"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)


def _is_test_path(path: str) -> bool:
    p = path.replace("\\", "/")
    if any(m in p for m in TEST_PATH_MARKERS):
        return True
    if p.endswith(".t.sol"):
        return True
    stem = Path(p).name
    return any(m in stem for m in TEST_NAME_MARKERS)


def _reachable(fn: Function) -> list[Function]:
    """fn + its modifiers + transitively-called internal/library functions."""
    seen: list[Function] = []
    todo: list[Function] = [fn]
    while todo:
        f = todo.pop()
        if f in seen or not isinstance(f, Function):
            continue
        seen.append(f)
        todo.extend(m for m in f.modifiers if isinstance(m, Function) and m not in seen)
        for ir in f.all_internal_calls():
            if isinstance(ir.function, Function) and ir.function not in seen:
                todo.append(ir.function)
    return seen


def _constrains_msg_sender(fn: Function, contract) -> bool:
    """True iff a conditional/require node reachable from fn depends on msg.sender."""
    for f in _reachable(fn):
        for node in f.nodes:
            if not (
                node.is_conditional(include_loop=False)
                or node.contains_require_or_assert()
            ):
                continue
            for ir in node.irs:
                for v in getattr(ir, "read", []):
                    if v == MSG_SENDER:
                        return True
                    if is_dependent(v, MSG_SENDER, contract):
                        return True
    return False


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
            decl_file = str(fn.contract_declarer.source_mapping.filename.absolute)
            if "node_modules" in decl_file.replace("\\", "/"):
                continue
            out[(contract.name, fn.name)] = (fn, contract)
    return out


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 3a fires on this before/after pair."""
    # Exclusion 3a.3: not production code. In a real repo walk this receives
    # the repo-relative path; fixture dirs ("fixtures/...") match no marker.
    if _is_test_path(str(case_meta.get("source_path", after_path))):
        return False

    before = Slither(str(before_path), solc_remaps=REMAPS)
    after = Slither(str(after_path), solc_remaps=REMAPS)

    targets_before = _target_functions(before)
    targets_after = _target_functions(after)

    for key, (fn_b, contract_b) in targets_before.items():
        if not _constrains_msg_sender(fn_b, contract_b):
            continue  # was not constrained before; nothing to weaken
        if key not in targets_after:
            # Exclusion 3a.2: the upgrade path / target function no longer
            # exists at commit N. Nothing widened.
            continue
        fn_a, contract_a = targets_after[key]
        if not _constrains_msg_sender(fn_a, contract_a):
            # Constrained at N-1, unconstrained at N. Any remaining msg.sender
            # check (e.g. an inline timelock require, exclusion 3a.1) would
            # have kept _constrains_msg_sender True.
            return True
    return False
