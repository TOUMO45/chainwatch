"""Shared Slither-based semantic helpers for Chainwatch rules.

Everything here is AST/IR/data-dependency based. No regex on source text and
no modifier name-string matching (CHARTER.md rule 4, RULES.md Rule 1 note).
"""

import logging
from pathlib import Path

from slither import Slither
from slither.core.declarations import Function, SolidityVariableComposed, Structure
from slither.core.solidity_types import UserDefinedType
from slither.slithir.operations import Assignment, InternalCall, Member
from slither.analyses.data_dependency.data_dependency import is_dependent

REMAPS = [
    "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
    "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
]

MSG_SENDER = SolidityVariableComposed("msg.sender")

TEST_PATH_MARKERS = ("test/", "tests/", "mock/", "mocks/", "script/", "scripts/")
TEST_NAME_MARKERS = ("Mock", "Harness")

for _name in ("CryticCompile", "Slither", "Printers", "Detectors"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

_PARSE_CACHE: dict[str, Slither] = {}


def parse(path) -> Slither:
    """Compile+analyze a file, memoized per absolute path."""
    key = str(Path(path).resolve())
    if key not in _PARSE_CACHE:
        _PARSE_CACHE[key] = Slither(str(path), solc_remaps=REMAPS)
    return _PARSE_CACHE[key]


def is_test_path(path: str) -> bool:
    p = str(path).replace("\\", "/")
    if any(m in p for m in TEST_PATH_MARKERS):
        return True
    if p.endswith(".t.sol"):
        return True
    return any(m in Path(p).name for m in TEST_NAME_MARKERS)


def declared_in_repo(fn: Function) -> bool:
    """False for functions inherited from node_modules (library code)."""
    decl = str(fn.contract_declarer.source_mapping.filename.absolute).replace("\\", "/")
    return "node_modules" not in decl


def reachable(fn: Function) -> list:
    """fn + its modifiers + transitively-called internal/library functions."""
    seen: list = []
    todo: list = [fn]
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


def guard_nodes(fn: Function):
    """Conditional / require / assert nodes in fn's own body."""
    for node in fn.nodes:
        if node.is_conditional(include_loop=False) or node.contains_require_or_assert():
            yield node


def node_depends_on_msg_sender(node, contract) -> bool:
    for ir in node.irs:
        for v in getattr(ir, "read", []):
            if v == MSG_SENDER:
                return True
            if is_dependent(v, MSG_SENDER, contract):
                return True
    return False


def constrains_msg_sender(fn: Function, contract) -> bool:
    """True iff a guard node reachable from fn depends on msg.sender.

    NOTE: slither's own Function.is_protected() short-circuits on the modifier
    NAME "onlyOwner" (see slither/core/declarations/function.py) - exactly the
    name matching RULES.md forbids - so it is deliberately not used.
    """
    for f in reachable(fn):
        for node in guard_nodes(f):
            if node_depends_on_msg_sender(node, contract):
                return True
    return False


def _is_namespace_pointer_function(fn) -> bool:
    """True iff `fn` hands back an ERC-7201 namespaced storage pointer.

    Shape (OZ 5, verified against the installed 5.7.0 source): a function whose
    body is inline assembly assigning `$.slot := <namespace constant>` and which
    returns a struct held in storage:

        function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
            assembly { $.slot := OwnableStorageLocation }
        }

    Detected by that structure, never by name or by the `erc7201:` annotation.
    Deliberately does NOT require the slot constant to be read directly: OZ 5's
    Initializable reaches it through a further call (_initializableStorageSlot()),
    which is exactly why Slither attributes no state-variable write to the
    `initializer` modifier and why Signal A failed on OZ 5 (finding 3x-L3).
    """
    if not isinstance(fn, Function) or not fn.returns:
        return False
    if not any(node.type.name == "ASSEMBLY" for node in fn.nodes):
        return False
    for ret in fn.returns:
        rtype = getattr(ret, "type", None)
        if isinstance(rtype, UserDefinedType) and isinstance(rtype.type, Structure):
            return True
    return False


def _namespaced_member_access(fn: Function, transitive: bool = True) -> tuple[set, set]:
    """(member names read, member names written) through a namespaced pointer.

    Tracks which IR values are ERC-7201 storage pointers, then classifies each
    member access on them. A member REF used as an Assignment lvalue is a write;
    a member REF appearing in any operation's reads is a read. This is the
    namespaced-struct analogue of "which declared state variables does this
    touch", which is what the OZ 4 path uses.
    """
    reads: set = set()
    writes: set = set()
    for f in (reachable(fn) if transitive else [fn]):
        pointers: set = set()
        ref_to_member: dict = {}
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) and _is_namespace_pointer_function(
                    getattr(ir, "function", None)
                ):
                    if ir.lvalue is not None:
                        pointers.add(ir.lvalue)
                elif isinstance(ir, Assignment):
                    if getattr(ir, "rvalue", None) in pointers and ir.lvalue is not None:
                        pointers.add(ir.lvalue)
                if isinstance(ir, Member) and ir.variable_left in pointers:
                    ref_to_member[ir.lvalue] = str(ir.variable_right).strip('"')
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, Assignment) and ir.lvalue in ref_to_member:
                    writes.add(ref_to_member[ir.lvalue])
                for v in getattr(ir, "read", []):
                    if v in ref_to_member:
                        reads.add(ref_to_member[v])
    return reads, writes


def is_oneshot_init_guard(mod: Function) -> bool:
    """True iff `mod` is a one-shot initialization guard, structurally.

    Shape: the modifier gates on a storage flag AND writes that same flag, so
    it can only pass a bounded number of times. This is what OpenZeppelin's
    `initializer` and `reinitializer(n)` both do, and what `onlyInitializing`
    (reads the flag, writes nothing) deliberately does not.
    Detected by structure, never by name.

    Two storage forms are recognised, chosen per contract by which one actually
    matches - there is no global version switch:

      * OZ 4 form: the flag is a declared state variable.
      * OZ 5 form: the flag is a member of an ERC-7201 namespaced struct reached
        through an assembly storage pointer, so it is not a declared state
        variable at all (finding 3x-L3).

    The OZ 4 test runs first and is untouched, so OZ 4 behaviour is unchanged;
    the OZ 5 test can only add detections where the OZ 4 test found none.
    """
    if not isinstance(mod, Function):
        return False

    # --- OZ 4 form: declared state variables.
    written = set(mod.all_state_variables_written())
    if written:
        for node in guard_nodes(mod):
            if set(node.state_variables_read) & written:
                return True

    # --- OZ 5 form: ERC-7201 namespaced struct members.
    if not any(True for f in reachable(mod) for _ in guard_nodes(f)):
        return False
    ns_reads, ns_writes = _namespaced_member_access(mod)
    return bool(ns_reads & ns_writes)


def has_init_guard(fn: Function) -> bool:
    """True iff fn carries a one-shot init guard as a modifier, or implements
    one inline in its own body (exclusion 3b.2)."""
    if any(is_oneshot_init_guard(m) for m in fn.modifiers):
        return True
    written = set(fn.all_state_variables_written())
    for node in guard_nodes(fn):
        if set(node.state_variables_read) & written:
            return True
    # Same inline check for an ERC-7201 namespaced flag. Restricted to fn's own
    # body so that a guard belonging to a callee is not credited to fn.
    if any(True for _ in guard_nodes(fn)):
        ns_reads, ns_writes = _namespaced_member_access(fn, transitive=False)
        if ns_reads & ns_writes:
            return True
    return False


def defines_init_machinery(contract) -> bool:
    """True iff the contract (or anything it inherits) defines a one-shot init
    guard modifier - the structural signature of an upgradeable/proxy-deployed
    implementation contract.

    Used for RULES.md exclusion 3b.4, which was corrected during human review:
    DISCARD only when the contract is PROVABLY never behind a proxy. Absence of
    this machinery is that proof; its presence is affirmative evidence the
    contract is proxy-deployed.
    """
    for mod in contract.modifiers:
        if is_oneshot_init_guard(mod):
            return True
    return False


def access_control_state_vars(contract) -> set:
    """State variables that participate in msg.sender-based access control:
    everything read by a function/modifier whose body gates on msg.sender.

    A function writing one of these is setting ownership/admin/critical config.
    """
    out: set = set()
    for f in list(contract.functions) + list(contract.modifiers):
        if any(node_depends_on_msg_sender(n, contract) for n in guard_nodes(f)):
            out.update(f.all_state_variables_read())
    return out
