"""Shared Slither-based semantic helpers for Chainwatch rules.

Everything here is AST/IR/data-dependency based. No regex on source text and
no modifier name-string matching (CHARTER.md rule 4, RULES.md Rule 1 note).
"""

import logging
from pathlib import Path

from slither import Slither
from slither.core.declarations import Function, SolidityVariableComposed, Structure
from slither.core.solidity_types import UserDefinedType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Assignment,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Member,
    Send,
)
from slither.slithir.variables import Constant, ReferenceVariable
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


TEST_PATH_SEGMENTS = {"test", "tests", "mock", "mocks", "script", "scripts"}


def is_test_path_segments(path: str) -> bool:
    """Segment-based test/mock path classifier (finding 3x-L1).

    Matches whole path SEGMENTS, never substrings: `contracts/latest/Foo.sol`
    is NOT a test path even though it contains the letters "test", whereas
    `test/mocks/Treasury.sol` is (segments `test`, `mocks`). This is the
    classifier Rule 1 keys exclusion 1.6 on, reading the repo-relative
    `source_path` a case declares so the rule sees the file the way the real
    repo walk would.

    The `.t.sol` suffix and `*Mock*`/`*Harness*` patterns are matched against
    the file BASENAME only (a filename, part of the path) - never against a
    Slither contract name, per the charter's no-name-matching stance.
    """
    p = str(path).replace("\\", "/")
    segments = [s for s in p.split("/") if s]
    if any(s in TEST_PATH_SEGMENTS for s in segments):
        return True
    name = segments[-1] if segments else ""
    if name.endswith(".t.sol"):
        return True
    return any(m in name for m in TEST_NAME_MARKERS)


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


# Raw ERC20 methods whose bool return is the Rule 5 (SC06) checkable value.
ERC20_RETURN_FNS = ("transfer", "transferFrom")


def is_return_checkable_call(ir) -> bool:
    """True iff `ir` is an external call whose return value is the subject of a
    Rule 5 unchecked-return check: any low-level .call/.staticcall/.delegatecall,
    a .send, or a raw ERC20 transfer/transferFrom. Library calls (SafeERC20's
    safeTransfer etc.) are excluded - their checking is internal - and generic
    high-level typed calls (e.g. an internal owner() read, or an interface method)
    are excluded so this never flags an access-control guard as a call-return
    check (which would break Rules 1/3a)."""
    if isinstance(ir, LibraryCall):
        return False
    if isinstance(ir, (LowLevelCall, Send)):
        return True
    if isinstance(ir, HighLevelCall):
        return getattr(ir, "function_name", None) in ERC20_RETURN_FNS
    return False


def external_call_return_taint(fn: Function) -> set:
    """Set of IR values that carry (transitively) the return value of a
    return-checkable external call in fn's OWN body - the call's lvalue plus
    everything forward-assigned from it. A guard reading any of these is checking
    an external-call RESULT, not a function parameter or msg.sender, which is the
    Rule 5 vs Rule 1/6 discriminator."""
    seeds = set()
    for node in fn.nodes:
        for ir in node.irs:
            if is_return_checkable_call(ir) and ir.lvalue is not None:
                seeds.add(ir.lvalue)
    if not seeds:
        return set()
    tainted = set(seeds)
    changed = True
    while changed:
        changed = False
        for node in fn.nodes:
            for ir in node.irs:
                lv = getattr(ir, "lvalue", None)
                if lv is None or lv in tainted:
                    continue
                if any(r in tainted for r in getattr(ir, "read", [])):
                    tainted.add(lv)
                    changed = True
    return tainted


def guard_checks_call_return(node, taint: set) -> bool:
    """True iff `node` (a guard node) reads a value tainted by an external-call
    return - i.e. the guard is checking an external call's result."""
    if not taint:
        return False
    for ir in node.irs:
        for v in getattr(ir, "read", []):
            if v in taint:
                return True
    return False


def constrains_msg_sender(
    fn: Function, contract, skip_call_return_guards: bool = False
) -> bool:
    """True iff a guard node reachable from fn depends on msg.sender.

    NOTE: slither's own Function.is_protected() short-circuits on the modifier
    NAME "onlyOwner" (see slither/core/declarations/function.py) - exactly the
    name matching RULES.md forbids - so it is deliberately not used.

    skip_call_return_guards (Rule 1 boundary with Rule 5): when True, a guard that
    is checking an external-call RETURN value is ignored even if that value is
    data-dependent on msg.sender (e.g. require(ok) after msg.sender.call{value:}).
    Such a check is SC06 (Rule 5), not access control, so Rule 1 must not treat it
    as a msg.sender constraint. Default False keeps Rule 3a's behaviour unchanged.
    """
    for f in reachable(fn):
        taint = external_call_return_taint(f) if skip_call_return_guards else set()
        for node in guard_nodes(f):
            if skip_call_return_guards and guard_checks_call_return(node, taint):
                continue
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


def _namespaced_member_access(
    fn: Function, transitive: bool = True
) -> tuple[set, set, set]:
    """(member names read, member names written, members written-to-constant)
    through an ERC-7201 namespaced pointer.

    Tracks which IR values are ERC-7201 storage pointers, then classifies each
    member access on them. A member REF used as an Assignment lvalue is a write;
    a member REF appearing in any operation's reads is a read. If that write's
    rvalue is a compile-time Constant, the member is also recorded as
    written-to-constant, which the init-guard discriminator needs to separate a
    monotonic init flag from a per-call rate-limit member (finding
    3b-L-ratelimit). This is the namespaced-struct analogue of "which declared
    state variables does this touch", which is what the OZ 4 path uses.
    """
    reads: set = set()
    writes: set = set()
    const_writes: set = set()
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
                    member = ref_to_member[ir.lvalue]
                    writes.add(member)
                    if isinstance(getattr(ir, "rvalue", None), Constant):
                        const_writes.add(member)
                for v in getattr(ir, "read", []):
                    if v in ref_to_member:
                        reads.add(ref_to_member[v])
    return reads, writes, const_writes


def _state_vars_written_to_constant(fn: Function) -> set:
    """Declared state variables assigned a compile-time Constant somewhere in
    fn's reachable body.

    Verified against OZ 4.9.6 / 5.7.0 IR: `initializer` writes `_initialized = 1`
    and `_initializing = true/false` (all Constants), so the init flag lands
    here; `reinitializer` writes `_initialized = version` (a parameter, NOT a
    Constant) but still writes `_initializing = true/false`, so it too has a
    constant-written gated flag. A rate-limit variable is only ever written from
    `block.timestamp` / an argument, so it never appears here. This is the
    discriminator behind finding 3b-L-ratelimit.
    """
    out: set = set()
    for f in reachable(fn):
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, Assignment) and isinstance(
                    getattr(ir, "rvalue", None), Constant
                ):
                    lv = ir.lvalue
                    origin = (
                        lv.points_to_origin
                        if isinstance(lv, ReferenceVariable)
                        else lv
                    )
                    if isinstance(origin, StateVariable):
                        out.add(origin)
    return out


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

    Gate-on-and-write-same-var is NECESSARY but not SUFFICIENT: a rate-limit
    guard has the identical shape (`require(block.timestamp >= lastX + N);
    lastX = block.timestamp`). The discriminator (finding 3b-L-ratelimit): a
    real init flag is written to a compile-time CONSTANT and monotonically
    closes the gate; a rate-limit member is rewritten from a per-call value and
    reopens it. So the gated-and-written variable must ALSO be written to a
    constant somewhere.
    """
    if not isinstance(mod, Function):
        return False

    # --- OZ 4 form: declared state variables.
    written = set(mod.all_state_variables_written())
    if written:
        const_written = _state_vars_written_to_constant(mod)
        for node in guard_nodes(mod):
            gated = set(node.state_variables_read) & written
            if gated & const_written:
                return True

    # --- OZ 5 form: ERC-7201 namespaced struct members.
    if not any(True for f in reachable(mod) for _ in guard_nodes(f)):
        return False
    ns_reads, ns_writes, ns_const = _namespaced_member_access(mod)
    return bool(ns_reads & ns_writes & ns_const)


def has_init_guard(fn: Function) -> bool:
    """True iff fn carries a one-shot init guard as a modifier, or implements
    one inline in its own body (exclusion 3b.2).

    The inline checks apply the same rate-limit discriminator as
    is_oneshot_init_guard: a gated-and-written variable only counts as an init
    flag if it is also written to a compile-time constant (finding
    3b-L-ratelimit), so an inline rate limit is not mistaken for a manual
    initialized-bool guard.
    """
    if any(is_oneshot_init_guard(m) for m in fn.modifiers):
        return True
    written = set(fn.all_state_variables_written())
    const_written = _state_vars_written_to_constant(fn)
    for node in guard_nodes(fn):
        gated = set(node.state_variables_read) & written
        if gated & const_written:
            return True
    # Same inline check for an ERC-7201 namespaced flag. Restricted to fn's own
    # body so that a guard belonging to a callee is not credited to fn.
    if any(True for _ in guard_nodes(fn)):
        ns_reads, ns_writes, ns_const = _namespaced_member_access(fn, transitive=False)
        if ns_reads & ns_writes & ns_const:
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
