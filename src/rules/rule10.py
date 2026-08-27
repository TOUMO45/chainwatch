"""RULE 10 - SC01: a security control's RESPONSIBILITY migrated to an
unguarded entry point.

Closes LIMITATIONS.md §RC-RENAME1, measured empirically on 88mph
`contracts/NFT.sol` a4c48d61 (constructor deleted, unguarded `init()` added).

WHY THIS IS NOT A DIFF RULE. Rules 1-9 match a function across commits by
`(contract, name)` and ask what that function LOST. That is structurally
incapable of seeing a control that moved: `init` exists only at N, so there is
no N-1 counterpart to diff against, and the N-1 protection was the CONSTRUCTOR
MECHANISM itself - one-shot and deployer-only, enforced by the EVM, not by any
AST node a rule inspects. Rule 10 therefore inverts the matching direction and
keys on the CONTRACT'S EXTERNAL SURFACE:

    T1  at N-1 the gate variable was established one-shot (a constructor
        anywhere in the inheritance chain, or an init-guarded function), and
    T2  at N-1 NO unguarded run-time writer of it existed, and
    T3  at N one does.

T2 is what keeps this a REGRESSION detector rather than a general vulnerability
detector: a contract that already had an unguarded writer was never safe, and
CHARTER.md puts "a contract that was never safe" out of scope by definition.
Reporting current state is Slither's job; claiming it here would be exactly the
"Slither with extra steps" failure the charter names.

MEASURED MECHANISMS (both wrong on the first design; see LIMITATIONS.md §R10-M1
and §R10-M2). Neither was discoverable from a fixture - each was found only by
probing the real 88mph parse and the real OZ 4 library source:

  * Constructor writes are collected by iterating `contract.functions` and
    filtering `fn.is_constructor`, which reaches EVERY constructor in the
    inheritance chain. `contract.constructor` is deliberately NOT used: on
    88mph at N-1 it returned the derived constructor, whose
    `all_state_variables_written()` omits `Ownable._owner` entirely, so T1
    would have failed on the rule's own positive case.
  * `_gate_vars` resolves one call-hop through the functions a guard node
    INVOKES. OZ 4's `onlyOwner` reaches `_owner` via
    `_checkOwner() -> owner()`, so the guard node itself reads no state
    variable at all and a node-local definition returns the empty set.

Exclusions handled:
  10.1 the new writer carries a one-shot init guard (`initializer`,
       `reinitializer(n)`, or an inline set-once flag) -> quiet.
  10.2 the new writer constrains msg.sender -> protection relocated, not
       removed -> quiet.
  10.3 test/mock/script path -> not production code.
  10.4 DESIGN-L2: the declaration is not in a file this commit changed.
  10.5 the writer is internal/private and every external caller is itself
       guarded -> not externally reachable.
  10.6 the written variable is not a gate variable -> no security control is
       involved (this is what keeps an ordinary new setter, and a renamed
       getter, quiet).
  10.8 the unguarded writer at N has a SAME-NAMED counterpart at N-1 that also
       wrote this gate variable -> the function survived and lost a guard,
       which is Rule 1 / Rule 3b territory, not a migration. This is the rule
       BOUNDARY, and it is not cosmetic: without it Rule 10 co-fires on every
       Rule 3b positive (measured: `fixtures/` P3b-01 and P3b-02, where
       `initialize` exists at both commits and merely drops its `initializer`
       modifier), which is a precision failure even though the underlying
       regression is real. Rule 3b owns "the guard left the function"; Rule 10
       owns "the responsibility left the guarded function". Matching is by
       NAME rather than full signature, the more suppressive choice, per the
       precision-first tie-break.

  10.7 NOT IMPLEMENTED - STATED FUTURE EXTENSION. v1 keys exclusively on GATE
       variables: those an access-control decision reads. A migration that
       exposes an unguarded writer to a VALUE-HOLDING variable (a fee
       recipient, a treasury address, a withdrawal cap) is out of scope and
       stays quiet, even though it can move funds. Widening to value-holding
       state is a real extension, not a tweak: it needs its own fixture set,
       because "which state is value-bearing" has no structural definition as
       crisp as "read by a msg.sender-dependent guard", and guessing at it is
       how precision dies. Recorded here rather than left silent.
"""

from pathlib import Path

from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.declarations import Function
from slither.slithir.operations import (
    HighLevelCall,
    LibraryCall,
    LowLevelCall,
    Send,
    Transfer,
)

from ._shared import (
    ERC20_RETURN_FNS,
    SAFE_ERC20_DEST_POS,
    accept_finding,
    constrains_msg_sender,
    declared_in_repo,
    emit,
    guard_nodes,
    has_init_guard,
    is_test_path_segments,
    node_depends_on_msg_sender,
    parse,
)
from .rule3b import _externally_reachable

RULE_ID = "10"


def _gate_vars(contract) -> set:
    """State variables an access-control decision actually READS.

    Deliberately tighter than `_shared.access_control_state_vars`, which
    returns everything read by a function that merely HAS a msg.sender guard
    (so `onlyOwner setFee()` contributes `_fee` as well as `_owner`). Here only
    the guard node's own reads count, plus the state read by functions that
    node invokes - the call-hop OZ 4 needs.
    """
    out: set = set()
    for fn in list(contract.functions) + list(contract.modifiers):
        for node in guard_nodes(fn):
            if not node_depends_on_msg_sender(node, contract):
                continue
            out.update(node.state_variables_read)
            for ir in node.irs:
                callee = getattr(ir, "function", None)
                if isinstance(callee, Function):
                    out.update(callee.all_state_variables_read())
    return out


def _value_vars(contract) -> set:
    """State variables that RECEIVE FUNDS - closes the 10.7 gap.

    Structural, never nominal. A variable qualifies because a native
    value-moving operation sends to a destination that is data-dependent on it:
    `Transfer` (`addr.transfer(x)`), `Send` (`addr.send(x)`), or a `LowLevelCall`
    carrying a call value (`addr.call{value: x}("")`). Naming it `treasury` or
    `feeRecipient` counts for nothing - name matching across commits is the
    precise blind spot RC-RENAME1 exists to document, and re-introducing it to
    close 10.7 would be a poor trade.

    `fixtures-r10v/negative/N10v-03` is what makes this test real: an `oracle`
    address, migrated in exactly the P10v-01 shape, that is only ever READ
    through `IOracle(oracle).price()`. It is address-typed and unguarded and
    must stay quiet, so an implementation that treated every address-typed
    state variable as value-holding fails there while passing everything else.

    ERC20 recipients count too, by ARGUMENT POSITION on exactly two methods:
    `transfer(to, amount)` -> argument 0, `transferFrom(from, to, amount)` ->
    argument 1. That is the common real-world treasury shape and native-only
    detection could not see it. The ABI names come from
    `_shared.ERC20_RETURN_FNS`, which Rule 5 already depends on, so no new
    convention is introduced.

    THREE EXCLUSIONS THE NATIVE-ONLY VERSION DID NOT NEED, each locked by a
    fixture, because widening to ERC20 brings its own false positives:

      * `approve(spender, amount)` names a SPENDER, not a destination - no value
        moves to it, and approving a DEX router is routine (N10e-01). Matching
        on "an address passed to an ERC20 call" would make a router approval
        indistinguishable from a treasury rotation.
      * `transferFrom`'s recipient is argument 1. Argument 0 is the SOURCE, and
        value moves AWAY from it (N10e-02).
      * every other ERC20 method moves nothing - `balanceOf`, `allowance` and
        friends are reads (N10e-03).

    SafeERC20's `safeTransfer`/`safeTransferFrom` (OpenZeppelin's `using
    SafeERC20 for IERC20` wrapper, the pattern Reserve uses throughout) are
    LibraryCalls, not HighLevelCalls, so the branch above never sees them.
    Matched separately via `SAFE_ERC20_DEST_POS`: the `using` receiver rides
    as the LibraryCall's own arguments[0], so `safeTransfer(token, to, amt)`
    -> position 1 and `safeTransferFrom(token, from, to, amt)` -> position 2 -
    one more than the raw ERC20_RETURN_FNS positions, for the token argument
    each wrapper method adds. `fixtures-r10-safeerc20/negative/N10se-02` locks
    the same argument-position trap one level in: `safeTransferFrom`'s SOURCE
    is now argument 1 (was 0 for the raw call), and a widening that reused the
    raw positions unshifted would mis-flag it as the destination.
    """
    out: set = set()
    for fn in contract.functions:
        if not fn.is_implemented:
            continue
        for node in fn.nodes:
            for ir in node.irs:
                dest = None
                if isinstance(ir, (Transfer, Send)):
                    dest = getattr(ir, "destination", None)
                elif isinstance(ir, LowLevelCall):
                    if getattr(ir, "call_value", None) is not None:
                        dest = getattr(ir, "destination", None)
                elif isinstance(ir, LibraryCall):
                    fname = getattr(ir, "function_name", None)
                    fname = str(fname) if fname is not None else None
                    pos = SAFE_ERC20_DEST_POS.get(fname)
                    if pos is not None:
                        args = list(getattr(ir, "arguments", []) or [])
                        if len(args) > pos:
                            dest = args[pos]
                elif isinstance(ir, HighLevelCall):
                    fname = getattr(ir, "function_name", None)
                    fname = str(fname) if fname is not None else None
                    if fname in ERC20_RETURN_FNS:
                        args = list(getattr(ir, "arguments", []) or [])
                        # transfer(to, amount) -> 0 ; transferFrom(from, to, amt) -> 1
                        pos = 1 if fname == "transferFrom" else 0
                        if len(args) > pos:
                            dest = args[pos]
                if dest is None:
                    continue
                for var in contract.state_variables:
                    if var is dest or is_dependent(dest, var, contract):
                        out.add(var)
    return out


def _writes(fn: Function) -> set:
    """Canonical names of the state variables fn transitively writes.

    Canonical names, not object identity: before/after are separate Slither
    compilations, so no state-variable object is shared between them.
    """
    return {v.canonical_name for v in fn.all_state_variables_written()}


def _classify(contract, var_name: str) -> tuple[list, list]:
    """(one-shot writers, unguarded run-time writers) of `var_name`."""
    oneshot: list = []
    unguarded: list = []
    for fn in contract.functions:
        if not fn.is_implemented or fn.is_shadowed:
            continue
        if var_name not in _writes(fn):
            continue
        # Constructors reach here for the WHOLE inheritance chain, which is the
        # point - see the module docstring on why contract.constructor is not
        # used.
        if fn.is_constructor or has_init_guard(fn):
            oneshot.append(fn)
            continue
        if constrains_msg_sender(fn, contract):
            continue  # 10.2
        if not _externally_reachable(fn, contract):
            continue  # 10.5
        unguarded.append(fn)
    return oneshot, unguarded


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 10 fires on this before/after pair."""
    # 10.3
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)
    before_contracts = {c.name: c for c in before.contracts_derived}

    for contract_a in after.contracts_derived:
        contract_b = before_contracts.get(contract_a.name)
        if contract_b is None:
            continue  # new contract at N: nothing migrated, nothing regressed

        gate_a = _gate_vars(contract_a)
        value_a = _value_vars(contract_a)
        for var in gate_a | value_a:
            var_name = var.canonical_name
            var_class = "gate" if var in gate_a else "value" 

            oneshot_b, unguarded_b = _classify(contract_b, var_name)
            if not oneshot_b:
                continue  # T1: never established one-shot -> no control to lose
            if unguarded_b:
                continue  # T2: already reachable unguarded -> never safe

            _, unguarded_a = _classify(contract_a, var_name)
            if not unguarded_a:
                continue  # T3: still no unguarded run-time writer

            # 10.8 - RULE BOUNDARY. Names of N-1 functions that already wrote
            # this gate variable, whatever their guard state. An unguarded
            # writer at N whose name is in here did not APPEAR; it survived and
            # changed, which Rule 1 / Rule 3b already own.
            wrote_before = {
                fn.name
                for fn in contract_b.functions
                if fn.is_implemented
                and not fn.is_shadowed
                and var_name in _writes(fn)
            }

            for fn_a in unguarded_a:
                if fn_a.name in wrote_before:
                    continue  # 10.8
                # Attribute only to code this repo declares: an unguarded writer
                # inside node_modules is library behaviour, not this commit's
                # regression. Note this filter is applied to the FIRE only,
                # never to T2 - a pre-existing hole in library code must still
                # be able to prove the contract was never safe.
                if not declared_in_repo(fn_a):
                    continue
                if not accept_finding(fn_a, case_meta):
                    continue  # 10.4
                emit(
                    case_meta, RULE_ID, decl=fn_a,
                    detail=(
                        f"{contract_a.name}.{var.name} was established only at "
                        f"construct time (or behind a one-shot initializer) at "
                        f"commit N-1, with no unguarded run-time writer; at "
                        f"commit N it is written by "
                        f"{fn_a.contract_declarer.name}.{fn_a.full_name}, which "
                        f"is externally reachable with neither a one-shot guard "
                        f"nor a msg.sender constraint"
                    ),
                    evidence={
                        "owasp": "SC01",
                        "trigger": "control-migrated-to-unguarded-entry-point",
                        "gate_variable": var_name,
                        "variable_class": var_class,
                        "oneshot_writers_before": [
                            f"{f.contract_declarer.name}.{f.full_name}"
                            for f in oneshot_b
                        ],
                        "unguarded_writers_before": [],
                        "unguarded_writer_after": (
                            f"{fn_a.contract_declarer.name}.{fn_a.full_name}"
                        ),
                        "visibility_after": fn_a.visibility,
                        # Found live (2026-08-26), scanning the real 88mph
                        # NFT.init() regression this rule exists to catch: this
                        # key was never set, so evidence field 4 (reachability)
                        # read writes_state_after as ABSENT (not False) and
                        # capped every rule 10 finding at CANDIDATE forever,
                        # regardless of liveness - the same defect SHAPE as
                        # RC-VERDICT1, on a single-emit-site rule this time. True
                        # by construction: `fn_a` IS T3's unguarded writer of
                        # `var`, so it always writes state; matches the
                        # `bool(fn.all_state_variables_written())` idiom used at
                        # every other rule's emit site rather than a bare literal.
                        "writes_state_after": bool(fn_a.all_state_variables_written()),
                    },
                )
                return True

    return False
