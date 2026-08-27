"""RULE 3b - SC10: Initializer re-callable.

Trigger (RULES.md): a function that sets ownership/admin/critical config lost
its `initializer` modifier, or the `_disableInitializers()` call in the
constructor was removed.

All analysis is structural (Slither AST/IR + data dependency). No regex, no
modifier name matching:

  * "initialization guard" = a modifier that gates on a storage flag AND
    writes that same flag (one-shot). OpenZeppelin's `initializer` and
    `reinitializer(n)` both have this shape; `onlyInitializing` (reads
    _initializing, writes nothing) does not. Verified against the installed
    library source, not guessed.
  * "sets ownership/admin/critical config" = the function transitively writes
    a state variable that participates in a msg.sender-based access-control
    check somewhere in the contract (e.g. OwnableUpgradeable._owner).

Exclusions handled:
  3b.1 `reinitializer(n)`: still a one-shot guard, so the function is not
       freely re-callable -> quiet.
  3b.2 explicit manual `initialized` bool guard added inline: same structural
       test applied to the function's own body -> quiet.
  3b.3 function became internal/private and is only reached through a guarded
       caller -> quiet.
  3b.4 (as corrected in human review) DISCARD ONLY with affirmative proof the
       contract is never proxy-deployed - i.e. it has no one-shot init
       machinery at all. `_disableInitializers()` in the constructor is
       explicitly NOT grounds for discard: it protects the implementation
       contract's own storage, never the proxy's storage. Nothing in this
       module consults it as a suppressor.
"""

from pathlib import Path

from slither.core.declarations import Function

from ._shared import (
    accept_finding,
    access_control_state_vars,
    constrains_msg_sender,
    declared_in_repo,
    defines_init_machinery,
    emit,
    has_init_guard,
    is_oneshot_init_guard,
    is_test_path_segments,
    parse,
    reachable,
)

RULE_ID = "3b"


def _init_flag_vars(contract) -> set:
    """State flags used by the contract's one-shot init guards."""
    flags: set = set()
    for mod in contract.modifiers:
        if is_oneshot_init_guard(mod):
            flags.update(mod.all_state_variables_written())
    return flags


def _sets_critical_config(fn: Function, contract) -> bool:
    ac_vars = access_control_state_vars(contract)
    return bool(set(fn.all_state_variables_written()) & ac_vars)


def _externally_reachable(fn: Function, contract) -> bool:
    """Exclusion 3b.3: internal/private and every caller is itself guarded."""
    if fn.visibility in ("external", "public"):
        return True
    for other in contract.functions:
        if other == fn or other.visibility not in ("external", "public"):
            continue
        if fn in reachable(other) and not has_init_guard(other):
            if not constrains_msg_sender(other, contract):
                return True
    return False


def _candidate_functions(slither_obj) -> dict:
    """{(contract, function name): [functions]} for repo-declared functions."""
    out: dict = {}
    for contract in slither_obj.contracts_derived:
        for fn in contract.functions:
            if fn.is_constructor or not fn.is_implemented or fn.is_shadowed:
                continue
            if not declared_in_repo(fn):
                continue
            out.setdefault((contract.name, fn.name), []).append((fn, contract))
    return out


def _constructor_disables_init(contract) -> bool:
    """True iff the constructor writes the init flags (what
    _disableInitializers() does). Structural, not name-based."""
    ctor = contract.constructor
    if ctor is None:
        return False
    flags = _init_flag_vars(contract)
    if not flags:
        return False
    for f in reachable(ctor):
        if set(f.all_state_variables_written()) & flags:
            return True
    return False


def _contract_initializer(contract):
    """The contract's own critical-config initializer, if it has one - same
    identification criteria Trigger 1 uses (`has_init_guard` +
    `_sets_critical_config`), reused here for a different purpose: reachability
    evidence for Trigger 2 (see `run`, `_disableInitializers` removal).

    Trigger 2's regression is IN THE CONSTRUCTOR, but nothing calls a
    constructor twice - what actually becomes exploitable is the contract's
    OWN initializer, now callable directly on the implementation contract
    instead of only through the proxy. `visibility_after`/`writes_state_after`
    therefore describe THIS function, not the constructor `decl` is attributed
    to; file/line attribution is unaffected, since `decl` stays `contract_a`.
    """
    for fn in contract.functions:
        if has_init_guard(fn) and _sets_critical_config(fn, contract):
            return fn
    return None


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 3b fires on this before/after pair."""
    # Exclusion 3a.3-style test/mock path check.
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)

    before_fns = _candidate_functions(before)
    after_fns = _candidate_functions(after)
    after_contracts = {c.name: c for c in after.contracts_derived}

    # --- Trigger 1: an init-guarded critical-config function lost its guard.
    for (cname, fname), entries in before_fns.items():
        for fn_b, contract_b in entries:
            if not has_init_guard(fn_b):
                continue
            if not _sets_critical_config(fn_b, contract_b):
                continue

            contract_a = after_contracts.get(cname)
            if contract_a is None:
                continue  # contract gone at N: nothing to exploit

            # Exclusion 3b.4: discard ONLY with proof the contract is never
            # proxy-deployed, i.e. no one-shot init machinery remains.
            # _disableInitializers() is deliberately NOT consulted here.
            if not defines_init_machinery(contract_a):
                continue

            successors = after_fns.get((cname, fname), [])
            if not successors:
                continue  # function removed entirely at N

            for fn_a, _ in successors:
                if has_init_guard(fn_a):
                    continue  # 3b.1 / 3b.2: still one-shot guarded
                if not _sets_critical_config(fn_a, contract_a):
                    continue
                if not _externally_reachable(fn_a, contract_a):
                    continue  # 3b.3
                # DESIGN-L2: only attribute to a declaration in a file actually
                # changed in this commit.
                if not accept_finding(fn_a, case_meta):
                    continue
                emit(
                    case_meta, RULE_ID, decl=fn_a,
                    detail=(
                        f"{cname}.{fname} set critical configuration behind a one-shot "
                        f"initializer guard at commit N-1 and is callable without that "
                        f"guard at commit N, on a contract that still defines "
                        f"initializer machinery (proxy-deployed)"
                    ),
                    evidence={
                        "owasp": "SC10", "trigger": "initializer-guard-removed",
                        "init_guard_before": True, "init_guard_after": False,
                        "proxy_deployed": True,
                        "visibility_after": fn_a.visibility,
                        "writes_state_after": bool(fn_a.all_state_variables_written()),
                    },
                )
                return True

    # --- Trigger 2: constructor's _disableInitializers() removed.
    # NOTE: no fixture exercises this clause yet; it is spec-faithful but
    # currently unproven by the fixture set.
    for cname, contract_a in after_contracts.items():
        contract_b = next(
            (c for c in before.contracts_derived if c.name == cname), None
        )
        if contract_b is None:
            continue
        if not defines_init_machinery(contract_a):
            continue  # 3b.4: not proxy-deployed
        if _constructor_disables_init(contract_b) and not _constructor_disables_init(
            contract_a
        ):
            # DESIGN-L2: only attribute to a contract declared in a file
            # actually changed in this commit.
            if not accept_finding(contract_a, case_meta):
                continue
            initializer = _contract_initializer(contract_a)
            evidence = {
                "owasp": "SC10", "trigger": "disableInitializers-removed",
                "proxy_deployed": True,
                "disables_init_before": True, "disables_init_after": False,
            }
            if initializer is not None:
                # Reachability evidence describes the exposed INITIALIZER
                # (external, state-changing, callable directly on the
                # implementation contract now) - not the constructor, which
                # nothing calls twice. Absent when no critical-config
                # initializer is identifiable: incomplete evidence caps at
                # CANDIDATE rather than guessing.
                evidence["visibility_after"] = initializer.visibility
                evidence["writes_state_after"] = bool(
                    initializer.all_state_variables_written())
                evidence["exposed_initializer"] = initializer.full_name
            emit(
                case_meta, RULE_ID, decl=contract_a,
                detail=(
                    f"{cname}'s constructor called _disableInitializers() at commit N-1 "
                    f"and no longer does at commit N: the implementation contract can be "
                    f"initialized directly by anyone"
                    + (f" (via {initializer.full_name})" if initializer is not None else "")
                ),
                evidence=evidence,
            )
            return True

    return False
