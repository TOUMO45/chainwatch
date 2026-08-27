"""RULE 4 - SC09: Integer Overflow/Underflow regression.

Trigger (RULES.md), all three forms:
  A. pragma LOWERED from >=0.8.0 to <0.8.0, arithmetic left plain (P4-03) -
     the compiler's global checks vanish while the source looks unchanged.
  B. SafeMath usage removed while the pragma STAYS <0.8.0 (P4-02) - nothing
     replaces the library's guards.
  C. `unchecked { }` added around arithmetic that was checked at N-1, on
     solc >=0.8.0 (P4-01).

The rule is PRAGMA-AWARE by construction: every branch above is selected by
comparing the solidity pragma at N-1 against the one at N, read from Slither's
parsed `Pragma` directives for the analysed file (never from source text - the
text-level pragma read in _shared is build configuration, used only to pick a
compiler binary). A pragma is treated as guaranteeing built-in checks iff the
LOWEST version it admits is >= 0.8.0, so `>=0.7.0` is correctly read as
unprotected even though 0.8.x satisfies it.

EXCLUSION 4.5 - the make-or-break check. SafeMath removed AND pragma raised to
>=0.8.0 in the same commit is a safe migration: the compiler's own checks now do
what the library did, so the code is no less protected at N than at N-1. That is
the single most common commit in mature Solidity history; firing on it would put
a false positive on nearly every 0.8 upgrade in existence. It is handled by an
explicit early return (not as a side effect of branch ordering) so it cannot be
lost to a later refactor - see `run()`.

Other exclusions:
  4.1 unchecked around a provably-bounded loop counter. The bound is read
      STRUCTURALLY off the loop condition: an IFLOOP node comparing the counter
      against a constant, or against a value derived from a `.length` operation.
      Comments and variable names are never consulted (N4-02).
  4.2 a require()/assert() DOMINATING the arithmetic bounds every operand by a
      constant, and the worst-case result still fits the result type (N4-03).
  4.3/4.4 unchecked subtraction with a dominating require(minuend >= subtrahend)
      - the require-then-unchecked-subtract idiom of production ERC20/vault
      code (N4-04).
  4.6 test/mock path, matched on repo-relative `source_path` by whole segments,
      shared with Rules 1.6 / 2a.2.8 / 2b / 5.6 / 6.7 (N4-05).

Dominance is Slither's own CFG dominator set, so "earlier in the same function"
means the guard is on every path to the arithmetic - not merely above it in the
source.

DESIGN-L1 (LIMITATIONS.md): before.sol and after.sol are separate compilations,
so no object identity survives the diff. Every cross-commit comparison here is
done on a stable STRING key - `_arith_key` = (function canonical name, operation
type, sorted operand keys), where an operand key is a canonical/variable name, a
constant's value, or (for an index access like `deposits[msg.sender]`) the
canonical name of the state variable it points to. `i++` at N-1 and `++i` at N
therefore produce the SAME key, which is what makes N4-02 a real test of
exclusion 4.1 rather than an accidental miss.

Verdict: True (CONFIRMED) or False. Rule 4 has no CANDIDATE mode - each of the
three triggers is a fact about the compiler's behaviour, not an intent judgement.

Known conservative simplifications (all bias toward silence, never toward a
false positive):
  - An index-access operand is keyed by its base state variable, so
    `bal[a] - bal[b]` guarded by `require(bal[a] >= bal[b])` is accepted. A
    guard on a DIFFERENT key of the same mapping would also be accepted.
  - Nested sub-expressions that reach the operation as compiler temporaries key
    as "tmp"; two structurally different such operations in one function with
    the same operator can share a key.
  - Only require/assert conditions are read as bounding guards; an
    `if (x > y) revert Custom();` guard is not, so such code stays quiet.
"""

from decimal import Decimal, InvalidOperation
from pathlib import Path

from slither.core.cfg.node import NodeType
from slither.core.expressions.literal import Literal
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    Length,
    LibraryCall,
)
from slither.slithir.variables import Constant, ReferenceVariable, TemporaryVariable

from ._shared import emit, is_test_path_segments, parse, reachable, version_tuple

RULE_ID = "4"

# Operations that can overflow/underflow. Division and modulo cannot (a revert
# on division by zero is not an SC09 concern), so they are not tracked.
ARITH_OPS = {
    BinaryType.ADDITION,
    BinaryType.SUBTRACTION,
    BinaryType.MULTIPLICATION,
    BinaryType.POWER,
}

COMPARISONS = {
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
}

CHECKED_ARITHMETIC_SINCE = (0, 8, 0)

# A loop bound at or above this cannot be argued to be reachable; below it, an
# increment of a counter that starts at zero provably cannot wrap a uint256.
SAFE_LOOP_BOUND = 1 << 255


# --------------------------------------------------------------------------
# pragma
# --------------------------------------------------------------------------


def _constraints(expr: str) -> list[tuple[str, str]]:
    """`>=0.7.0 <0.9.0` -> [('>=', '0.7.0'), ('<', '0.9.0')]; `^0.8.0` ->
    [('^', '0.8.0')]. Hand-scanned rather than regexed, over the version
    expression Slither already parsed out of the pragma directive."""
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(expr):
        op = ""
        while i < len(expr) and expr[i] in "<>=^~":
            op += expr[i]
            i += 1
        num = ""
        while i < len(expr) and (expr[i].isdigit() or expr[i] == "."):
            num += expr[i]
            i += 1
        if num:
            out.append((op, num))
        elif not op:
            i += 1
    return out


def _expr_floor(expr: str) -> tuple:
    """Lowest solc version a pragma expression admits. `^0.7.6` -> (0,7,6);
    `>=0.7.0 <0.9.0` -> (0,7,0); an expression with no lower bound -> (0,0,0)."""
    floor = (0, 0, 0)
    for op, num in _constraints(expr):
        if op in ("<", "<="):
            continue  # upper bound only
        version = version_tuple(num)
        if version and version > floor:
            floor = version
    return floor


def _file_of(obj) -> str:
    try:
        return str(Path(obj.source_mapping.filename.absolute).resolve())
    except Exception:
        return ""


def _pragma_floor(sl, path) -> tuple:
    """Lowest solc version the ANALYSED file's solidity pragma admits.

    Directives from imported files (node_modules, other sources) are ignored:
    the checks that matter are the ones applied to this file's own arithmetic.
    """
    target = str(Path(path).resolve())
    floor = None
    for unit in sl.compilation_units:
        for directive in unit.pragma_directives:
            if not directive.is_solidity_version:
                continue
            if _file_of(directive) != target:
                continue
            candidate = _expr_floor(directive.version)
            if floor is None or candidate < floor:
                floor = candidate
    return floor if floor is not None else (0, 0, 0)


def _has_builtin_checks(floor: tuple) -> bool:
    """True iff every solc version the pragma admits emits overflow checks."""
    return floor >= CHECKED_ARITHMETIC_SINCE


# --------------------------------------------------------------------------
# cross-commit keys (DESIGN-L1) and site collection
# --------------------------------------------------------------------------


def _var_key(var) -> str:
    if isinstance(var, ReferenceVariable):
        origin = var.points_to_origin
        if origin is not None and origin is not var:
            return _var_key(origin)
        return "ref"
    if isinstance(var, Constant):
        return f"const:{var.value}"
    if isinstance(var, TemporaryVariable):
        return "tmp"
    name = getattr(var, "canonical_name", None) or getattr(var, "name", None)
    return str(name if name else var)


def _arith_key(fn, ir) -> tuple:
    return (
        fn.canonical_name,
        str(ir.type),
        tuple(sorted(_var_key(v) for v in ir.read)),
    )


def _own_functions(sl, path) -> list:
    """Functions and modifiers declared by non-library contracts in `path`."""
    target = str(Path(path).resolve())
    out, seen = [], set()
    for contract in sl.contracts:
        if contract.is_library or _file_of(contract) != target:
            continue
        for fn in list(contract.functions) + list(contract.modifiers):
            if fn.contract_declarer is not contract:
                continue
            if fn.canonical_name in seen:
                continue
            seen.add(fn.canonical_name)
            out.append(fn)
    return out


def _arith_sites(sl, path) -> list:
    """[(fn, node, ir)] for every overflow-capable operation in the file's own
    non-library contracts. Library bodies are dependency code - a SafeMath-style
    wrapper's internal `a + b` is guarded by its own require."""
    sites = []
    for fn in _own_functions(sl, path):
        for node in fn.nodes:
            for ir in node.irs:
                if isinstance(ir, Binary) and ir.type in ARITH_OPS:
                    sites.append((fn, node, ir))
    return sites


def _is_unchecked(node) -> bool:
    scope = getattr(node, "scope", None)
    return scope is not None and not getattr(scope, "is_checked", True)


# --------------------------------------------------------------------------
# guards: 4.1 / 4.2 / 4.3 / 4.4
# --------------------------------------------------------------------------


def _literal_int(text: str):
    raw = str(text).strip().replace("_", "")
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(Decimal(raw))
    except (TypeError, ValueError, InvalidOperation):
        return None


def _const_int(var):
    """Integer value of a compile-time-constant operand, else None."""
    if isinstance(var, Constant):
        return _literal_int(var.value)
    if isinstance(var, StateVariable) and var.is_constant:
        if isinstance(var.expression, Literal):
            return _literal_int(var.expression.value)
    return None


def _guards(fn) -> list:
    """[(node, comparison type, left key, left var, right key, right var)] for
    every require()/assert() condition in fn's own body."""
    out = []
    for node in fn.nodes:
        if not node.contains_require_or_assert():
            continue
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type in COMPARISONS and len(ir.read) == 2:
                left, right = ir.read[0], ir.read[1]
                out.append(
                    (node, ir.type, _var_key(left), left, _var_key(right), right)
                )
    return out


def _upper_bound(var, key, node, guards):
    """Smallest constant upper bound on an operand established by a guard that
    dominates `node`, or the operand's own value when it is a constant."""
    own = _const_int(var)
    best = own
    for g_node, g_type, left_key, left_var, right_key, right_var in guards:
        if g_node not in node.dominators:
            continue
        bound = None
        if g_type in (BinaryType.LESS, BinaryType.LESS_EQUAL) and left_key == key:
            bound = _const_int(right_var)
        elif g_type in (BinaryType.GREATER, BinaryType.GREATER_EQUAL) and right_key == key:
            bound = _const_int(left_var)
        if bound is not None and (best is None or bound < best):
            best = bound
    return best


def _ordered(minuend_key, subtrahend_key, node, guards) -> bool:
    """True iff a dominating guard proves minuend >= subtrahend (4.3 / 4.4)."""
    for g_node, g_type, left_key, _lv, right_key, _rv in guards:
        if g_node not in node.dominators:
            continue
        if (
            g_type in (BinaryType.GREATER, BinaryType.GREATER_EQUAL)
            and left_key == minuend_key
            and right_key == subtrahend_key
        ):
            return True
        if (
            g_type in (BinaryType.LESS, BinaryType.LESS_EQUAL)
            and left_key == subtrahend_key
            and right_key == minuend_key
        ):
            return True
    return False


def _bounded_counters(fn) -> set:
    """Keys of variables a loop condition provably bounds (4.1).

    Structural only: an IFLOOP node comparing the variable against a constant
    below SAFE_LOOP_BOUND, or against a value produced by a `.length` read.
    """
    length_vars = set()
    for node in fn.nodes:
        for ir in node.irs:
            if isinstance(ir, Length):
                length_vars.add(str(ir.lvalue))
            elif isinstance(ir, Assignment) and str(ir.rvalue) in length_vars:
                length_vars.add(str(ir.lvalue))

    bounded = set()
    for node in fn.nodes:
        if node.type != NodeType.IFLOOP:
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type not in COMPARISONS:
                continue
            if len(ir.read) != 2:
                continue
            left, right = ir.read[0], ir.read[1]
            if ir.type in (BinaryType.LESS, BinaryType.LESS_EQUAL):
                counter, bound = left, right
            else:
                counter, bound = right, left
            bound_value = _const_int(bound)
            if (bound_value is not None and bound_value < SAFE_LOOP_BOUND) or str(
                bound
            ) in length_vars:
                bounded.add(_var_key(counter))
    return bounded


def _type_max(ir) -> int:
    text = str(getattr(ir.lvalue, "type", "") or "")
    if text.startswith("uint"):
        bits = text[4:]
        return (1 << (int(bits) if bits.isdigit() else 256)) - 1
    if text.startswith("int"):
        bits = text[3:]
        return (1 << ((int(bits) if bits.isdigit() else 256) - 1)) - 1
    return (1 << 256) - 1


def _is_protected(node, ir, counters, guards) -> bool:
    """True iff an exclusion proves this operation cannot overflow/underflow."""
    keys = [_var_key(v) for v in ir.read]
    lvalue_key = _var_key(ir.lvalue)

    # 4.1 - loop counter stepped by a constant, bounded by its loop condition.
    if (
        ir.type in (BinaryType.ADDITION, BinaryType.SUBTRACTION)
        and lvalue_key in counters
        and lvalue_key in keys
        and any(isinstance(v, Constant) for v in ir.read)
    ):
        return True

    if len(ir.read) != 2:
        return False

    # 4.3 / 4.4 - subtraction whose ordering a dominating require establishes.
    if ir.type is BinaryType.SUBTRACTION:
        return _ordered(keys[0], keys[1], node, guards)

    # 4.2 - every operand bounded by a dominating require, worst case in range.
    if ir.type in (BinaryType.ADDITION, BinaryType.MULTIPLICATION):
        low = _upper_bound(ir.read[0], keys[0], node, guards)
        high = _upper_bound(ir.read[1], keys[1], node, guards)
        if low is None or high is None:
            return False
        worst = low + high if ir.type is BinaryType.ADDITION else low * high
        return worst <= _type_max(ir)

    return False


# --------------------------------------------------------------------------
# SafeMath, by structure rather than by name
# --------------------------------------------------------------------------


def _is_checked_arith_wrapper(fn) -> bool:
    """True iff `fn` is a library function that performs integer arithmetic and
    guards it - the structure of SafeMath.add/sub/mul.

    Never matches on the name "SafeMath" (CHARTER.md rule 4 forbids name-string
    matching), so a vendored copy, a renamed fork and an inlined equivalent are
    all recognised, and a library merely called SafeMath that guards nothing is
    not.
    """
    contract = fn.contract_declarer
    if contract is None or not contract.is_library:
        return False
    returns = fn.return_type or []
    if not returns or not all(str(t).startswith(("uint", "int")) for t in returns):
        return False
    if not fn.parameters or not all(
        str(p.type).startswith(("uint", "int")) for p in fn.parameters
    ):
        return False
    has_arith = any(
        isinstance(ir, Binary) and ir.type in ARITH_OPS
        for node in fn.nodes
        for ir in node.irs
    )
    has_guard = any(node.contains_require_or_assert() for node in fn.nodes)
    return has_arith and has_guard


# --------------------------------------------------------------------------
# triggers
# --------------------------------------------------------------------------


def _unprotected_arith_keys(sl, path) -> set:
    """Keys of operations that nothing proves safe - the payload a pragma
    downgrade exposes. An operation the guards already cover is not exposed by
    losing the compiler's checks, so it is not counted."""
    exposed = set()
    cache: dict = {}
    for fn, node, ir in _arith_sites(sl, path):
        if fn.canonical_name not in cache:
            cache[fn.canonical_name] = (_bounded_counters(fn), _guards(fn))
        counters, guards = cache[fn.canonical_name]
        if _is_protected(node, ir, counters, guards):
            continue
        exposed.add(_arith_key(fn, ir))
    return exposed


def _site_for_key(sl, path, keys):
    """First (fn, node, ir) in `path`'s own code whose _arith_key is in `keys`.
    Attribution only - the verdict is already decided by the caller."""
    for fn, node, ir in _arith_sites(sl, path):
        if _arith_key(fn, ir) in keys:
            return fn, node, ir
    return None, None, None


def _reachable_checked_calls(fn) -> int:
    """Checked-arith library calls anywhere reachable from `fn` - itself, its
    modifiers, and every internal helper it transitively calls.

    RC-EXTRACT1's fix (measured on Aave v2 `UniswapLiquiditySwapAdapter.
    executeOperation`): the checked call is not removed, it is EXTRACTED into
    a NEW helper (`_swapLiquidity`). `fn`'s own body never changes, so a
    same-function check (the pre-fix version of this rule) finds nothing to
    compare and stays silent - the caller "kept its raw loop counter and lost
    its visible SafeMath" with no diff inside the caller at all. Counting
    reachable calls, the way rules 2a/2b already resolve delegated bodies via
    `after_call_writes_resolved`, is what makes the extraction visible.
    """
    total = 0
    for f in reachable(fn):
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, LibraryCall) and _is_checked_arith_wrapper(ir.function):
                    total += 1
    return total


def _reachable_plain_site(fn):
    """First (containing fn, node, ir) with plain arithmetic anywhere
    reachable from `fn`. Existence check only - proves there is something for
    the lost checked call to have exposed, not which specific site it was."""
    for f in reachable(fn):
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, Binary) and ir.type in ARITH_OPS:
                    return f, node, ir
    return None, None, None


def _safemath_removed(before, before_path, after, after_path, case_meta=None) -> bool:
    """True iff an entry point declared in this file reached at least one
    checked-arithmetic library call at N-1 - directly, through a modifier, or
    through an internal helper - and reaches none at N, while still reaching
    plain arithmetic somewhere.

    Attribution stays on the ENTRY function (`fn_after`), never on the
    resolved helper: same convention as rule2b's RC-INLINE2 fix, so file/line
    always come from the one object `emit()` was told about and a delegated
    body in a different file can never produce a mismatched (file, line).
    """
    entries_before = {fn.canonical_name: fn for fn in _own_functions(before, before_path)}
    for fn_after in _own_functions(after, after_path):
        name = fn_after.canonical_name
        fn_before = entries_before.get(name)
        if fn_before is None:
            continue  # new-at-N entry point: out of scope for a diff rule
        checked_before = _reachable_checked_calls(fn_before)
        if not checked_before:
            continue
        if _reachable_checked_calls(fn_after):
            continue  # still reaches a checked call somewhere: not a regression
        site_fn, _node, _ir = _reachable_plain_site(fn_after)
        if site_fn is None:
            continue  # lost the wrapper but reaches no arithmetic at all now
        via = "directly" if site_fn is fn_after else f"through {site_fn.canonical_name}"
        emit(
            case_meta, RULE_ID, decl=fn_after,
            detail=(
                f"{name} reached a checked-arithmetic library call at commit N-1 "
                f"and reaches none at commit N ({via} exposes plain arithmetic now), "
                f"with the pragma still below 0.8.0 (no compiler checks)"
            ),
            evidence={
                "owasp": "SC09", "trigger": "safemath-removed",
                "visibility_after": getattr(fn_after, "visibility", None),
                "writes_state_after": bool(fn_after.all_state_variables_written()),
                "wrapper_calls_before": checked_before, "wrapper_calls_after": 0,
                "compiler_checked": False,
            },
        )
        return True
    return False


def _unchecked_added(before, before_path, after, after_path, case_meta=None) -> bool:
    """Trigger C: arithmetic checked at N-1, inside `unchecked { }` at N, and
    not covered by an exclusion."""
    checked_before, unchecked_before = set(), set()
    for fn, node, ir in _arith_sites(before, before_path):
        key = _arith_key(fn, ir)
        (unchecked_before if _is_unchecked(node) else checked_before).add(key)

    cache: dict = {}
    for fn, node, ir in _arith_sites(after, after_path):
        if not _is_unchecked(node):
            continue
        key = _arith_key(fn, ir)
        if key in unchecked_before:
            continue  # already unchecked at N-1: no change, not a regression
        if key not in checked_before:
            continue  # new arithmetic at N: Rule 4 is a diff rule
        if fn.canonical_name not in cache:
            cache[fn.canonical_name] = (_bounded_counters(fn), _guards(fn))
        counters, guards = cache[fn.canonical_name]
        if _is_protected(node, ir, counters, guards):
            continue  # 4.1 / 4.2 / 4.3 / 4.4
        emit(
            case_meta, RULE_ID, decl=fn, node=node,
            detail=(
                f"{fn.canonical_name}: arithmetic ({str(ir.type)}) that the compiler "
                f"checked at commit N-1 is inside an `unchecked` block at commit N, "
                f"and no guard bounds it"
            ),
            evidence={
                "owasp": "SC09", "trigger": "unchecked-block-added",
                "visibility_after": getattr(fn, "visibility", None),
                "writes_state_after": bool(fn.all_state_variables_written()),
                "operation": str(ir.type), "compiler_checked": True,
                "checked_before": True, "checked_after": False,
            },
        )
        return True
    return False


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 4 fires on this before/after pair."""
    # Exclusion 4.6: test/mock path, on repo-relative source_path by whole
    # segments. A fixture that declares no source_path falls back to after_path.
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)

    floor_before = _pragma_floor(before, before_path)
    floor_after = _pragma_floor(after, after_path)
    checked_before = _has_builtin_checks(floor_before)
    checked_after = _has_builtin_checks(floor_after)

    # ---- EXCLUSION 4.5, stated before any trigger is considered ----------
    # The pragma was raised across the 0.8.0 boundary. Whatever manual
    # protection the commit dropped, the compiler now emits a revert on every
    # overflow and underflow in this file, so the code is not less protected at
    # N than at N-1. This is the 0.8 migration commit that thousands of repos
    # made; firing here would make Rule 4 unusable on real code. Quiet, always,
    # and deliberately BEFORE the trigger chain so no future reordering can
    # reach a fire through some other branch.
    if not checked_before and checked_after:
        return False

    # ---- Trigger B: SafeMath removed with the pragma still below 0.8.0 ----
    if not checked_before and not checked_after:
        return _safemath_removed(before, before_path, after, after_path, case_meta)

    # ---- Trigger A: pragma lowered out of the checked range ---------------
    if checked_before and not checked_after:
        # Only a regression if arithmetic that existed at N-1 is now exposed:
        # a downgrade that also re-introduced SafeMath (arithmetic moved into
        # guarded library calls) leaves nothing unprotected, and new-at-N code
        # is out of scope for a diff rule.
        exposed = _unprotected_arith_keys(after, after_path)
        if not exposed:
            return False
        before_keys = {_arith_key(fn, ir) for fn, _n, ir in _arith_sites(before, before_path)}
        hit = exposed & before_keys
        if not hit:
            return False
        fn_a, node, ir = _site_for_key(after, after_path, hit)
        emit(
            case_meta, RULE_ID, decl=fn_a, node=node,
            detail=(
                f"the pragma was lowered out of the compiler-checked range "
                f"({'.'.join(map(str, floor_before))} -> "
                f"{'.'.join(map(str, floor_after))}), exposing arithmetic in "
                f"{fn_a.canonical_name if fn_a else 'this file'} that nothing else guards"
            ),
            evidence={
                "owasp": "SC09", "trigger": "pragma-lowered",
                "visibility_after": getattr(fn_a, "visibility", None),
                "writes_state_after": bool(
                    fn_a.all_state_variables_written()) if fn_a else None,
                "pragma_before": ".".join(map(str, floor_before)),
                "pragma_after": ".".join(map(str, floor_after)),
                "exposed_operations": len(hit),
                "operation": str(ir.type) if ir is not None else None,
            },
        )
        return True

    # ---- Trigger C: unchecked{} added on >=0.8.0 --------------------------
    # Only meaningful when both commits compile with built-in checks: below
    # 0.8.0 an `unchecked` block does not exist and no arithmetic is checked.
    if checked_before and checked_after:
        return _unchecked_added(before, before_path, after, after_path, case_meta)

    return False
