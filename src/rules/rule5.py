"""RULE 5 - SC06: Unchecked External Calls regression.

Trigger (RULES.md): the return value of a .call/.delegatecall/.staticcall/.send,
or a raw ERC20 transfer/transferFrom, was checked at N-1 and is not at N; OR a
try/catch around an external call was removed at N.

Detection is semantic (Slither IR/CFG). For each external call in the function's
own body we record a stable cross-commit key and whether its result is CHECKED -
either its return value flows (via forward taint) into a guard, or the call sits
inside a try/catch. A key that was checked at N-1 and is present-but-unchecked at
N is the regression.

DESIGN-L1 (LIMITATIONS.md): before.sol and after.sol are separate Slither
compilations, so call/variable objects are distinct instances across commits. The
per-commit comparison is done on stable STRING keys (call kind, resolved
destination canonical-name/constant, function name), never on object identity.

Verdict (three-verdict model, same as 2a/2b/verdict-less rules):
  True         -> CONFIRMED: value-bearing (.call{value:}) or raw-ERC20
                  transfer/transferFrom return-check removed, or a try/catch
                  removed (P5-01/02/03).
  "candidate"  -> a best-effort, no-value, non-ERC20 notification .call whose
                  check was dropped (5.3) - non-security-relevance cannot be
                  proven from one repo, so RULES.md caps it at CANDIDATE (N5-05).
  False        -> quiet.

Exclusions handled:
  5.1 SafeERC20 wrapper at N -> the raw transfer key is gone (safeTransfer is a
      LibraryCall, excluded), so there is no unchecked raw-transfer regression.
  5.2 return value checked later in the function -> the call is still CHECKED at
      N (forward taint reaches a guard), so no regression.
  5.4 known non-reverting target (address(this) / precompile 0x01..0x0a) -> the
      regressed call's destination is trusted, dropped.
  5.6 test/mock path -> segment-based source_path match, quiet.
  no-change: unchecked at N-1 and N (key not in the N-1 checked set) -> quiet.

Rule 1 / Rule 6 boundary: a removed check on an external-call RETURN value is
SC06, not access control (Rule 1) or input validation (Rule 6). Those rules skip
call-return guards (see _shared.guard_checks_call_return), so a param- or
msg.sender-bearing Rule 5 case is owned here alone (fixture P5-04).

Not implemented (no fixture): 5.5 in its general form is covered incidentally -
generic high-level typed calls are not treated as return-checkable here, so their
check removal is never flagged.
"""

from pathlib import Path

from slither.core.declarations import SolidityVariable
from slither.core.cfg.node import NodeType
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import (
    Assignment,
    HighLevelCall,
    LibraryCall,
    LowLevelCall,
    Send,
    Transfer,
    TypeConversion,
)
from slither.slithir.variables import Constant

from ._shared import (
    ERC20_RETURN_FNS,
    accept_finding,
    emit,
    external_call_return_taint,
    guard_checks_call_return,
    is_test_path_segments,
    parse,
)
from .rule1 import _candidate_map

RULE_ID = "5"

# Precompile address range (identity=0x04, ecrecover=0x01, ... point-eval=0x0a).
_PRECOMPILE_MAX = 0x0A

_CALL_OPS = (LowLevelCall, Send, Transfer, HighLevelCall)


def _guard_nodes_all(fn):
    for node in fn.nodes:
        if node.contains_require_or_assert() or node.is_conditional(include_loop=False):
            yield node


def _resolve_dest(dest, defmap, depth: int = 0):
    """Follow TypeConversion/Assignment temporaries back to the underlying
    variable or constant a call destination came from."""
    if depth > 8:
        return dest
    d = defmap.get(dest)
    if d is None:
        return dest
    reads = [r for r in getattr(d, "read", [])]
    if len(reads) == 1:
        return _resolve_dest(reads[0], defmap, depth + 1)
    return dest


def _dest_key_and_trust(resolved) -> tuple:
    """(stable string key for the destination, is-trusted-non-reverting)."""
    if isinstance(resolved, Constant):
        val = resolved.value
        try:
            ival = int(val)
        except (TypeError, ValueError):
            ival = None
        trusted = ival is not None and 1 <= ival <= _PRECOMPILE_MAX
        return (f"const:{val}", trusted)
    if isinstance(resolved, SolidityVariable):
        name = str(resolved)
        # address(this) is a known non-reverting self target.
        return (f"sol:{name}", name == "this")
    if isinstance(resolved, (StateVariable, LocalVariable)):
        return (f"var:{resolved.canonical_name}", False)
    return (f"other:{resolved}", False)


def _call_records(fn) -> list:
    """One record per external call in fn's OWN body. Each record is a dict with
    stable string fields plus per-commit checked/kind flags."""
    # Map temporaries to their defining TypeConversion/Assignment for dest resolve.
    defmap = {}
    for node in fn.nodes:
        for ir in node.irs:
            if isinstance(ir, (TypeConversion, Assignment)) and ir.lvalue is not None:
                defmap[ir.lvalue] = ir

    taint = external_call_return_taint(fn)
    guard_nodes = list(_guard_nodes_all(fn))

    records = []
    pos = 0  # RC-2: per-site ordinal within fn's own external-call iteration order.
    for node in fn.nodes:
        in_try = node.type == NodeType.TRY
        for ir in node.irs:
            if not isinstance(ir, _CALL_OPS):
                continue
            if isinstance(ir, LibraryCall):
                continue  # SafeERC20-style wrapper: checking is internal (5.1)

            fname = getattr(ir, "function_name", None)
            if isinstance(ir, HighLevelCall):
                if fname in ERC20_RETURN_FNS:
                    kind = "erc20"
                else:
                    kind = "high"  # generic typed call - only try/catch-relevant
            else:
                kind = "low"

            resolved = _resolve_dest(getattr(ir, "destination", None), defmap)
            dest_key, trusted = _dest_key_and_trust(resolved)

            # Checked = return value tainted into a guard, or inside try/catch.
            checked_by_return = False
            if ir.lvalue is not None:
                for gnode in guard_nodes:
                    if guard_checks_call_return(gnode, taint):
                        # taint is function-wide; confirm THIS call's lvalue reaches
                        # the guard by checking the guard reads something tainted
                        # from this call's lvalue specifically.
                        if _lvalue_reaches_guard(fn, ir.lvalue, gnode):
                            checked_by_return = True
                            break

            records.append(
                {
                    "key": (kind if kind != "high" else "high", dest_key, str(fname), pos),
                    "kind": kind,
                    "checked": checked_by_return or in_try,
                    "in_try": in_try,
                    "value_bearing": getattr(ir, "call_value", None) is not None,
                    "trusted": trusted,
                    # Attribution only (never part of `key`, so R5-L1's
                    # within-commit injectivity is unaffected).
                    "node": node,
                    "dest": dest_key,
                    "method": str(fname),
                }
            )
            pos += 1
    return records


def _lvalue_reaches_guard(fn, lvalue, gnode) -> bool:
    """Forward-taint from a single call lvalue and test whether gnode reads it."""
    tainted = {lvalue}
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
    for ir in gnode.irs:
        for v in getattr(ir, "read", []):
            if v in tainted:
                return True
    return False


def _dest_label(dest_key: str) -> str:
    """Human-readable form of a destination key, for the report text only.

    The key itself is never changed: its exact string is half of the
    cross-commit call identity, and R5-L1's within-commit injectivity fix is
    built on it. This only decides how it READS. An `other:` key means the
    destination is a Slither temporary that resolved to no named variable, so
    printing it leaks an internal name like `other:REF_61` and tells a reader
    nothing; say what is actually true instead.
    """
    prefix, _, rest = str(dest_key).partition(":")
    if prefix == "var":
        return rest.rsplit(".", 1)[-1] if rest else "a variable"
    if prefix == "sol":
        return rest
    if prefix == "const":
        return f"the fixed address {rest}"
    return "an unresolved destination"


def _emit5(case_meta, fn_a, ar, what: str, severity: str = "CONFIRMED") -> None:
    """One attribution record per regressed CALL SITE (Rule 5 is the only rule
    that can legitimately find several in one function - the ordinal in `key`
    keeps them distinct)."""
    emit(
        case_meta, RULE_ID, decl=fn_a, node=ar.get("node"), severity=severity,
        detail=(
            f"{fn_a.canonical_name}: {what} the {ar['kind']} call to "
            f"{ar['method']}() on {_dest_label(ar['dest'])}; "
            f"a failure now passes silently"
        ),
        evidence={
            "owasp": "SC06", "call_kind": ar["kind"],
            "destination": _dest_label(ar["dest"]),
            "destination_key": ar["dest"],
            "method": ar["method"], "value_bearing": ar["value_bearing"],
            "checked_before": True, "checked_after": False,
            "visibility_after": fn_a.visibility,
            "writes_state_after": bool(fn_a.all_state_variables_written())
            or ar["value_bearing"],
            "was_in_try_catch": what.startswith("try/catch"),
        },
    )


def run(before_path: Path, after_path: Path, case_meta: dict):
    """Returns True (fire), "candidate" (5.3), or False (quiet)."""
    # Exclusion 5.6: test/mock path (segment-based, shared with the other rules).
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    before = parse(before_path)
    after = parse(after_path)

    before_map = _candidate_map(before)
    after_map = _candidate_map(after)

    confirmed = False
    candidate = False

    for key, (fn_b, _cb) in before_map.items():
        if key not in after_map:
            continue
        fn_a, _ca = after_map[key]

        # DESIGN-L2: only attribute a fire to a declaration in a file actually
        # changed in this commit. Applied before the per-call loop so no
        # confirmed / candidate flag is set from an unchanged imported file.
        if not accept_finding(fn_a, case_meta):
            continue

        brecs = _call_records(fn_b)
        arecs = _call_records(fn_a)

        # Calls checked at N-1, keyed by stable string key.
        before_checked = {}
        for r in brecs:
            if r["checked"]:
                before_checked[r["key"]] = r

        for ar in arecs:
            if ar["checked"]:
                continue  # still checked/guarded at N (covers 5.2)
            br = before_checked.get(ar["key"])
            if br is None:
                continue  # was not checked at N-1 (no-change / N5-06)
            if ar["trusted"]:
                continue  # 5.4 known non-reverting target
            # try/catch removal is always CONFIRMED, regardless of call kind.
            if br["in_try"]:
                confirmed = True
                _emit5(case_meta, fn_a, ar, "try/catch removed around")
                continue
            if ar["kind"] == "high":
                continue  # generic typed call return - not a Rule 5 subject (5.5)
            # Return-value check removed on a low-level or ERC20 call.
            if (
                ar["value_bearing"]
                or br["value_bearing"]
                or ar["kind"] == "erc20"
                or br["kind"] == "erc20"
            ):
                confirmed = True
                _emit5(case_meta, fn_a, ar, "return-value check removed on")
            else:
                # No value, not ERC20: best-effort notification hook (5.3).
                candidate = True
                _emit5(case_meta, fn_a, ar, "return-value check removed on",
                       severity="CANDIDATE")

    if confirmed:
        return True
    if candidate:
        return "candidate"
    return False
