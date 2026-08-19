"""Shared Slither-based semantic helpers for Chainwatch rules.

Everything here is AST/IR/data-dependency based. No regex on source text and
no modifier name-string matching (CHARTER.md rule 4, RULES.md Rule 1 note).
"""

import logging
import os
import shutil
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

# Per-checkout build configuration. A trajectory run analyses TWO checkouts at
# once - the N-1 worktree and the N worktree - and they do not necessarily share
# a dependency tree (a commit can add or drop a package). A single global REMAPS
# list can only describe one of them, so one side would silently compile against
# the other side's dependencies. Roots registered here win over REMAPS for any
# file inside them, longest prefix first. The scorer registers nothing and keeps
# using REMAPS exactly as before.
_ROOT_REMAPS: list[tuple[str, list[str]]] = []


def register_root(root, remaps) -> None:
    """Bind a checkout directory to the remappings its own commit needs.
    Re-registering a root replaces it rather than shadowing it."""
    key = str(Path(root).resolve()).replace("\\", "/")
    for i, (existing, _) in enumerate(_ROOT_REMAPS):
        if existing == key:
            _ROOT_REMAPS[i] = (key, list(remaps))
            return
    _ROOT_REMAPS.append((key, list(remaps)))


def clear_roots() -> None:
    _ROOT_REMAPS.clear()


def remaps_for(path) -> list[str]:
    """The remappings that apply to `path`: its registered checkout's, else the
    global REMAPS."""
    p = str(Path(path).resolve()).replace("\\", "/")
    best: tuple[str, list[str]] | None = None
    for root, remaps in _ROOT_REMAPS:
        if p == root or p.startswith(root + "/"):
            if best is None or len(root) > len(best[0]):
                best = (root, remaps)
    return list(best[1]) if best else list(REMAPS)


MSG_SENDER = SolidityVariableComposed("msg.sender")

TEST_PATH_MARKERS = ("test/", "tests/", "mock/", "mocks/", "script/", "scripts/")
TEST_NAME_MARKERS = ("Mock", "Harness")

for _name in ("CryticCompile", "Slither", "Printers", "Detectors"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

_PARSE_CACHE: dict[str, Slither] = {}
# Failures, memoised alongside successes. See `parse` for why this is not
# merely an optimisation and why its scope is already correct.
_PARSE_FAIL_CACHE: dict[str, Exception] = {}


# --------------------------------------------------------------------------
# BUILD CONFIGURATION - which compiler binary runs. Same category as scorer.py's
# _apply_build_config: it decides how a file is compiled, never what is reported.
# No detection logic reads anything below; Rule 4 compares pragmas through
# Slither's parsed Pragma objects, not through source_pragma_expr().
# --------------------------------------------------------------------------


def source_pragma_expr(path) -> str:
    """The file's raw `pragma solidity <expr>;` text (build config only).

    This is the one place a Chainwatch helper looks at unparsed source, and it
    has to: the compiler version must be known BEFORE the file can be compiled,
    so no AST exists yet. It is used solely to rank which installed solc to try.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("pragma") and "solidity" in stripped:
            body = stripped[len("pragma") :].strip()
            if body.startswith("solidity"):
                body = body[len("solidity") :].strip()
            return body.split(";", 1)[0].strip()
    return ""


def version_tuple(text: str) -> tuple:
    """('0.7.6') -> (0, 7, 6); unparseable -> ()."""
    parts = text.split(".")
    if not parts or not all(p.isdigit() for p in parts if p != ""):
        return ()
    return tuple(int(p) for p in parts if p != "")


def solc_candidates(path) -> list[str]:
    """Installed solc versions to try for `path`, most likely first.

    Only consulted after the ambient compiler has already REFUSED the file.
    The ranking is a speed heuristic, nothing more: correctness comes from solc
    itself, which enforces the pragma and rejects a wrong pick, so a mis-ranked
    guess costs one retry and can never produce a wrong analysis.
    """
    try:
        from solc_select.solc_select import installed_versions

        versions = list(installed_versions())
    except Exception:  # solc-select absent -> no fallback available
        return []

    expr = source_pragma_expr(path)
    floor = ()
    digits = "0123456789."
    token = ""
    for ch in expr:
        if ch in digits:
            token += ch
        elif token:
            break
    floor = version_tuple(token)

    def rank(version: str) -> tuple:
        vt = version_tuple(version)
        same_line = bool(floor) and vt[:2] == floor[:2]
        satisfies_floor = bool(floor) and vt >= floor
        return (same_line, satisfies_floor, vt)

    return sorted(versions, key=rank, reverse=True)


def exact_pin_installed(path) -> str | None:
    """The EXACT version this file pins, if that version is installed; else None.

    Returns None for a caret/range pragma (`^0.8.0`, `>=0.5.0<0.8.0`) and for an
    exact pin whose compiler is absent — both of which must keep the retry
    fallback below. `version_tuple` already rejects anything carrying an
    operator, so little new parsing is introduced: `^0.8.0` yields () because
    "^0" is not a digit string.

    `=X.Y.Z` IS an exact pin and is normalised here. Uniswap v3-core and
    v3-periphery both write their pin that way (33 and 40 occurrences at HEAD),
    and without this they would take neither the fast path nor B3's
    auto-install. Only a LEADING bare `=` is stripped, so `>=0.7.6` and
    `<=0.7.6` are untouched — they do not start with `=` and remain ranges.
    """
    expr = (source_pragma_expr(path) or "").strip()
    if expr.startswith("="):
        expr = expr[1:].strip()
    vt = version_tuple(expr)
    if len(vt) != 3:
        return None
    version = ".".join(str(p) for p in vt)
    try:
        from solc_select.solc_select import installed_versions

        return version if version in installed_versions() else None
    except Exception:  # noqa: BLE001 - solc-select absent: take the old path
        return None


def _compile_attempt(path, **extra) -> Slither:
    """Compile with the ambient compiler; if it refuses the file's pragma, retry
    with each installed solc until one accepts it.

    Needed because a diff can legitimately span the 0.8.0 boundary (fixtures-r4
    P4-03 / N4-01: one commit is <0.8.0 and the other >=0.8.0), which no single
    SOLC_VERSION can compile. The ambient version is always tried first and is
    always restored, so a run whose files all match the configured compiler
    behaves exactly as before this fallback existed.

    FAN-OUT SHORT-CIRCUIT for exact pins. An exact pragma pin can be satisfied
    by exactly one compiler, by construction, so when that compiler is present
    there is nothing for the retry loop to discover: if the pinned version
    cannot compile the file, no other version can either. Trying the remaining
    eight is pure waste, and MEASURED it is the dominant cost of any run
    containing an uncompilable file - 90 Slither invocations per failing file
    (9 rules that route through `parse` x 10 attempts each), of which exactly
    one is informative. `parse` memoises only SUCCESSES, so every rule pays the
    whole fan-out again.

    The short-circuit also fixes a METHODOLOGY Face A instance in passing: the
    error that escapes now comes from the compiler the file actually pins,
    instead of from whichever candidate the loop happened to try last.

    Note the pinned version is set EXPLICITLY rather than relying on the ambient
    one. Skipping the fallback while letting a mismatched ambient compiler make
    the only attempt would turn a satisfiable pin into a failure - the ambient
    version is frequently not the pinned one, and finding the pinned one is what
    the loop below was originally for.
    """
    pinned = exact_pin_installed(path)
    if pinned is not None:
        saved = os.environ.get("SOLC_VERSION")
        os.environ["SOLC_VERSION"] = pinned
        try:
            return Slither(str(path), solc_remaps=remaps_for(path), **extra)
        finally:
            if saved is None:
                os.environ.pop("SOLC_VERSION", None)
            else:
                os.environ["SOLC_VERSION"] = saved

    try:
        return Slither(str(path), solc_remaps=remaps_for(path), **extra)
    except Exception:
        pass

    saved = os.environ.get("SOLC_VERSION")
    try:
        for version in solc_candidates(path):
            if version == saved:
                continue
            os.environ["SOLC_VERSION"] = version
            try:
                return Slither(str(path), solc_remaps=remaps_for(path), **extra)
            except Exception:
                continue
    finally:
        if saved is None:
            os.environ.pop("SOLC_VERSION", None)
        else:
            os.environ["SOLC_VERSION"] = saved

    # Nothing accepted the file: re-raise the ambient compiler's own error.
    return Slither(str(path), solc_remaps=remaps_for(path), **extra)


def foundry_project_root(path):
    """The Foundry project root above `path`, or None - crytic-compile's OWN
    answer, not a re-implementation of it.

    The predicate that gates the fallback below has to agree EXACTLY with the
    detection that caused the failure, so it asks the detector rather than
    guessing at its rule. `locate_project_root` is the real installed API
    (crytic_compile/platform/foundry.py), read before use per CHARTER rule 4;
    `Foundry.is_supported` is a thin wrapper over it.

    Fails CLOSED. If the import ever moves, this returns None, the fallback
    never arms, and compilation behaves exactly as it did before this existed.
    """
    try:
        from crytic_compile.platform.foundry import Foundry
    except Exception:  # noqa: BLE001 - unknown crytic layout: no fallback
        return None
    try:
        return Foundry.locate_project_root(str(path))
    except Exception:  # noqa: BLE001
        return None


def foundry_toolchain_absent() -> bool:
    """True when `forge` is not on PATH.

    CHARTER rule 3 forbids installing one to make this False, and that is the
    right call twice over: a new dependency needs the human, and `forge` would
    be another binary executing target-adjacent code (WALK-L9's category).
    """
    return shutil.which("forge") is None


def _foundry_platform_unusable(path) -> bool:
    """True when crytic-compile WILL route `path` to the Foundry platform and
    that platform CANNOT compile anything, because `forge` does not exist.

    Both halves are load-bearing, and the second is what keeps this a fallback
    instead of an override:

    * A repo carrying `foundry.toml` is compiled by `forge`, not by solc, for
      every file in it - so this is a whole-ecosystem hole, not one repo's
      quirk. See LIMITATIONS.md COMP-L1.
    * When `forge` IS installed, a Foundry build that fails has told us
      something real about the sources, and retrying under bare solc would
      mask it. So the fallback stays disarmed in that case, even though it
      would raise the coverage number. That is the whole reason this is
      "solc as fallback" and never "solc always".

    When `forge` is absent the primary attempt fails in
    `Foundry.config()` -> `subprocess.run(["forge", ...])`, BEFORE any compiler
    reads the file. The error it raises is therefore `FileNotFoundError` about
    a missing executable and carries no information about the Solidity at all.
    Nothing can be masked by retrying, because nothing was learned.

    NOT MATCHED ON THE ERROR STRING, deliberately. That message is emitted by
    the OS and is localized - on this machine it reads
    `[WinError 2] Le fichier spécifié est introuvable` - so any substring test
    would pass or fail depending on the machine's display language. The
    condition is structural instead: is it a Foundry project, and is forge
    missing. Both are facts about the filesystem.
    """
    return foundry_project_root(path) is not None and foundry_toolchain_absent()


def _compile(path) -> Slither:
    """`_compile_attempt`, plus ONE narrowly gated retry with the Foundry
    platform disabled (finding COMP-L1).

    Order of events, and why each step is where it is:

    1. The normal attempt runs FIRST and unchanged. A repo whose framework
       build works keeps using it; every fixture set takes this path and its
       counts are byte-identical to before this function existed.
    2. If it raises, `_foundry_platform_unusable` decides. It is False for
       every non-Foundry target and for every Foundry target on a machine
       that has `forge`, and in both cases the original error propagates with
       `raise` - same exception, same traceback, no wrapping.
    3. Only when it is True do we retry with `foundry_ignore=True`, which
       makes `Foundry.is_supported` return False and lets detection fall
       through to the Solc platform for this one call. Remappings still come
       from `remaps_for(path)` - i.e. from `history.derive_remaps`, which
       already reads `lib/` and `remappings.txt` - so the fallback is not
       compiling blind.

    IF THE FALLBACK ALSO FAILS, ITS ERROR IS THE ONE THAT ESCAPES, and that is
    the point rather than a side effect. A genuine syntax error inside a
    Foundry repo currently surfaces as "forge is not installed", which sends
    the reader after the wrong problem entirely; after this it surfaces as the
    compiler's own diagnostic, identical to the one the same file produces
    outside a Foundry tree. Python chains the two, so the forge-missing cause
    is still visible in the traceback - masked in neither direction
    (METHODOLOGY Face A: report the error from the path that actually knows).
    """
    try:
        return _compile_attempt(path)
    except Exception:
        if not _foundry_platform_unusable(path):
            raise
        # INSIDE the except block on purpose. Retrying after it had exited
        # would work identically until the retry ALSO failed, at which point
        # the forge-missing cause would have been dropped from the traceback -
        # the implicit `__context__` link only survives here.
        return _compile_attempt(path, foundry_ignore=True)


def parse(path) -> Slither:
    """Compile+analyze a file, memoized per absolute path.

    FAILURES ARE MEMOISED TOO. Previously only successes were stored - the
    assignment `_PARSE_CACHE[key] = _compile(path)` simply never ran when
    `_compile` raised - so each of the nine rules that route through here paid
    the entire compile attempt again on an uncompilable file. Combined with the
    retry fan-out that was 90 attempts per bad file; the exact-pin
    short-circuit cut that to 9, and this cuts it to 1. The scope is inherited,
    not invented: `reset_caches()` clears both memos and is already called
    after every checkout, so a cached failure can never outlive the content
    that caused it.

    CACHE CONTRACT: the key is the path alone, so this memo is only sound while
    a given path's CONTENT does not change within one process. That holds for
    the scorer (fixture files are static on disk) but NOT for a trajectory
    walker, which checks successive commits out into the same scratch worktree
    path. Such a caller MUST call `reset_caches()` after each checkout, or it
    will silently re-serve the previous commit's analysis for the new one.
    """
    key = str(Path(path).resolve())
    if key in _PARSE_CACHE:
        return _PARSE_CACHE[key]
    if key in _PARSE_FAIL_CACHE:
        # Re-raise the ORIGINAL error, not a summary of it. A caller that sees
        # a different message on the second rule than the first would be
        # debugging the cache instead of the file (METHODOLOGY Face A).
        raise _PARSE_FAIL_CACHE[key]
    try:
        _PARSE_CACHE[key] = _compile(path)
    except Exception as exc:
        _PARSE_FAIL_CACHE[key] = exc
        raise
    return _PARSE_CACHE[key]


def reset_caches() -> None:
    """Drop the parse memo. Required between commits by any caller that reuses
    a filesystem path for different content (see the cache contract on
    `parse`). Cheap: the next `parse` simply recompiles.

    Clears the FAILURE memo too, and that is what makes the failure memo safe:
    a cached failure is only ever consulted within the same checkout, because
    every caller that reuses a path for different content already calls this
    between commits (src/scan.py:341, walker.py:172). A file that fails to
    compile at commit N and succeeds at N+1 is therefore never mistakenly
    reported as still broken - the memo does not survive the checkout that
    changed the content."""
    _PARSE_CACHE.clear()
    _PARSE_FAIL_CACHE.clear()


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


def accept_finding(decl, case_meta) -> bool:
    """DESIGN-L2 attribution guard: is `decl` declared in a file that ACTUALLY
    changed in this commit? Returns True (accept fire) or False (suppress
    phantom).

    Rules iterate `slither_obj.contracts_derived`, which includes every contract
    from every compiled source — including transitively-imported files that are
    byte-identical between N-1 and N. A within-commit non-injectivity (e.g.
    R5-L1) can then manufacture a phantom fire on unchanged imported code and
    mis-attribute it to the changed file Slither was called on. This predicate
    is the one universal filter: a rule that would fire on `decl` first asks
    here whether `decl`'s file is in the commit's changed set; if not, the fire
    is suppressed.

    Backward compatibility: single-file frozen fixtures do not carry a
    `changed_files` scope. Absence means "unscoped — accept everything", so
    those fixtures' verdicts are unchanged. A trajectory walker MUST populate
    `case_meta["changed_files"]` with the pair's repo-relative modified paths
    (from `changed_sol()`); a multi-file fixture MUST list its own changed
    files (typically `["before.sol", "after.sol"]`, since those are the pair
    the scorer parses).

    `decl` may be a Function (uses its `contract_declarer`) or a Contract
    (uses its own `source_mapping`). Matching is by absolute-path suffix,
    normalising Windows backslashes, so:
      - a trajectory `changed_files = {"contracts/facade/facets/ActFacet.sol"}`
        matches an absolute path ending in that suffix,
      - a fixture `changed_files = ["before.sol", "after.sol"]` matches the
        basename of a per-fixture path.
    Substring-in-path is deliberately NOT used — it re-introduces the 3x-L1
    class of silent false negatives.
    """
    if not isinstance(case_meta, dict):
        return True
    scope = case_meta.get("changed_files")
    if not scope:
        return True

    # Resolve to the file that DECLARES this contract/function.
    from slither.core.declarations import Contract as _Contract
    if isinstance(decl, Function):
        src_obj = decl.contract_declarer
    elif isinstance(decl, _Contract):
        src_obj = decl
    else:
        # Unknown declaration type — precision-first: pass through rather than
        # over-suppress a fire whose attribution we can't reason about.
        return True
    decl_path = str(src_obj.source_mapping.filename.absolute).replace("\\", "/")
    for p in scope:
        p_norm = str(p).replace("\\", "/")
        if decl_path == p_norm or decl_path.endswith("/" + p_norm):
            return True
    return False


def emit(
    case_meta,
    rule_id: str,
    *,
    decl=None,
    contract=None,
    function=None,
    node=None,
    severity: str = "CONFIRMED",
    detail: str = "",
    evidence=None,
) -> None:
    """Record WHICH declaration a rule fired on, without changing what it returns.

    ATTRIBUTION IS A SIDE CHANNEL, BY DESIGN. Every rule's `run()` contract stays
    exactly `True | "candidate" | False`, so scorer.py (a guard-protected file)
    and every frozen fixture verdict are untouched by this. A caller that wants
    more than a boolean passes a dict as `case_meta` and reads
    `case_meta["_findings"]` afterwards; a caller that does not, pays nothing.

    The whole body is exception-swallowing on purpose: attribution is reporting
    metadata, and a malformed source mapping must never be able to turn a fire
    into a miss (or vice versa). If detail extraction fails, the verdict still
    stands and the record is simply thinner.

    `decl` is the Function or Contract the finding is attributed to - the same
    object `accept_finding` was asked about, so the emitted file always agrees
    with the DESIGN-L2 scope decision. `node` narrows the line number to a
    specific statement when a rule knows one (Rule 4's arithmetic site).
    """
    try:
        if not isinstance(case_meta, dict):
            return
        from slither.core.declarations import Contract as _Contract

        rec: dict = {
            "rule_id": rule_id,
            "severity": severity,
            "contract": contract,
            "function": function,
            "signature": None,
            "file": None,
            "line": None,
            "detail": detail,
            "evidence": dict(evidence or {}),
        }

        src_obj = None
        if isinstance(decl, Function):
            rec["function"] = function or decl.name
            rec["signature"] = decl.full_name
            rec["contract"] = contract or decl.contract_declarer.name
            src_obj = decl.contract_declarer
            rec["line"] = _first_line(decl)
        elif isinstance(decl, _Contract):
            rec["contract"] = contract or decl.name
            src_obj = decl
            rec["line"] = _first_line(decl)

        if node is not None:
            line = _first_line(node)
            if line is not None:
                rec["line"] = line

        if src_obj is not None:
            rec["file"] = str(src_obj.source_mapping.filename.absolute).replace("\\", "/")

        case_meta.setdefault("_findings", []).append(rec)
    except Exception:  # noqa: BLE001 - reporting must never alter a verdict
        return


def _first_line(obj):
    try:
        lines = obj.source_mapping.lines
        return int(lines[0]) if lines else None
    except Exception:  # noqa: BLE001
        return None


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


def _const_values_by_var(fn: Function) -> dict:
    """{state variable: set of DISTINCT compile-time constant values written}.

    The value set, not merely the fact of a constant write, is what separates a
    one-shot initializer from a set/clear reentrancy mutex (finding RC-MUTEX1):

        initializer   _initialized = true          -> {True}      closes, stays closed
        lock()        _locked = 0; _; _locked = 1  -> {0, 1}      closes, then REOPENS

    `_state_vars_written_to_constant` cannot tell them apart because both write
    constants; the missing property is MONOTONICITY, and monotonicity is
    visible here as the number of distinct values.

    This duplicates a little of `_cfg._gated_const_assigns` on purpose:
    `_cfg` imports `_shared`, so `_shared` cannot import `_cfg.has_setclear_mutex`
    without creating a cycle. Stated rather than worked around.
    """
    out: dict = {}
    for f in reachable(fn):
        for node in f.nodes:
            for ir in node.irs:
                if not isinstance(ir, Assignment):
                    continue
                rv = getattr(ir, "rvalue", None)
                if isinstance(rv, Constant):
                    key = ("const", rv.value)
                elif isinstance(rv, StateVariable) and rv.is_constant:
                    key = ("cvar", rv.canonical_name)
                else:
                    continue
                lv = ir.lvalue
                origin = (lv.points_to_origin
                          if isinstance(lv, ReferenceVariable) else lv)
                if isinstance(origin, StateVariable):
                    out.setdefault(origin, set()).add(key)
    return out


def _setclear_flags(fn: Function) -> set:
    """State variables written to TWO OR MORE distinct constants in fn - a gate
    that closes and then REOPENS. That is a reentrancy mutex's signature
    (`_locked = 0; _; _locked = 1`), and it is what a one-shot initializer
    never does to the flag it is gated on."""
    return {v for v, vals in _const_values_by_var(fn).items() if len(vals) >= 2}


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
        # TWO conditions, and BOTH are load-bearing. Dropping either one
        # breaks a case this project has already paid for:
        #
        #  (a) some gated flag is written to a CONSTANT - finding
        #      3b-L-ratelimit. A rate limit writes `lastX = block.timestamp`,
        #      never a constant, and must not read as an init guard.
        #  (b) some gated flag is NOT set/clear - finding RC-MUTEX1. A mutex's
        #      flag closes and reopens (0 then 1); an initializer's does not.
        #
        # Requiring instead that a gated flag be written to exactly one
        # constant looks equivalent and is not: OZ's `reinitializer(n)` writes
        # `_initialized = version` from a PARAMETER, so its only
        # constant-written gated flag is `_initializing`, which is set/clear
        # just like a mutex. That stricter form regressed fixtures/N3b-01.
        const_written = set(_const_values_by_var(mod))
        setclear = _setclear_flags(mod)
        for node in guard_nodes(mod):
            gated = set(node.state_variables_read) & written
            if (gated & const_written) and (gated - setclear):
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
    const_written = set(_const_values_by_var(fn))     # 3b-L-ratelimit
    setclear = _setclear_flags(fn)                    # RC-MUTEX1
    for node in guard_nodes(fn):
        gated = set(node.state_variables_read) & written
        if (gated & const_written) and (gated - setclear):
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
