"""Real storage-layout extraction via `solc --storage-layout`.

RULES.md 3c is explicit that this sub-rule requires a genuine slot-by-slot
comparator produced by the compiler, not AST heuristics. This module shells out
to the pinned solc and returns the compiler's own layout, so slot arithmetic
(inheritance ordering, packing, gap spans) is never re-implemented here.
"""

import json
import math
import os
import re
import subprocess
from pathlib import Path

from ._shared import _is_namespace_pointer_function, solc_candidates

ROOT = Path(__file__).resolve().parents[2]

# The directory solc runs in and resolves relative paths against. Defaults to
# Chainwatch's own root, which is correct for the fixture scorer (fixtures live
# inside this repo). A trajectory walker analyses files in a scratch WORKTREE of
# some other repository, so it must point this at that checkout - otherwise solc
# runs with the wrong cwd and the wrong --allow-paths, every import resolves
# against Chainwatch's tree, and Rule 3c errors on every file (measured: 42/42
# on the Reserve window). Build configuration only, never detection logic; same
# category as REMAPPINGS.
PROJECT_ROOT = ROOT

REMAPPINGS = [
    "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
    "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
]

_LAYOUT_CACHE: dict[str, dict] = {}


def _root_and_remaps(src: Path) -> tuple[Path, list[str]]:
    """The checkout `src` belongs to, and the remappings that checkout needs.

    Mirrors `_shared.remaps_for`: a trajectory pair spans TWO worktrees, and
    Rule 3c compiles a file from each, so neither the root nor the remap set can
    be a single global. Falls back to PROJECT_ROOT / REMAPPINGS, which is what
    the fixture scorer uses.
    """
    from ._shared import _ROOT_REMAPS

    p = str(src).replace("\\", "/")
    best: tuple[str, list[str]] | None = None
    for root, remaps in _ROOT_REMAPS:
        if p == root or p.startswith(root + "/"):
            if best is None or len(root) > len(best[0]):
                best = (root, remaps)
    if best:
        return Path(best[0]), list(best[1])
    return Path(PROJECT_ROOT), list(REMAPPINGS)


def _run_layout(rel: str, root: Path, remaps: list[str],
                version: str | None = None) -> subprocess.CompletedProcess:
    """One `solc --combined-json storage-layout` invocation. `version` overrides
    the compiler for this call only (build config, never detection logic).

    The compiler is selected the same way `_shared._compile` selects it: an
    explicit `version`, else `SOLC_VERSION` inherited from the environment (which
    is what a walker sets from the commit's own pin), else whatever solc-select
    has globally selected. `--allow-paths` is the project root rather than "."
    so an absolute remap into a sibling dependency tree is readable.
    """
    env = dict(os.environ)
    if version:
        env["SOLC_VERSION"] = version
    # Every remap target must be readable, not just the project root: since
    # WALK-L4 the dependency remaps point at the junction's real target, which
    # lives in the walker's cache OUTSIDE the checkout. Without these entries
    # solc refuses the read as a path violation.
    allowed = [str(root)]
    for rm in remaps:
        _, _, dest = rm.partition("=")
        dest = dest.rstrip("/")
        if dest and dest not in allowed:
            allowed.append(dest)
    return subprocess.run(
        ["solc", *remaps, "--allow-paths", ",".join(allowed), "--combined-json",
         "storage-layout", rel],
        cwd=str(root), capture_output=True, text=True, env=env,
    )


def reset_caches() -> None:
    """Drop the layout memo. Same cache contract as `_shared.parse`: the key is
    the path alone, so a caller that reuses a path for different content (a
    trajectory walker checking successive commits into one scratch worktree)
    MUST call this after each checkout or it will re-serve the previous
    commit's layout."""
    _LAYOUT_CACHE.clear()


def storage_layouts(path) -> dict:
    """{contract_name: {"storage": [entries], "types": {...}}} for contracts
    declared in `path` itself. Library contracts under node_modules are skipped:
    they are dependency code, not the repo's own layout.

    CACHE CONTRACT: memoized on absolute path only - sound for static fixture
    files, unsound for a path whose content changes in-process. See
    `reset_caches()`.
    """
    src = Path(path).resolve()
    key = str(src)
    if key in _LAYOUT_CACHE:
        return _LAYOUT_CACHE[key]

    root, remaps = _root_and_remaps(src)
    rel = src.relative_to(root).as_posix() if src.is_relative_to(root) else str(src)
    proc = _run_layout(rel, root, remaps)
    if proc.returncode != 0:
        # Build config only: the ambient compiler refused this file's pragma
        # (a pre-0.8 commit in a mixed-version fixture set). Same fallback as
        # _shared._compile - try each installed solc, keep the first that works.
        for version in solc_candidates(src):
            proc = _run_layout(rel, root, remaps, version)
            if proc.returncode == 0:
                break
    if proc.returncode != 0:
        raise RuntimeError(f"solc --storage-layout failed for {rel}:\n{proc.stderr}")

    combined = json.loads(proc.stdout)
    out: dict = {}
    for qualified, payload in combined.get("contracts", {}).items():
        source, _, cname = qualified.rpartition(":")
        if "node_modules" in source.replace("\\", "/"):
            continue
        layout = payload.get("storage-layout") or {}
        if isinstance(layout, str):
            # solc <0.8 emits storage-layout as a JSON *string* inside
            # combined-json, where 0.8.x emits a nested object. Same data,
            # one more decode - a wire-format difference, not a layout one.
            layout = json.loads(layout) if layout.strip() else {}
        out[cname] = {
            "storage": layout.get("storage", []),
            "types": layout.get("types") or {},
        }
    _LAYOUT_CACHE[key] = out
    return out


_AST_ID_SUFFIX = re.compile(
    r"(t_(?:contract|struct|enum|userDefinedValueType)\([^()]*\))\d+"
)


def canonical_type(type_str: str) -> str:
    """A solc layout type string with its astId suffixes removed (RC-AST1).

    solc tags every user-defined type reference in `--storage-layout` with the
    declaring node's astId: `t_contract(IMain)2141`, `t_struct(Set)1331_storage`,
    `t_mapping(t_contract(IERC20)1005,t_contract(IAsset)2937)`. That number is a
    source-position artifact - it renumbers whenever ANY declaration is added or
    removed earlier in the compilation unit - so it is not stable across commits
    and says nothing about whether the type's identity changed. Comparing raw
    strings therefore reports a type change on ordinary refactors that moved no
    storage at all (measured on reserve-protocol `cef2f655..7f65c030`, where
    `t_contract(IOracle)24` at N-1 and `t_contract(IRegistry)24` at N are
    *different* declarations wearing the same number).

    This is the type-comparison analogue of the astId instability that
    `keyed_entries` already handles for entry IDENTITY by keying positionally.

    Array lengths are deliberately NOT stripped: in `t_array(t_uint256)50_storage`
    the digits are the array's LENGTH, a real part of the layout, and collapsing
    50 vs 49 would hide a genuine `__gap` shrink or array growth. Only
    contract/struct/enum/UDVT identifiers carry an astId here.

    Callers compare canonical forms; `slot_span` and the `types` map keep using
    the RAW string, because the layout JSON's `types` dict is keyed by it.
    """
    return _AST_ID_SUFFIX.sub(r"\1", type_str or "")


def slot_span(entry: dict, types: dict) -> int:
    """How many 32-byte slots this variable occupies (minimum 1)."""
    info = types.get(entry["type"]) or {}
    try:
        nbytes = int(info.get("numberOfBytes", "32"))
    except (TypeError, ValueError):
        nbytes = 32
    return max(1, (nbytes + 31) // 32)


def struct_member_layout(struct) -> dict | None:
    """{member name: {slot, offset, type}} for one struct, or None if a member
    cannot be sized confidently.

    Needed because `solc --storage-layout` emits NOTHING for an ERC-7201
    namespaced struct: its members are not declared state variables, so the
    contract-level layout is empty and there is nothing to diff (finding
    3x-L3 / P3c-oz5-01). Offsets are therefore computed here.

    Packing follows solc's sequential rules, using Slither's own
    `Type.storage_size` -> (bytes, forces_new_slot) rather than a hand-rolled
    size table. Validated against `solc --combined-json storage-layout` over ten
    struct shapes (packed value types, exact-fit boundaries, fixed arrays,
    mappings, dynamic bytes); all ten reproduced the compiler exactly.

    Returning None on an unsizeable member is deliberate: a wrong size would
    shift every following member and manufacture a false collision, so the
    precision-first tie-break is to decline to analyse the struct.
    """
    slot = 0
    offset = 0
    out: dict = {}
    for elem in struct.elems_ordered:
        try:
            size, forces_new_slot = elem.type.storage_size
        except Exception:
            return None
        if not isinstance(size, int) or size <= 0:
            return None
        if forces_new_slot:
            if offset:
                slot += 1
                offset = 0
            out[elem.name] = {"slot": slot, "offset": 0, "type": str(elem.type)}
            slot += math.ceil(size / 32)
            offset = 0
        else:
            if offset + size > 32:
                slot += 1
                offset = 0
            out[elem.name] = {"slot": slot, "offset": offset, "type": str(elem.type)}
            offset += size
    return out


def namespaced_struct_layouts(slither_obj) -> dict:
    """{contract name: {struct canonical name: member layout}} for ERC-7201
    namespaced structs DECLARED IN THE REPO.

    Structs declared under node_modules are skipped on purpose: dependency
    layouts do not change between two commits of the repo being analysed, and
    including them would turn a routine OpenZeppelin bump into a storm of
    findings (limitation 3c-L7).
    """
    out: dict = {}
    for contract in slither_obj.contracts:
        structs: dict = {}
        for fn in contract.functions:
            if not _is_namespace_pointer_function(fn):
                continue
            decl = str(fn.contract_declarer.source_mapping.filename.absolute)
            if "node_modules" in decl.replace("\\", "/"):
                continue
            for ret in fn.returns:
                struct = getattr(getattr(ret, "type", None), "type", None)
                if struct is None or not hasattr(struct, "elems_ordered"):
                    continue
                layout = struct_member_layout(struct)
                if layout is not None:
                    structs[struct.canonical_name] = layout
        if structs:
            out[contract.name] = structs
    return out


def keyed_entries(layout: dict) -> dict:
    """Key each entry as (label, nth-occurrence-of-that-label).

    Positional keying is required because reserved gaps all share the label
    `__gap` across an inheritance chain, and astIds are not stable between
    commits (adding a declaration renumbers them), so astId cannot be used to
    match a variable to its counterpart.
    """
    out: dict = {}
    seen: dict = {}
    for entry in layout.get("storage", []):
        label = entry["label"]
        idx = seen.get(label, 0)
        seen[label] = idx + 1
        out[(label, idx)] = entry
    return out
