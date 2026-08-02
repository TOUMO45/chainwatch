"""Real storage-layout extraction via `solc --storage-layout`.

RULES.md 3c is explicit that this sub-rule requires a genuine slot-by-slot
comparator produced by the compiler, not AST heuristics. This module shells out
to the pinned solc and returns the compiler's own layout, so slot arithmetic
(inheritance ordering, packing, gap spans) is never re-implemented here.
"""

import json
import math
import subprocess
from pathlib import Path

from ._shared import _is_namespace_pointer_function

ROOT = Path(__file__).resolve().parents[2]

REMAPPINGS = [
    "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
    "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
]

_LAYOUT_CACHE: dict[str, dict] = {}


def storage_layouts(path) -> dict:
    """{contract_name: {"storage": [entries], "types": {...}}} for contracts
    declared in `path` itself. Library contracts under node_modules are skipped:
    they are dependency code, not the repo's own layout.
    """
    src = Path(path).resolve()
    key = str(src)
    if key in _LAYOUT_CACHE:
        return _LAYOUT_CACHE[key]

    rel = src.relative_to(ROOT).as_posix() if src.is_relative_to(ROOT) else str(src)
    proc = subprocess.run(
        ["solc", *REMAPPINGS, "--allow-paths", ".", "--combined-json",
         "storage-layout", rel],
        cwd=ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"solc --storage-layout failed for {rel}:\n{proc.stderr}")

    combined = json.loads(proc.stdout)
    out: dict = {}
    for qualified, payload in combined.get("contracts", {}).items():
        source, _, cname = qualified.rpartition(":")
        if "node_modules" in source.replace("\\", "/"):
            continue
        layout = payload.get("storage-layout") or {}
        out[cname] = {
            "storage": layout.get("storage", []),
            "types": layout.get("types") or {},
        }
    _LAYOUT_CACHE[key] = out
    return out


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
