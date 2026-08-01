"""Real storage-layout extraction via `solc --storage-layout`.

RULES.md 3c is explicit that this sub-rule requires a genuine slot-by-slot
comparator produced by the compiler, not AST heuristics. This module shells out
to the pinned solc and returns the compiler's own layout, so slot arithmetic
(inheritance ordering, packing, gap spans) is never re-implemented here.
"""

import json
import subprocess
from pathlib import Path

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
