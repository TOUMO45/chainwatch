"""Shared, best-effort single-file Solidity compilation for next-gen probes.

Compiles ONE self-contained source (no unresolved imports) via the classic
engine's own `src/rules/_shared.parse`, so version fallback and remap handling
are identical to the rules. A caller that gets a raise treats the commit as
`measurable=False` - it never guesses the property either way.

`slither` / `solc` are needed only to CALL this, never to import a module that
uses it.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path


def slither_for_source(text: str):
    """Return a `Slither` object for `text`, or raise. Writes to a unique temp
    path (never reused) so `_shared.parse`'s path-keyed memo cannot serve a
    stale analysis."""
    from src.rules import _shared

    tmp = Path(tempfile.gettempdir()) / "chainwatch-nextgen-solc"
    tmp.mkdir(parents=True, exist_ok=True)
    f = tmp / f"src-{uuid.uuid4().hex}.sol"
    f.write_text(text, encoding="utf-8")
    try:
        _shared.reset_caches()
        return _shared.parse(f)
    finally:
        try:
            f.unlink()
        except OSError:
            pass
