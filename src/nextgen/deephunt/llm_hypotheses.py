"""Optional, tightly-bounded LLM hypothesis hook (spec sections 22, 33).

The LLM may PROPOSE protocol-specific invariants and transaction sequences. It
never validates one and never decides a verdict - every proposal re-enters the
deterministic machinery (`invariants.discover` keeps only proposals that name a
real function / variable in the `ProtocolModel`; `state.classify` still owns the
verdict).

This module is:
  * import-safe with no `google-generativeai` installed and no `GEMINI_API_KEY`
    (every entry point returns `[]`);
  * never exercised by the test suite's assertions - Phase 2..10 are
    deterministic and pass with no key.

It reuses `agent.runner.api_key_present()` for the key check so there is one
answer to "is a model configured" across Chainwatch.
"""

from __future__ import annotations

import json
import re
from typing import Any

_MODEL = "gemini-3.5-flash-lite"
_MAX_ITEMS = 12


def available() -> bool:
    try:
        from agent.runner import api_key_present
        return bool(api_key_present())
    except Exception:  # noqa: BLE001
        return False


def propose_invariants(model: Any) -> list[dict]:
    """Return a list of `{statement, functions, variables, rationale}` dicts,
    or `[]`. Callers MUST re-check every item against the model."""
    if not available():
        return []
    prompt = _invariant_prompt(model)
    raw = _call(prompt)
    return _parse_items(raw, keys=("statement",))


def propose_sequences(model: Any, invariant_statement: str = "") -> list[dict]:
    """Return a list of `{steps: [fn, ...], rationale}` dicts, or `[]`."""
    if not available():
        return []
    prompt = _sequence_prompt(model, invariant_statement)
    raw = _call(prompt)
    return _parse_items(raw, keys=("steps",))


# --------------------------------------------------------------------------- #

def _call(prompt: str) -> str:
    try:
        import google.generativeai as genai  # noqa: F401
        from agent.runner import _load_env
        _load_env()
        import os
        genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))
        m = genai.GenerativeModel(_MODEL)
        resp = m.generate_content(prompt)
        return getattr(resp, "text", "") or ""
    except Exception:  # noqa: BLE001 - the hook is best-effort, never fatal
        return ""


def _invariant_prompt(model: Any) -> str:
    try:
        summary = json.dumps(model.as_dict(), default=str)[:12000]
    except Exception:  # noqa: BLE001
        summary = str(model)[:4000]
    return (
        "You are a smart-contract security researcher. Given this structured "
        "protocol model, propose up to 8 PROTOCOL-SPECIFIC security invariants "
        "that could be violated by an attacker. Each must name real functions "
        "and state variables from the model. Do NOT explain exploits.\n"
        "Return ONLY a JSON array of objects: "
        '{"statement": str, "functions": [str], "variables": [str], '
        '"rationale": str}.\n\nMODEL:\n' + summary)


def _sequence_prompt(model: Any, inv: str) -> str:
    try:
        fns = [f"{f.contract}.{f.name}" for f in model.ranked_functions()][:40]
    except Exception:  # noqa: BLE001
        fns = []
    return (
        "You are a smart-contract security researcher. Given these callable "
        f"functions {fns} and the invariant to attack: {inv!r}, propose up to 6 "
        "bounded transaction sequences (2-5 steps each) most likely to violate "
        "it. Return ONLY a JSON array of objects: "
        '{"steps": [str], "rationale": str}. Each step is one of the function '
        "names above.")


def _parse_items(raw: str, *, keys: tuple[str, ...]) -> list[dict]:
    if not raw:
        return []
    m = re.search(r"\[.*\]", raw, re.S)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except Exception:  # noqa: BLE001
        return []
    out: list[dict] = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and all(k in item for k in keys):
            out.append(item)
        if len(out) >= _MAX_ITEMS:
            break
    return out
