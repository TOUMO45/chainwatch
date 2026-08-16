"""The six agent tools (AGENT-DESIGN.md §3).

Each is a plain Python function: ADK wraps it as a `FunctionTool` and derives
the schema from the name, docstring and type hints, so the docstrings here are
interface, not commentary. Every tool returns a dict and signals failure by
RETURNING `{"status": "error", "error_message": ...}` rather than raising —
ADK's convention, and it also means a broken tool degrades the agent's turn
instead of killing the run.

None of these performs analysis. None can change a verdict. Together they are
the complete surface the model is allowed to touch.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .store import FindingStore
from .templates import assemble, skeleton
from .verify import verify as _verify

# The store is bound once, at agent construction, from a finished scan report.
_STORE: Optional[FindingStore] = None
_OUT_DIR = Path("reports")


def bind(store: FindingStore, out_dir: Optional[Path] = None) -> None:
    """Attach the tools to one scan report. Called by the host, never by the model."""
    global _STORE, _OUT_DIR
    _STORE = store
    if out_dir is not None:
        _OUT_DIR = Path(out_dir)


def _need_store() -> Optional[dict]:
    if _STORE is None:
        return {"status": "error", "error_message": "no scan report is loaded"}
    return None


def _coerce_slots(slots_json) -> tuple[bool, object]:
    """Accept the slot map as a JSON string OR as an already-decoded dict.

    Measured against a real model (2c): the declared type is `str`, but the
    runtime happily passes a dict when the model emits a JSON object, and the
    first `save_report` call failed with "the JSON object must be str". That is
    a tool-ergonomics defect, not a model error - the tool should accept what
    the schema plausibly produces. It does NOT relax any check: whatever comes
    back is assembled through the fixed template and put through the same gate.
    """
    import json as _json

    if isinstance(slots_json, dict):
        return True, slots_json
    try:
        slots = _json.loads(slots_json or "{}")
    except Exception:  # noqa: BLE001
        # Second chance: a Python-literal mapping (single quotes). Measured in
        # 2c - the model emitted this on 3 of 5 verify calls and burned a
        # round-trip recovering each time. `literal_eval` parses literals only;
        # it cannot execute anything, and the result still goes through
        # `assemble` and the same gate, so tolerating the dialect relaxes no
        # check. It only stops the loop wasting turns on punctuation.
        import ast

        try:
            slots = ast.literal_eval(slots_json)
        except Exception as exc:  # noqa: BLE001
            return False, (f"slots_json is not valid JSON: {exc}. Send a JSON "
                           f"object like {{\"summary\": \"...\"}}")
    if not isinstance(slots, dict):
        return False, "slots_json must be a JSON object of {slot_key: prose}"
    return True, {str(k): v for k, v in slots.items()}


# --------------------------------------------------------------------- tools


def list_findings() -> dict:
    """List every finding in the loaded Chainwatch scan, identity fields only.

    Returns one entry per finding with its finding_id, rule, verdict, contract,
    function, file, line and commit. Deliberately carries no prose: use
    get_finding to obtain evidence for a specific finding.
    """
    if (err := _need_store()):
        return err
    idx = _STORE.index()
    return {"status": "success", "count": len(idx), "findings": idx,
            "coverage": _STORE.report.get("coverage", {}).get("pairs_analyzed_pct")}


def get_finding(finding_id: str) -> dict:
    """Return the complete evidence record for one finding.

    Includes the six required evidence fields with what is and is not
    established, the reasons the verdict was not raised, the commit trajectory
    (parent, regression commit, author, date, changed lines, whether it
    survives to HEAD), and the on-chain liveness result if one was taken.

    Args:
        finding_id: id from list_findings.
    """
    if (err := _need_store()):
        return err
    facts = _STORE.facts(finding_id)
    if not facts.get("verdict"):
        return {"status": "error", "error_message": f"no finding with id {finding_id}"}
    return {"status": "success", "finding": facts}


def get_diff(finding_id: str) -> dict:
    """Return the actual git diff for the finding's file at its regression commit.

    This is the ground truth for what changed. Use it to check the engine's
    description against the code before writing anything.

    Args:
        finding_id: id from list_findings.
    """
    if (err := _need_store()):
        return err
    ok, payload = _STORE.diff(finding_id)
    if not ok:
        return {"status": "error", "error_message": payload}
    return {"status": "success", "diff": payload[:20000]}


def draft_report(finding_id: str) -> dict:
    """Return the report skeleton for one finding: the fixed header, the facts
    already rendered by code, and the empty prose slots you are to fill.

    You fill only slot content. The header and the facts are rendered from the
    finding record and cannot be changed from here - do not restate commit
    hashes, addresses, line numbers or file paths in your prose.

    Args:
        finding_id: id from list_findings.
    """
    if (err := _need_store()):
        return err
    facts = _STORE.facts(finding_id)
    if not facts.get("verdict"):
        return {"status": "error", "error_message": f"no finding with id {finding_id}"}
    return skeleton(facts)


def verify_report(finding_id: str, slots_json: str) -> dict:
    """Check your drafted prose against the finding record. Mechanical, not a model.

    Pass the same JSON object of {slot_key: prose} you intend to save. The
    document is assembled exactly as save_report would assemble it and then
    checked: every commit hash, address, source path, line reference and
    qualified name must appear in the finding record; for a CANDIDATE the fixed
    header must be intact, no severity or impact section may exist, and
    assertive vulnerability language is rejected. Fix every reported violation
    and verify again before saving.

    Args:
        finding_id: id from list_findings.
        slots_json: JSON object of {slot_key: prose}.
    """
    if (err := _need_store()):
        return err
    facts = _STORE.facts(finding_id)
    if not facts.get("verdict"):
        return {"status": "error", "error_message": f"no finding with id {finding_id}"}
    ok, slots = _coerce_slots(slots_json)
    if not ok:
        return {"status": "error", "error_message": slots}
    return _verify(assemble(facts, slots), facts)


def save_report(finding_id: str, slots_json: str) -> dict:
    """Assemble and save the final report for one finding.

    Pass your prose as a JSON object mapping slot keys to their content. The
    header, the facts and the document structure are re-rendered from the
    finding record at save time, so only your prose is taken from you. The
    report is verified before writing and is REFUSED if verification fails.

    Args:
        finding_id: id from list_findings.
        slots_json: JSON object of {slot_key: prose}.
    """
    if (err := _need_store()):
        return err
    facts = _STORE.facts(finding_id)
    if not facts.get("verdict"):
        return {"status": "error", "error_message": f"no finding with id {finding_id}"}
    ok, slots = _coerce_slots(slots_json)
    if not ok:
        return {"status": "error", "error_message": slots}

    markdown = assemble(facts, slots)
    check = _verify(markdown, facts)
    if not check["ok"]:
        return {"status": "error",
                "error_message": "report refused: verification failed",
                "violations": check["violations"]}

    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{facts['contract']}_{finding_id}")
    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = _OUT_DIR / f"{safe}.md"
    path.write_text(markdown, encoding="utf-8")
    return {"status": "success", "path": str(path), "bytes": len(markdown)}


ALL_TOOLS = [list_findings, get_finding, get_diff,
             draft_report, verify_report, save_report]
