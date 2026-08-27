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

import hashlib
import json
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


def explain_impact(finding_id: str) -> dict:
    """Return the impact-narration skeleton for ONE existing finding.

    This tool EXPLAINS a finding the deterministic engine already produced. It
    cannot create a finding, promote a CANDIDATE to CONFIRMED, or change any
    verdict field - the verdict, the header and the fact block are rendered from
    the stored record by code, and only slot prose comes from you. If the
    evidence looks insufficient to you, say so in the slots; that does not
    change the verdict.

    Every rule that applies to draft_report applies here unchanged: no restating
    hashes, addresses, line numbers or paths; no exploit material; and for a
    CANDIDATE, no assertion that anything is confirmed or exploitable.

    Args:
        finding_id: id from list_findings.
    """
    if (err := _need_store()):
        return err
    facts = _STORE.facts(finding_id)
    if not facts.get("verdict"):
        return {"status": "error", "error_message": f"no finding with id {finding_id}"}
    return skeleton(facts, kind="impact")


def verify_impact(finding_id: str, slots_json: str) -> dict:
    """Check drafted impact prose against the finding record. Mechanical, not a model.

    Same gate as verify_report, over the impact slot set: every commit hash,
    address, source path, line reference and qualified name must already appear
    in the finding record, and a CANDIDATE keeps its fixed header with no
    severity/impact section and no assertive language. Fix every violation and
    verify again.

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
    return _verify(assemble(facts, slots, kind="impact"), facts)


# Fields that bear on RELATIVE priority. Every one is already in the finding
# record - this list exists so the ranking material is explicit and auditable,
# not assembled ad hoc per call.
_RANK_FIELDS = ("finding_id", "rule_id", "owasp", "verdict", "liveness",
                "survives_to_head", "contract", "function", "file", "line",
                "detail")


def rank_findings(finding_ids_json: str) -> dict:
    """Return the priority-relevant facts for SEVERAL existing findings, so they
    can be ordered relative to one another.

    This tool does NOT rank. It hands you the facts the records already contain
    and you supply the ordering, which verify_ranking then checks. It cannot
    create a finding, promote a CANDIDATE, or change any verdict field: the
    verdicts below are reproduced from the stored records and are not yours to
    move. If two findings differ in verdict, say so as a fact - do not treat
    ordering as re-grading.

    Rank on what the records show. Typical signals, strongest first: liveness
    LIVE over UNKNOWN; survives_to_head true over false; a CONFIRMED verdict
    over a CANDIDATE; a state-changing declaration over a view. Cite ONLY
    fields returned here.

    Args:
        finding_ids_json: JSON array of finding ids from list_findings.
    """
    if (err := _need_store()):
        return err
    try:
        ids = json.loads(finding_ids_json)
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise ValueError
    except Exception:
        return {"status": "error",
                "error_message": "finding_ids_json must be a JSON array of id strings"}
    if len(ids) < 2:
        return {"status": "error",
                "error_message": "ranking needs at least two finding ids"}

    items, missing = [], []
    for fid in ids:
        facts = _STORE.facts(fid)
        if not facts.get("verdict"):
            missing.append(fid)
            continue
        items.append({k: facts.get(k) for k in _RANK_FIELDS})
    if missing:
        return {"status": "error",
                "error_message": f"no finding with id(s): {', '.join(missing)}"}
    return {
        "status": "success",
        "count": len(items),
        "findings": items,
        "rules": [
            "Return one entry per finding given, no more and no fewer.",
            "Cite only the fields shown here. Do not infer TVL, funds at risk, "
            "or real-world stakes that are not in the record.",
            "The verdict is decided by the engine. Ordering is not re-grading.",
        ],
    }


def _ranking_violations(ids: list, ranking: list) -> list[dict]:
    """Shared gate: every check verify_ranking (and now save_ranking) applies.
    Pulled out so the two tools cannot drift into checking different things -
    save_ranking is the source of truth for what gets persisted, and it must
    reject exactly what verify_ranking would have flagged, not a weaker set.
    """
    violations: list[dict] = []

    def cite(kind, span, reason):
        violations.append({"kind": kind, "span": str(span), "reason": reason})

    got = [r.get("finding_id") for r in ranking if isinstance(r, dict)]
    for fid in got:
        if fid not in ids:
            cite("invented", fid, "ranked a finding that was not among the inputs")
    for fid in ids:
        if fid not in got:
            cite("dropped", fid, "input finding is missing from the ranking")
    for fid in set(got):
        if got.count(fid) > 1:
            cite("duplicate", fid, "finding ranked more than once")

    ranks = sorted(r.get("rank") for r in ranking if isinstance(r, dict))
    if ranks != list(range(1, len(ranking) + 1)):
        cite("rank", ranks, f"ranks must be a permutation of 1..{len(ranking)}")

    for r in ranking:
        if not isinstance(r, dict):
            continue
        fid = r.get("finding_id")
        if fid not in ids:
            continue
        facts = _STORE.facts(fid)
        if not facts.get("verdict"):
            continue
        res = _verify(str(r.get("rationale") or ""), facts)
        for v in res.get("violations", []):
            # A rationale is prose about ONE finding; the CANDIDATE header and
            # section constraints belong to the report document, not here.
            if v["kind"] in ("header", "section"):
                continue
            cite(v["kind"], v["span"], f"{fid}: {v['reason']}")

    return violations


def verify_ranking(finding_ids_json: str, ranking_json: str) -> dict:
    """Check a ranking against the records. Mechanical, not a model.

    Rejects an invented finding id, a dropped or duplicated one, a rank that is
    not a permutation of 1..N, and any rationale asserting a fact absent from
    that finding's own record (same gate as verify_report/verify_impact).

    Args:
        finding_ids_json: the same JSON array passed to rank_findings.
        ranking_json: JSON array of {finding_id, rank, rationale}.
    """
    if (err := _need_store()):
        return err
    try:
        ids = list(json.loads(finding_ids_json))
        ranking = json.loads(ranking_json)
        assert isinstance(ranking, list)
    except Exception:
        return {"status": "error",
                "error_message": "both arguments must be JSON arrays"}

    violations = _ranking_violations(ids, ranking)
    return {"status": "success", "ok": not violations,
            "violation_count": len(violations), "violations": violations[:50]}


def save_ranking(finding_ids_json: str, ranking_json: str) -> dict:
    """Persist a checked ranking of several existing findings.

    Pass the same finding ids you were given and your final ranking, each
    entry {finding_id, rank, rationale}. Re-checked with the exact same gate
    as verify_ranking and REFUSED (nothing written) if any violation remains
    - fix them and call verify_ranking again before saving, the same
    discipline save_report already applies to a dossier.

    Args:
        finding_ids_json: the same JSON array passed to rank_findings.
        ranking_json: JSON array of {finding_id, rank, rationale}.
    """
    if (err := _need_store()):
        return err
    try:
        ids = list(json.loads(finding_ids_json))
        ranking = json.loads(ranking_json)
        assert isinstance(ranking, list)
    except Exception:
        return {"status": "error",
                "error_message": "both arguments must be JSON arrays"}

    violations = _ranking_violations(ids, ranking)
    if violations:
        return {"status": "error",
                "error_message": "ranking refused: verification failed",
                "violations": violations[:50]}

    ordered = sorted(ranking, key=lambda r: r.get("rank", 0))
    key = re.sub(r"[^A-Za-z0-9_]", "_", "_".join(sorted(ids)))[:80]
    safe = hashlib.sha256(key.encode()).hexdigest()[:16]
    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = _OUT_DIR / f"ranking_{safe}.json"
    payload = {"finding_ids": ids, "ranking": ordered}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"status": "success", "path": str(path), "ranking": ordered}


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
             draft_report, verify_report, save_report,
             explain_impact, verify_impact,
             rank_findings, verify_ranking, save_ranking]
