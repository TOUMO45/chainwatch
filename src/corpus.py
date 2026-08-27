"""Capability 16 - the findings corpus, on Firestore (CORPUS-1).

Two jobs, one store:

  1. JOB STATE. `webapp/server.py` keeps scans in a process-local dict, so Cloud
     Run at `min-instances: 0` loses every running scan when it scales to zero -
     a documented, reproduced bug, not a theoretical one. Persisted here, a scan
     survives the instance that started it.

  2. THE CORPUS. Every analysed commit pair, keyed by
     `(repo, prev_sha, cur_sha, rule)`. This is the part that compounds: a pair
     already analysed is never re-analysed (scans cost minutes), and the
     accumulated set answers questions no single scan can - "every time an
     initializer guard was removed, across every protocol we have ever walked".

DEGRADES, NEVER BLOCKS. Firestore is optional infrastructure for an analysis
engine that must keep working on a laptop with no cloud project at all. Every
function here returns a status instead of raising, and `available()` is false
when the client, the credentials or the project are missing. A scan whose
persistence fails is still a valid scan - it just was not recorded.

NOTHING HERE DECIDES ANYTHING. The corpus stores verdicts that
`verdict.classify` already produced. Reading a cached finding must return
exactly what the deterministic engine returned, or the cache would become a
second, divergent opinion about what CONFIRMED means.

REGION NOTE, measured: the database is `eur3` and Cloud Run is `us-central1`,
so every operation crosses the Atlantic (~100ms). Writes are therefore BATCHED
per scan rather than issued per finding.
"""

from __future__ import annotations

import hashlib
import re
import os
import time
from typing import Any, Optional

# Set by deployment; the defaults match the project's own database so a local
# run with credentials works without configuration.
PROJECT_ID = os.environ.get("FIRESTORE_PROJECT", "chainwatch-ee1d1")
DATABASE_ID = os.environ.get("FIRESTORE_DATABASE", "chainwatch2026")

COL_JOBS = "scans"
COL_PAIRS = "pairs"
COL_FINDINGS = "findings"

_client: Any = None
_probe_error: str = ""


def _connect() -> Any:
    """The Firestore client, or None. Cached, including the failure."""
    global _client, _probe_error
    if _client is not None or _probe_error:
        return _client
    try:
        from google.cloud import firestore

        _client = firestore.Client(project=PROJECT_ID, database=DATABASE_ID)
        return _client
    except Exception as exc:  # noqa: BLE001 - absence of a cloud is not an error
        _probe_error = f"{type(exc).__name__}: {exc}"[:200]
        return None


def available() -> dict:
    """Whether the corpus can be used, and plainly why not if it cannot.

    The front ends must be able to SAY "not recorded" rather than fail
    obscurely, exactly as `agent.runner.api_key_present` does for Gemini.
    """
    client = _connect()
    return {"available": client is not None,
            "project": PROJECT_ID, "database": DATABASE_ID,
            "reason": _probe_error}


def pair_key(repo: str, prev_sha: str, cur_sha: str) -> str:
    """Stable id for one analysed commit pair.

    Hashed rather than concatenated because a repo URL contains characters
    Firestore forbids in a document id ('/'), and because the raw key would
    otherwise exceed the 1500-byte id limit on a long URL.
    """
    raw = f"{_repo_id(repo)}|{prev_sha}|{cur_sha}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _repo_id(repo: str) -> str:
    """Normalise a repo reference so the same project keys identically whether
    it arrived as a clone URL or a local path.

    Lowercased FIRST: `removeprefix` is case-sensitive, so `HTTPS://...` kept
    its scheme, and the later ':' -> '/' rewrite then turned it into
    `https///github.com/...` - a different key for the same repository, which
    would silently defeat every cache hit. Caught by
    tests/test_corpus.py::test_repo_id_normalisation_is_case_and_suffix_insensitive.
    """
    r = str(repo).replace("\\", "/").rstrip("/").lower()
    r = r.removesuffix(".git")
    for prefix in ("https://", "http://", "git@"):
        r = r.removeprefix(prefix)
    # ':' -> '/' folds `git@host:org/repo` and `C:/path` into one shape, then
    # repeated separators collapse: `C:\path` would otherwise become `c//path`
    # and key differently from the same checkout named any other way.
    return re.sub(r"/+", "/", r.replace(":", "/"))


# ------------------------------------------------------------------ corpus


def record_scan(report: dict, *, repo: Optional[str] = None) -> dict:
    """Persist one finished scan: its summary, its pairs, and its findings.

    ONE batch for the whole scan (see the region note in the module docstring).
    Firestore caps a batch at 500 operations, so this chunks rather than
    silently dropping the tail of a large walk.
    """
    client = _connect()
    if client is None:
        return {"ok": False, "reason": _probe_error or "firestore unavailable",
                "written": 0}

    # EVERYTHING below is inside the try, not just the commit. Building the
    # operation list calls `client.collection(...)`, which is itself a live
    # call that can raise (revoked token, quota, network drop) - an earlier
    # version left that outside and the exception escaped, killing a scan that
    # had already done all of its real work. Caught by
    # tests/test_corpus.py::test_a_broken_client_does_not_escape.
    written = 0
    scan_id = ""
    try:
        return _record(client, report, repo)
    except Exception as exc:  # noqa: BLE001 - persistence never fails a scan
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"[:200],
                "written": written, "scan_id": scan_id}


def _record(client: Any, report: dict, repo: Optional[str]) -> dict:
    repo_ref = _repo_id(repo or report.get("repo", ""))
    findings = report.get("findings", []) or []
    cov = report.get("coverage", {}) or {}
    now = time.time()

    ops: list[tuple[Any, dict]] = []

    scan_id = hashlib.sha256(
        f"{repo_ref}|{report.get('head')}|{now}".encode("utf-8")).hexdigest()[:24]
    ops.append((client.collection(COL_JOBS).document(scan_id), {
        "repo": repo_ref,
        "head": report.get("head"),
        "address": report.get("address"),
        "recorded_at": now,
        "summary": report.get("summary", {}),
        "coverage": {k: cov.get(k) for k in (
            "pairs_analyzed", "pairs_total", "files_ok", "files_total",
            "rule_invocations_ok", "rule_invocations_answerable",
            "rule_coverage_pct")},
    }))

    for rec in cov.get("pair_records", []) or []:
        pair = str(rec.get("pair", ""))
        if ".." not in pair:
            continue
        prev_sha, _, cur_sha = pair.partition("..")
        ops.append((client.collection(COL_PAIRS).document(
            pair_key(repo_ref, prev_sha, cur_sha)), {
                "repo": repo_ref, "prev": prev_sha, "cur": cur_sha,
                "comparisons": rec.get("comparisons"),
                "comparisons_ok": rec.get("comparisons_ok"),
                "seconds": rec.get("seconds"),
                "analysed_at": now, "scan_id": scan_id,
        }))

    for f in findings:
        fid = f.get("finding_id") or hashlib.sha256(
            f"{repo_ref}|{f.get('commit')}|{f.get('rule_id')}|{f.get('file')}|"
            f"{f.get('contract')}|{f.get('function')}".encode("utf-8")
        ).hexdigest()[:24]
        ops.append((client.collection(COL_FINDINGS).document(fid), {
            "repo": repo_ref, "scan_id": scan_id, "recorded_at": now,
            "rule_id": f.get("rule_id"), "owasp": f.get("owasp"),
            "verdict": f.get("verdict"), "liveness": f.get("liveness"),
            "commit": f.get("commit"), "parent": f.get("parent"),
            "file": f.get("file"), "contract": f.get("contract"),
            "function": f.get("function"), "line": f.get("line"),
            "detail": (f.get("detail") or "")[:1500],
            "survives_to_head": f.get("survives_to_head"),
            "downgrade_reasons": f.get("downgrade_reasons", []),
        }))

    written = 0
    for chunk_start in range(0, len(ops), 400):   # under Firestore's 500 cap
        batch = client.batch()
        chunk = ops[chunk_start:chunk_start + 400]
        for ref, payload in chunk:
            batch.set(ref, payload)
        batch.commit()
        written += len(chunk)

    return {"ok": True, "written": written, "scan_id": scan_id,
            "findings": len(findings)}


def seen_pair(repo: str, prev_sha: str, cur_sha: str) -> Optional[dict]:
    """A previously analysed pair, or None.

    The point of the corpus that compounds: a caller can skip work already
    done. Returns the STORED record unchanged - never a re-derived verdict.
    """
    client = _connect()
    if client is None:
        return None
    try:
        snap = client.collection(COL_PAIRS).document(
            pair_key(repo, prev_sha, cur_sha)).get()
        return snap.to_dict() if snap.exists else None
    except Exception:  # noqa: BLE001
        return None


def query_findings(*, rule_id: Optional[str] = None,
                   verdict: Optional[str] = None,
                   repo: Optional[str] = None,
                   limit: int = 50) -> list[dict]:
    """Cross-repository query - the thing no single scan can answer.

    e.g. every CONFIRMED rule-10 finding ever recorded, across every protocol
    this installation has walked.
    """
    client = _connect()
    if client is None:
        return []
    try:
        q = client.collection(COL_FINDINGS)
        if rule_id:
            q = q.where("rule_id", "==", str(rule_id))
        if verdict:
            q = q.where("verdict", "==", verdict.upper())
        if repo:
            q = q.where("repo", "==", _repo_id(repo))
        return [d.to_dict() for d in q.limit(int(limit)).stream()]
    except Exception:  # noqa: BLE001
        return []


# -------------------------------------------------------------- job state


def put_job(job_id: str, state: dict) -> bool:
    """Persist one web-app job so it survives the instance that started it."""
    client = _connect()
    if client is None:
        return False
    try:
        client.collection(COL_JOBS).document(f"job-{job_id}").set(
            {**state, "updated_at": time.time()}, merge=True)
        return True
    except Exception:  # noqa: BLE001
        return False


def get_job(job_id: str) -> Optional[dict]:
    client = _connect()
    if client is None:
        return None
    try:
        snap = client.collection(COL_JOBS).document(f"job-{job_id}").get()
        return snap.to_dict() if snap.exists else None
    except Exception:  # noqa: BLE001
        return None
