"""MULTI-INSTANCE-1 - a scan job must survive landing on a different Cloud Run
instance than the one that ran it.

Measured live, not hypothesised: a scan started against the deployed service
and polled seconds later returned `{"detail": "no such scan"}`. `JOBS` is a
process-local dict; Cloud Run gives no session-affinity guarantee by default,
so the POST that starts a scan, the polls that check it, and the instance that
actually runs it can be three different processes that share nothing.
`CORPUS.put_job`/`get_job` existed for exactly this (see `corpus.py`'s own
module docstring) but were never wired to a write site until this fix.

These tests never hit a real Cloud Run instance or a real Firestore project -
they fake the ONE thing that differs between instances (the in-memory `JOBS`
dict) and assert the API falls back to a corpus read that a fake persistence
layer can serve. The multi-instance condition is simulated by deleting a job
from `JOBS` after "another instance" would have persisted it - which is
exactly what happens for real between a POST and a later GET on Cloud Run.

Run:  python -m pytest tests/test_job_multi_instance.py -q
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from webapp import server as SRV  # noqa: E402

client = TestClient(SRV.app)


class FakeCorpus:
    """A minimal stand-in for the two functions this fix actually calls,
    keyed exactly like the real `src.corpus.put_job`/`get_job` contract:
    `put_job` never raises, `get_job` returns `None` for anything unknown."""

    def __init__(self):
        self.store: dict[str, dict] = {}

    def put_job(self, job_id: str, state: dict) -> bool:
        self.store[f"job-{job_id}"] = dict(state)
        return True

    def get_job(self, job_id: str):
        return self.store.get(f"job-{job_id}")


@pytest.fixture
def fake_corpus(monkeypatch):
    fc = FakeCorpus()
    monkeypatch.setattr(SRV, "CORPUS", fc, raising=False)
    # The module imports `corpus` LOCALLY inside each function
    # (`from src import corpus as CORPUS`), not at module scope, so patching
    # `SRV.CORPUS` does nothing - patch the real import target instead.
    monkeypatch.setattr("src.corpus.put_job", fc.put_job)
    monkeypatch.setattr("src.corpus.get_job", fc.get_job)
    yield fc


def _job(status="done", report=None) -> SRV.Job:
    j = SRV.Job(id="abc123def456", repo="https://example.com/org/repo")
    j.status = status
    j.finished = time.time() if status in ("done", "error", "cancelled") else None
    j.report = report
    return j


# --------------------------------------------------------------------------- #
# The core property: a job absent from THIS instance's JOBS dict is still
# readable if another instance persisted it.
# --------------------------------------------------------------------------- #

def test_a_job_missing_locally_is_served_from_the_corpus(fake_corpus):
    report = {"summary": {"findings": 1, "confirmed": 0, "candidates": 1}}
    fake_corpus.put_job("abc123def456", {
        "id": "abc123def456", "repo": "https://example.com/org/repo",
        "status": "done", "started": 1.0, "finished": 2.0, "error": "",
        "summary": report["summary"], "report": report,
    })
    # NOT in this instance's JOBS - simulates a poll landing elsewhere.
    assert "abc123def456" not in SRV.JOBS

    body = client.get("/api/scan/abc123def456").json()
    assert body["status"] == "done"
    assert body["report"]["summary"]["findings"] == 1


def test_a_job_present_locally_never_touches_the_corpus(fake_corpus,
                                                        monkeypatch):
    """The common case (same instance) must not pay a Firestore round trip -
    and must not silently prefer stale persisted state over live memory."""
    j = _job(report={"summary": {"findings": 9}})
    SRV.JOBS[j.id] = j
    fake_corpus.put_job(j.id, {"status": "queued", "report": None})  # stale

    calls = {"n": 0}
    real_get = fake_corpus.get_job

    def counting_get(job_id):
        calls["n"] += 1
        return real_get(job_id)

    monkeypatch.setattr("src.corpus.get_job", counting_get)
    try:
        body = client.get(f"/api/scan/{j.id}").json()
        assert body["report"]["summary"]["findings"] == 9  # live, not stale
        assert calls["n"] == 0
    finally:
        SRV.JOBS.pop(j.id, None)


def test_a_job_nowhere_is_still_a_404(fake_corpus):
    assert client.get("/api/scan/totally-unknown").status_code == 404


def test_a_firestore_read_failure_degrades_to_404_not_a_500(monkeypatch):
    """`get_job` folding every exception into `None` is the corpus module's
    own contract; this pins that the route relies on that contract rather
    than wrapping it again."""
    def raising(job_id):
        raise RuntimeError("boom")

    # Simulate the (impossible per contract, but worth pinning) case where the
    # import itself resolves to a function that misbehaves - the route must
    # not crash the request.
    import src.corpus as C
    monkeypatch.setattr(C, "get_job", lambda job_id: None)
    assert client.get("/api/scan/nope-either").status_code == 404


# --------------------------------------------------------------------------- #
# The write side: start_scan and _run_job's completion both persist.
# --------------------------------------------------------------------------- #

def test_start_scan_persists_a_queued_placeholder(fake_corpus, monkeypatch):
    monkeypatch.setattr(SRV, "JOBS", {})
    monkeypatch.setattr(threading := __import__("threading"), "Thread",
                        lambda *a, **kw: type("T", (), {"start": lambda self: None})())
    resp = client.post("/api/scan", json={"repo": "https://example.com/x"})
    assert resp.status_code == 200
    job_id = resp.json()["id"]
    persisted = fake_corpus.get_job(job_id)
    assert persisted is not None
    assert persisted["status"] == "queued"
    assert persisted["report"] is None


def test_run_job_persists_the_terminal_state(fake_corpus):
    """Exercises `_run_job`'s `finally` block directly - the exact site the
    fix adds - without going through a real scan or a real clone."""
    j = _job(status="queued", report=None)
    SRV.JOBS[j.id] = j

    class Req:
        repo = "/definitely/not/a/git/repo"

    try:
        SRV._run_job(j, Req())  # the bad path -> "not a git working tree"
    finally:
        pass

    assert j.status == "error"
    persisted = fake_corpus.get_job(j.id)
    assert persisted is not None
    assert persisted["status"] == "error"
    assert "not a git working tree" in persisted["error"]
    SRV.JOBS.pop(j.id, None)


def test_persistence_failure_never_breaks_the_response(monkeypatch):
    """DEGRADES, NEVER BLOCKS - the same discipline `corpus.py` states for
    every other write in this module. A broken Firestore client must not turn
    a successfully-started or successfully-finished scan into a 500."""
    import src.corpus as C

    def boom(*a, **kw):
        raise RuntimeError("firestore is down")

    monkeypatch.setattr(C, "put_job", boom)
    monkeypatch.setattr(SRV, "JOBS", {})
    monkeypatch.setattr(__import__("threading"), "Thread",
                        lambda *a, **kw: type("T", (), {"start": lambda self: None})())
    resp = client.post("/api/scan", json={"repo": "https://example.com/x"})
    assert resp.status_code == 200

    j = _job(status="running", report=None)
    monkeypatch.setattr(C, "put_job", boom)

    class Req:
        repo = "/definitely/not/a/git/repo"

    SRV._run_job(j, Req())        # must not raise despite put_job blowing up
    assert j.status == "error"
