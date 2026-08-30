"""Capability 19 over HTTP - `GET /api/scan/{id}/funnel`.

The route exists to answer one question the report alone cannot: are the
numbers about to be drawn still consistent with the evidence recorded beside
them? It therefore RE-VERIFIES on every read rather than trusting what the
scan wrote, and says so in `verified`. These tests pin that behaviour,
including the failure direction - a tampered trace must be reported as a
divergence, never quietly served.

Run:  python -m pytest tests/test_funnel_api.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from src import funnel as F  # noqa: E402
from src.nextgen import state as S  # noqa: E402
from webapp import server as SRV  # noqa: E402

client = TestClient(SRV.app)


@pytest.fixture
def job(monkeypatch):
    """One finished job carrying two traces: one resolvable, one killed."""
    open_gates = {g.name: S.PASS for g in S.GATES}
    open_gates["target_live"] = S.PENDING
    resolvable = F.from_finding_state(_state("open", open_gates))

    dead_gates = {g.name: S.PASS for g in S.GATES}
    dead_gates["reproducer"] = S.FAIL
    killed = F.from_finding_state(_state("dead", dead_gates))

    traces = [killed, resolvable]
    j = SRV.Job(id="testjob", repo="org/repo")
    j.status = "done"
    j.report = {"funnel": {
        "schema": F.SCHEMA,
        "summary": F.summarize(traces),
        "traces": traces,
        "resolution_queue": [t["finding_id"]
                             for t in F.resolution_queue(traces)],
        "divergence": "",
    }}
    SRV.JOBS[j.id] = j
    yield j
    SRV.JOBS.pop(j.id, None)


def _state(name: str, gates: dict) -> S.FindingState:
    fs = S.FindingState(name)
    for g, r in gates.items():
        fs.set_gate(g, r)
    return fs


def test_unknown_job_is_404():
    assert client.get("/api/scan/nope/funnel").status_code == 404


def test_funnel_is_served_verified(job):
    body = client.get(f"/api/scan/{job.id}/funnel").json()
    assert body["verified"] is True
    assert body["divergence"] == ""
    assert len(body["traces"]) == 2
    assert body["summary"]["killed"] == 1
    assert body["summary"]["resolvable"] == 1


def test_the_served_queue_excludes_the_killed_candidate(job):
    body = client.get(f"/api/scan/{job.id}/funnel").json()
    ids = [t["finding_id"] for t in body["queue"]]
    assert ids == ["open"], "a REJECTED candidate is not resolvable by evidence"


def test_a_tampered_trace_is_reported_not_served_silently(job):
    """The whole point of re-verifying on read. A stored verdict that does not
    follow from its own gate states must surface as a divergence."""
    job.report["funnel"]["traces"][1]["verdict"] = S.VERDICT_CONFIRMED
    body = client.get(f"/api/scan/{job.id}/funnel").json()
    assert body["verified"] is False
    assert "CONFIRMED" in body["divergence"]


def test_a_scan_with_no_funnel_section_returns_an_empty_verified_body():
    """Reports predating capability 19 have no funnel. Zero traces verify
    vacuously - the route must not 500 on a corpus older than the feature."""
    j = SRV.Job(id="oldjob", repo="org/repo")
    j.status = "done"
    j.report = {"summary": {}, "findings": []}
    SRV.JOBS[j.id] = j
    try:
        body = client.get("/api/scan/oldjob/funnel").json()
        assert body["verified"] is True
        assert body["queue"] == []
    finally:
        SRV.JOBS.pop("oldjob", None)
