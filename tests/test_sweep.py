"""Capability 21 - the unattended sweep.

The property under test is not "does it scan" (that is `scan.py`'s job and is
tested elsewhere). It is: **does a failing target stop the sweep?** Because
nobody is watching a scheduled run, and a sweep that dies on repo four of
twenty is worse than useless - it looks like a completed run with a short list.

Run:  python -m pytest tests/test_sweep.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from src import funnel as F  # noqa: E402
from src import sweep as S  # noqa: E402
from webapp import server as SRV  # noqa: E402


# --------------------------------------------------------------------------- #
# Target parsing.
# --------------------------------------------------------------------------- #

def test_a_target_line_parses_all_four_fields():
    t = S.SweepTarget.parse("https://github.com/org/repo, contracts, 0xabc, 30")
    assert t.repo == "https://github.com/org/repo"
    assert t.root == "contracts" and t.address == "0xabc" and t.limit == 30


def test_comments_and_blanks_are_ignored():
    assert S.SweepTarget.parse("   ") is None
    assert S.SweepTarget.parse("# just a note") is None
    t = S.SweepTarget.parse("org/repo   # trailing note")
    assert t and t.repo == "org/repo"


def test_a_bad_limit_does_not_lose_the_target():
    """An unattended runner must not drop a repo over a typo in a number."""
    t = S.SweepTarget.parse("org/repo,,,not-a-number")
    assert t and t.repo == "org/repo" and t.limit == 15


def test_a_target_file_is_read_in_order(tmp_path):
    f = tmp_path / "repos.txt"
    f.write_text("# list\na\n\nb, contracts\nc\n", encoding="utf-8")
    assert [t.repo for t in S.load_targets(f)] == ["a", "b", "c"]


# --------------------------------------------------------------------------- #
# The one property that matters.
# --------------------------------------------------------------------------- #

def test_a_failing_target_is_recorded_and_never_raises(tmp_path):
    row = S.run_one(S.SweepTarget(repo=str(tmp_path / "nope")))
    assert row["ok"] is False
    assert "not a git working tree" in row["error"]
    assert row["traceback"]
    assert row["seconds"] >= 0


def test_one_failure_does_not_stop_the_others(monkeypatch):
    """Three targets, the middle one exploding inside the scan itself - the
    hardest case, because the failure is not a bad path the runner could have
    pre-checked."""
    seen: list[str] = []

    def fake_run_one(target, **kw):
        seen.append(target.repo)
        if target.repo == "boom":
            return {"repo": "boom", "ok": False, "error": "RuntimeError: boom",
                    "head": "", "summary": {}, "funnel_summary": {},
                    "agent": {}, "seconds": 0.1}
        return {"repo": target.repo, "ok": True, "error": "", "head": "h",
                "summary": {"findings": 2, "confirmed": 0, "candidates": 2},
                "funnel_summary": {"traces": 2, "resolvable": 2, "killed": 0},
                "agent": {}, "seconds": 1.0}

    monkeypatch.setattr(S, "run_one", fake_run_one)
    sweep = S.run_sweep([S.SweepTarget(repo=r) for r in ("a", "boom", "b")])

    assert seen == ["a", "boom", "b"], "the sweep stopped early"
    assert sweep["totals"]["ok"] == 2
    assert sweep["totals"]["failed"] == 1
    assert sweep["totals"]["findings"] == 4
    assert sweep["totals"]["candidates"] == 4


def test_the_digest_names_every_failure(monkeypatch):
    """A failure that is recorded but never printed is a failure nobody sees."""
    monkeypatch.setattr(S, "run_one", lambda t, **kw: {
        "repo": t.repo, "ok": False, "error": "RuntimeError: no clone",
        "head": "", "summary": {}, "funnel_summary": {}, "agent": {},
        "seconds": 0.2})
    text = S.summarize_text(S.run_sweep([S.SweepTarget(repo="x")]))
    assert "FAIL" in text and "x" in text and "no clone" in text
    assert "1 failed" in text


def test_an_all_failing_sweep_is_still_a_complete_record(monkeypatch):
    monkeypatch.setattr(S, "run_one", lambda t, **kw: {
        "repo": t.repo, "ok": False, "error": "nope", "head": "",
        "summary": {}, "funnel_summary": {}, "agent": {}, "seconds": 0.0})
    sweep = S.run_sweep([S.SweepTarget(repo=r) for r in ("a", "b")])
    assert sweep["totals"] == {"repos": 2, "ok": 0, "failed": 2, "findings": 0,
                               "confirmed": 0, "candidates": 0,
                               "resolvable": 0, "killed": 0}
    assert sweep["sweep_id"] and sweep["seconds"] >= 0


# --------------------------------------------------------------------------- #
# Self-check.
# --------------------------------------------------------------------------- #

def test_verify_accepts_a_consistent_sweep(monkeypatch):
    monkeypatch.setattr(S, "run_one", lambda t, **kw: {
        "repo": t.repo, "ok": True, "error": "", "head": "h",
        "summary": {"findings": 1}, "agent": {}, "seconds": 1.0,
        "funnel_summary": {"traces": 3, "resolvable": 2, "killed": 1}})
    assert S.verify(S.run_sweep([S.SweepTarget(repo="a")])) == 1


def test_verify_rejects_a_summary_that_does_not_add_up(monkeypatch):
    monkeypatch.setattr(S, "run_one", lambda t, **kw: {
        "repo": t.repo, "ok": True, "error": "", "head": "h",
        "summary": {"findings": 1}, "agent": {}, "seconds": 1.0,
        "funnel_summary": {"traces": 9, "resolvable": 2, "killed": 1}})
    with pytest.raises(F.TraceDivergence):
        S.verify(S.run_sweep([S.SweepTarget(repo="a")]))


# --------------------------------------------------------------------------- #
# The HTTP surface.
# --------------------------------------------------------------------------- #

client = TestClient(SRV.app)


def test_sweeps_route_says_not_recorded_rather_than_showing_an_empty_list(
        monkeypatch):
    """"No corpus configured" and "no sweep has ever run" are different facts
    and the API must not collapse them - the same distinction coverage draws
    for a scan."""
    from src import corpus as CORPUS

    monkeypatch.setattr(CORPUS, "available",
                        lambda: {"available": False, "reason": "no creds"})
    monkeypatch.setattr(CORPUS, "list_sweeps", lambda limit=20: [])
    body = client.get("/api/sweeps").json()
    assert body["available"] is False
    assert body["reason"] == "no creds"
    assert body["sweeps"] == []


def test_sweeps_route_returns_recorded_sweeps(monkeypatch):
    from src import corpus as CORPUS

    monkeypatch.setattr(CORPUS, "available",
                        lambda: {"available": True, "database": "db"})
    monkeypatch.setattr(CORPUS, "list_sweeps", lambda limit=20: [
        {"sweep_id": "s1", "totals": {"ok": 2, "failed": 1}}])
    body = client.get("/api/sweeps?limit=5").json()
    assert body["available"] is True
    assert body["sweeps"][0]["sweep_id"] == "s1"


# --------------------------------------------------------------------------- #
# Persistence.
# --------------------------------------------------------------------------- #

def test_a_recorded_sweep_drops_tracebacks_but_keeps_the_error(monkeypatch):
    from src import corpus as CORPUS

    written: dict = {}

    class FakeClient:
        def collection(self, name):
            written["collection"] = name
            return self

        def document(self, key):
            written["doc"] = key
            return self

        def set(self, payload):
            written["payload"] = payload

    monkeypatch.setattr(CORPUS, "_client", FakeClient())
    monkeypatch.setattr(CORPUS, "_probe_error", "")

    res = CORPUS.record_sweep({
        "schema": S.SCHEMA, "sweep_id": "abc", "started_at": 1.0,
        "finished_at": 2.0, "seconds": 1.0, "used_agent": False,
        "totals": {"ok": 0, "failed": 1},
        "results": [{"repo": "r", "ok": False, "error": "boom",
                     "traceback": "a very long traceback " * 50}],
    })
    assert res["ok"] is True
    assert written["collection"] == CORPUS.COL_SWEEPS
    row = written["payload"]["results"][0]
    assert row["error"] == "boom"
    assert "traceback" not in row


def test_recording_a_sweep_without_a_corpus_degrades(monkeypatch):
    from src import corpus as CORPUS

    monkeypatch.setattr(CORPUS, "_client", None)
    monkeypatch.setattr(CORPUS, "_probe_error", "no creds")
    res = CORPUS.record_sweep({"sweep_id": "x", "results": []})
    assert res["ok"] is False and res["written"] == 0
