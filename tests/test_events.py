"""The scan event stream, as a contract a progress view can be built on.

A progress indicator is only honest if every pair it starts is a pair it can
finish. That requires one property of the stream and nothing more:

    every pair emits exactly one `pair`, then exactly one of `skip` or
    `pair-done`.

It was NOT true. The `checkout-failed` branch of `scan()` updated coverage and
`continue`d without emitting anything, while its sibling `env-reconstruction-
failed` branch emitted a `skip` - so a pair could open on the stream and never
close, and the pairs it happened to for were the ones that went worst. The
final report showed the skip; the live view hung on it. That is fixed and
pinned here.

The invariant is asserted against a REAL scan over a temporary repository, not
against a hand-built list of events, because the thing that can regress is the
control flow of the loop and only a real traversal exercises it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import history as H  # noqa: E402
from src.scan import ScanOptions, scan  # noqa: E402

SOL = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\ncontract C {}\n"


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, "git %s: %s" % (" ".join(args), proc.stderr)
    return proc.stdout


def _repo_with_two_commits(tmp_path: Path) -> Path:
    src = tmp_path / "target"
    (src / "src").mkdir(parents=True)
    (src / "src" / "C.sol").write_text(SOL, encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(src)], capture_output=True,
                   text=True, timeout=120, check=True)
    _git(src, "config", "user.email", "t@example.com")
    _git(src, "config", "user.name", "t")
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "one")
    (src / "src" / "C.sol").write_text(SOL + "// touched\n", encoding="utf-8")
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "two")
    return src


def _run(tmp_path: Path, repo: Path) -> tuple[list[dict], dict]:
    events: list[dict] = []
    opts = ScanOptions(
        repo=repo, limit=5,
        worktrees=tmp_path / "wt", cache=tmp_path / "cache",
        # No rules: this file is about the STREAM, not about detection, and an
        # empty rule set keeps a real traversal free of compilation cost.
        rules=[],
        check_head_survival=False,
    )
    report = scan(opts, on_event=events.append)
    return events, report


def _pairing(events: list[dict]) -> list[tuple]:
    """(pair-event, resolution-event) for each pair, in stream order."""
    opened, out = None, []
    for ev in events:
        if ev["kind"] == "pair":
            assert opened is None, "a second `pair` opened before the first resolved"
            opened = ev
        elif ev["kind"] in ("skip", "pair-done"):
            assert opened is not None, "`%s` with no open pair" % ev["kind"]
            out.append((opened, ev))
            opened = None
    assert opened is None, "a pair opened and never resolved"
    return out


def test_a_normal_pair_opens_once_and_closes_once(tmp_path):
    repo = _repo_with_two_commits(tmp_path)
    events, report = _run(tmp_path, repo)

    pairs = _pairing(events)
    assert len(pairs) == 1
    opened, closed = pairs[0]
    assert closed["kind"] == "pair-done"
    assert closed["index"] == opened["index"] == 1
    assert closed["total"] == opened["total"] == 1
    assert len(report["coverage"]["pair_records"]) == 1


def test_a_checkout_failure_still_closes_its_pair(tmp_path, monkeypatch):
    """The regression this file exists for. Before the fix this produced a
    `pair` with no resolution at all."""
    repo = _repo_with_two_commits(tmp_path)

    def boom(self, sha):
        raise RuntimeError("simulated checkout failure")

    monkeypatch.setattr(H.Worktree, "checkout", boom)
    events, report = _run(tmp_path, repo)

    pairs = _pairing(events)
    assert len(pairs) == 1, "the pair never resolved on the stream"
    opened, closed = pairs[0]
    assert closed["kind"] == "skip"
    assert closed["reason"] == "checkout-failed"
    # Self-describing, so a progress view never has to remember which pair the
    # last `pair` event referred to.
    assert closed["index"] == opened["index"]
    assert closed["total"] == opened["total"]


def test_a_checkout_failure_is_still_counted_and_still_costs_time(tmp_path,
                                                                 monkeypatch):
    """A skipped pair is real elapsed time. Leaving it out of the observed set
    would make every remaining-time range too optimistic, systematically."""
    repo = _repo_with_two_commits(tmp_path)
    monkeypatch.setattr(H.Worktree, "checkout",
                        lambda self, sha: (_ for _ in ()).throw(RuntimeError("x")))
    _events, report = _run(tmp_path, repo)

    cov = report["coverage"]
    assert cov["pairs_skipped"] == 1
    assert [s["reason"] for s in cov["skips"]] == ["checkout-failed"]
    records = cov["pair_records"]
    assert len(records) == 1, "a skipped pair left no timing record"
    assert records[0]["comparisons"] == 0
    assert records[0]["seconds"] >= 0.0


def test_progress_is_derivable_from_the_stream_alone(tmp_path):
    """What G6 needs, stated as a test so it cannot quietly stop being true:
    the total, the current index and the completed count all come off existing
    events. No new event type is required."""
    repo = _repo_with_two_commits(tmp_path)
    events, _report = _run(tmp_path, repo)

    totals = [ev["total"] for ev in events if ev["kind"] == "pairs"]
    assert totals == [1]
    resolved = [ev for ev in events if ev["kind"] in ("skip", "pair-done")]
    assert len(resolved) == totals[0]
    assert all("index" in ev and "total" in ev for ev in resolved)
    # Timestamps are on every event, so elapsed and per-pair duration need no
    # extra field either.
    assert all("t" in ev for ev in events)


def test_the_live_sizing_rides_the_existing_pair_done_event(tmp_path):
    repo = _repo_with_two_commits(tmp_path)
    events, _report = _run(tmp_path, repo)

    done = [ev for ev in events if ev["kind"] == "pair-done"]
    assert done and "sizing" in done[-1]
    sizing = done[-1]["sizing"]
    assert sizing["observed"]["pairs"] == 1
    # One pair, none remaining: nothing to project and nothing to refuse.
    assert sizing["projection"] is None
    assert sizing["refusal"] == ""
