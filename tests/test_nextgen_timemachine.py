"""Phase 1 - the Security Time Machine engine (src/nextgen/timemachine.py, spec §1).

Two layers, both here:
  * `_derive_events` / `PropertyTimeline` - pure, fast, exhaustive.
  * `walk_property` against a REAL synthetic git repo, with a fake probe that
    just greps the file - exercises the git walk and `history.file_at` with no
    compiler in the loop.

Run:  python -m pytest tests/test_nextgen_timemachine.py -q
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen import timemachine as TM  # noqa: E402
from src.nextgen import evidence_graph as EG  # noqa: E402


def snap(sha, present, value=None, measurable=True, subject=""):
    return TM.Snapshot(sha, sha[:12], "dev", "2026-01-01T00:00:00Z",
                       subject or sha, present, value, measurable)


# --------------------------------------------------------------------------- #
# _derive_events
# --------------------------------------------------------------------------- #

def test_introduced_then_removed_then_still_absent():
    snaps = [
        snap("c1", True, ("modifier:onlyOwner",)),
        snap("c2", True, ("modifier:onlyOwner",)),      # unchanged -> no event
        snap("c3", False, ()),                          # REMOVED
        snap("c4", False, ()),                          # unchanged -> no event
    ]
    tl = TM.build_timeline(snaps, kind=TM.ACCESS_CONTROL)
    kinds = [(e.kind, e.at_commit) for e in tl.events]
    assert kinds == [(TM.INTRODUCED, "c1"), (TM.REMOVED, "c3")]
    assert tl.current_state == TM.ABSENT
    assert tl.regression_commit.at_commit == "c3"
    assert tl.first_introduced.at_window_start is True


def test_modified_when_present_but_value_changes():
    snaps = [
        snap("c1", True, ("modifier:onlyOwner",)),
        snap("c2", True, ("modifier:onlyRole",)),       # MODIFIED
        snap("c3", True, ("modifier:onlyRole",)),
    ]
    tl = TM.build_timeline(snaps)
    assert [e.kind for e in tl.events] == [TM.INTRODUCED, TM.MODIFIED]
    assert tl.modifications[0].from_value == ("modifier:onlyOwner",)
    assert tl.modifications[0].to_value == ("modifier:onlyRole",)
    assert tl.current_state == TM.PRESENT
    assert tl.regression_commit is None          # present now -> no live regression


def test_removed_then_restored_clears_the_regression():
    snaps = [
        snap("c1", True, ("g",)),
        snap("c2", False, ()),                          # REMOVED
        snap("c3", True, ("g",)),                       # RESTORED
    ]
    tl = TM.build_timeline(snaps)
    assert [e.kind for e in tl.events] == [TM.INTRODUCED, TM.REMOVED, TM.RESTORED]
    assert tl.restored_after_regression is True
    assert tl.regression_commit is None
    assert tl.current_state == TM.PRESENT


def test_second_removal_after_restore_is_the_live_regression():
    snaps = [
        snap("c1", True, ("g",)),
        snap("c2", False, ()),        # REMOVED (later healed)
        snap("c3", True, ("g",)),     # RESTORED
        snap("c4", False, ()),        # REMOVED again -> this one is live
    ]
    tl = TM.build_timeline(snaps)
    assert tl.regression_commit.at_commit == "c4"
    assert tl.current_state == TM.ABSENT


def test_unmeasurable_snapshots_are_skipped_not_treated_as_absent():
    snaps = [
        snap("c1", True, ("g",)),
        snap("c2", False, None, measurable=False),      # compile failed - skip
        snap("c3", True, ("g",)),                       # still present
    ]
    tl = TM.build_timeline(snaps)
    assert [e.kind for e in tl.events] == [TM.INTRODUCED]   # no REMOVED
    assert tl.current_state == TM.PRESENT


def test_all_unmeasurable_is_unknown_state_with_no_events():
    snaps = [snap("c1", False, None, measurable=False),
             snap("c2", False, None, measurable=False)]
    tl = TM.build_timeline(snaps)
    assert tl.events == []
    assert tl.current_state == TM.UNKNOWN
    assert tl.regression_commit is None


def test_absent_from_the_start_never_emits_introduced():
    snaps = [snap("c1", False, ()), snap("c2", False, ()), snap("c3", True, ("g",))]
    tl = TM.build_timeline(snaps)
    assert [e.kind for e in tl.events] == [TM.INTRODUCED]
    assert tl.events[0].at_commit == "c3"
    assert tl.events[0].at_window_start is False


def test_first_snapshot_present_is_flagged_window_start():
    tl = TM.build_timeline([snap("c1", True, ("g",))])
    assert tl.first_introduced.at_window_start is True


def test_walk_property_rejects_a_bad_kind():
    class Bad(TM.PropertyProbe):
        kind = "NONSENSE"
        paths = ("x.sol",)
        def measure(self, get_file):
            return TM.Measurement(True)

    with pytest.raises(ValueError):
        TM.walk_property(Path("."), Bad())


# --------------------------------------------------------------------------- #
# rendering / serialisation / evidence graph
# --------------------------------------------------------------------------- #

def test_render_text_marks_the_regression_commit():
    snaps = [snap("aaaa1111", True, ("g",), subject="add guard"),
             snap("bbbb2222", False, (), subject="refactor")]
    txt = TM.build_timeline(snaps, title="Only owner can withdraw",
                            kind=TM.ACCESS_CONTROL).render_text()
    assert "Only owner can withdraw" in txt
    assert "<-- regression" in txt
    assert "ABSENT" in txt


def test_as_dict_is_json_safe():
    import json
    snaps = [snap("c1", True, frozenset({"a", "b"})), snap("c2", False, ())]
    d = TM.build_timeline(snaps).as_dict()
    json.dumps(d)          # must not raise
    assert d["current_state"] == TM.ABSENT


def test_to_evidence_graph_adds_property_and_commit_nodes():
    snaps = [snap("c1", True, ("g",)), snap("c2", False, ())]
    tl = TM.build_timeline(snaps, title="P", kind=TM.ACCESS_CONTROL,
                           paths=("contracts/Vault.sol",))
    g = EG.EvidenceGraph()
    pid = tl.to_evidence_graph(g)
    assert g.node(pid).kind == EG.SECURITY_PROPERTY
    assert g.node(pid).established_by == "nextgen.timemachine"
    # the REMOVED commit REFUTES the property
    refutes = [e for e in g.edges(relation=EG.REFUTES)]
    assert refutes and g.node(refutes[0].src).data["event"] == TM.REMOVED


# --------------------------------------------------------------------------- #
# walk_property against a real synthetic git repo (no compiler)
# --------------------------------------------------------------------------- #

def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True,
                   capture_output=True, text=True)


@pytest.fixture
def synth_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    src = repo / "contracts"
    src.mkdir()
    f = src / "Vault.sol"

    def commit(body, msg):
        f.write_text(body, encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", msg)

    commit("function withdraw() external { require(msg.sender == owner); }", "guard in")
    commit("function withdraw() external { require(msg.sender == owner); } // touch",
           "unrelated edit")
    commit("function withdraw() external { }", "drop the guard")
    commit("function withdraw() external { } // still open", "another edit")
    return repo


class _GrepProbe(TM.PropertyProbe):
    kind = TM.ACCESS_CONTROL
    id = "grep:withdraw-guard"
    title = "withdraw() checks msg.sender"
    paths = ("contracts/Vault.sol",)

    def measure(self, get_file):
        text = get_file("contracts/Vault.sol")
        if text is None:
            return TM.Measurement(False, None, measurable=False)
        present = "require(msg.sender" in text
        return TM.Measurement(present, ("has-check",) if present else (),
                              measurable=True)


def test_walk_property_over_real_history(synth_repo):
    tl = TM.walk_property(synth_repo, _GrepProbe(), limit=50)
    assert len(tl.snapshots) == 4
    kinds = [e.kind for e in tl.events]
    assert kinds == [TM.INTRODUCED, TM.REMOVED]
    assert tl.current_state == TM.ABSENT
    reg = tl.regression_commit
    assert reg is not None
    # the regression is the 3rd commit ("drop the guard")
    assert reg.subject == "drop the guard"


def test_walk_property_limit_keeps_the_most_recent(synth_repo):
    tl = TM.walk_property(synth_repo, _GrepProbe(), limit=2)
    assert len(tl.snapshots) == 2
    assert tl.snapshots[-1].subject == "another edit"
