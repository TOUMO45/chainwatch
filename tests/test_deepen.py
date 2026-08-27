"""DEEPEN-1 / capability 15 - routing a CANDIDATE to what would settle it.

Three real deepening strategies already existed (rename-following for
reachability, the immutable-clone recompile for liveness, the capability 13/14
probes for live exposure) and nothing routed a finding to the right one. A
reader saw `missing evidence: liveness` and had to know from the source which
applied and what input it needed.

THE INVARIANT THESE TESTS EXIST TO PROTECT: this module gathers and names
evidence, it never grades. If a deepening step could promote a verdict, it
would be a second implementation of `verdict.classify` - two things that can
disagree about what CONFIRMED means, which is the failure mode this project
avoids everywhere else. `next_steps` is pure: it reads a finished finding and
returns a description.

Run:  python -m pytest tests/test_deepen.py -q
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import deepen as D  # noqa: E402


def _candidate(**over) -> dict:
    f = {"verdict": "CANDIDATE", "liveness": None, "address_used": False,
         "survives_to_head": True, "downgrade_reasons": []}
    f.update(over)
    return f


# --------------------------------------------------------- the hard invariant


def test_a_confirmed_finding_has_nothing_left_to_settle():
    assert D.next_steps({"verdict": "CONFIRMED"}) == []
    assert D.summarize({"verdict": "CONFIRMED"}) is None


def test_next_steps_never_mutates_the_finding():
    """Purity is the whole safety argument: a step that could write to the
    finding could change a verdict field."""
    f = _candidate(downgrade_reasons=["missing evidence: liveness"])
    before = copy.deepcopy(f)
    D.next_steps(f)
    assert f == before


def test_no_step_ever_reports_a_verdict():
    """Guard against a future step growing a 'verdict' or 'promote' key."""
    f = _candidate(downgrade_reasons=[
        "missing evidence: liveness, reachability",
        "rule 5 caps this trigger class at CANDIDATE",
    ])
    for step in D.next_steps(f):
        assert set(step) == {"gap", "status", "why", "action", "cost"}
        assert "CONFIRMED" not in step["status"].upper()


# --------------------------------------------------------- routing behaviour


def test_missing_address_is_distinguished_from_a_failed_match():
    """Two different gaps behind one `liveness: UNKNOWN`, with two different
    next steps. Collapsing them is what made the old output unactionable."""
    no_addr = D.next_steps(_candidate(
        downgrade_reasons=["missing evidence: liveness"]))[0]
    assert no_addr["status"] == "actionable"
    assert "--address" in no_addr["action"]

    bad_match = D.next_steps(_candidate(
        address_used=True, liveness="UNKNOWN",
        downgrade_reasons=["missing evidence: liveness"]))[0]
    assert bad_match["status"] == "actionable"
    assert "optimizer runs" in bad_match["action"]
    assert no_addr["why"] != bad_match["why"]


def test_a_patched_target_is_settled_not_actionable():
    """PATCHED is an answer, not a gap. Telling a user to 'try harder' here
    would be inviting them to manufacture a finding that is not there."""
    step = D.next_steps(_candidate(
        address_used=True, liveness="PATCHED",
        downgrade_reasons=["liveness=PATCHED, CONFIRMED requires LIVE"]))[0]
    assert step["status"] == "settled-negative"
    assert "none" in step["action"].lower()


def test_repaired_at_head_still_flags_the_immutable_clone_case():
    """The 88mph lesson: 'fixed in source' and 'fixed on chain' are different
    claims for a clone, and the step must not let a reader conflate them."""
    step = D.next_steps(_candidate(
        survives_to_head=False, fixed_at="f4886f31",
        downgrade_reasons=["regression does not survive to HEAD (repaired at f4886f31)"],
    ))[0]
    assert step["status"] == "settled-negative"
    assert "clone" in step["action"].lower()
    assert "f4886f31" in step["why"]


def test_a_rule_ceiling_is_reported_as_blocked_not_actionable():
    """A RULES.md cap is not missing evidence. Presenting it as actionable would
    invite exactly the per-finding override the rule exists to prevent."""
    step = D.next_steps(_candidate(
        downgrade_reasons=["rule 5 caps this trigger class at CANDIDATE"]))[0]
    assert step["gap"] == "rule-ceiling"
    assert step["status"] == "blocked"
    assert "RULES.md" in step["action"]


def test_multiple_gaps_are_all_reported_once_each():
    steps = D.next_steps(_candidate(downgrade_reasons=[
        "missing evidence: liveness, reachability",
        "liveness=UNKNOWN, CONFIRMED requires LIVE",   # same gap, second phrasing
    ]))
    gaps = [s["gap"] for s in steps]
    assert sorted(gaps) == ["liveness", "reachability"]
    assert len(gaps) == len(set(gaps)), "a gap was reported twice"


def test_an_unrecognised_reason_is_surfaced_not_dropped():
    """Silence would be the wrong failure: an unrouted reason must be visible as
    a gap in this module, not vanish from the report."""
    steps = D.next_steps(_candidate(
        downgrade_reasons=["some future reason nobody has routed yet"]))
    assert len(steps) == 1
    assert steps[0]["status"] == "unknown"
    assert "some future reason" in steps[0]["why"]


def test_summarize_prefers_something_the_user_can_act_on():
    f = _candidate(
        survives_to_head=False, fixed_at="abc1234", address_used=False,
        downgrade_reasons=["regression does not survive to HEAD (repaired at abc1234)",
                           "missing evidence: liveness"])
    line = D.summarize(f)
    assert line and line.startswith("liveness:"), \
        "summarize surfaced a settled gap over an actionable one"
