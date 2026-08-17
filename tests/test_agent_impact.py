"""Adversarial tests for the impact-narration gate (explain_impact / verify_impact).

Same discipline as tests/test_agent_tools.py: every check ships with an input
that MUST fail it. A gate that has never rejected anything is not known to work
- METHODOLOGY instance 4, where `_EXPLOIT`'s trailing `\\b` could never match a
token ending in punctuation and the hole was invisible to reading.

Every case below is a HAND-WRITTEN wrong answer, not model output. The model is
not involved and must not be: the point is to know the gate rejects bad prose
before any real generation is trusted.

Run:  python -m pytest tests/test_agent_impact.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.templates import IMPACT_SLOTS, assemble, skeleton  # noqa: E402
from agent.verify import verify  # noqa: E402

CONFIRMED_FACTS = {
    "finding_id": "F1",
    "verdict": "CONFIRMED",
    "rule_id": "10",
    "owasp": "SC01",
    "file": "contracts/NFT.sol",
    "line": 36,
    "line_range": "36-49",
    "contract": "NFT",
    "function": "init",
    "commit": "a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e",
    "address": "0x1111111111111111111111111111111111111111",
    "detail": "control migrated to an unguarded entry point",
    "missing_evidence": [],
}

CANDIDATE_FACTS = dict(CONFIRMED_FACTS, finding_id="F2", verdict="CANDIDATE",
                       missing_evidence=["liveness", "reachability"])


def _kinds(res):
    return {v["kind"] for v in res["violations"]}


# --------------------------------------------------------------- shape checks
def test_skeleton_uses_impact_slots_and_fixes_the_header():
    sk = skeleton(CANDIDATE_FACTS, kind="impact")
    assert sk["kind"] == "impact"
    assert sk["header_is_fixed"] is True
    assert {s["key"] for s in sk["slots"]} == {
        s["key"] for s in IMPACT_SLOTS["CANDIDATE"]}


def test_unknown_slot_keys_are_dropped_not_rendered():
    """A model cannot smuggle in a section of its own design."""
    md = assemble(CANDIDATE_FACTS, {"severity_rating": "CRITICAL 9.8"}, kind="impact")
    assert "9.8" not in md
    assert "severity_rating" not in md


def test_verdict_is_not_a_slot():
    """No slot key can rewrite the verdict; it is rendered from the record."""
    md = assemble(CANDIDATE_FACTS, {"verdict": "CONFIRMED"}, kind="impact")
    assert "NOT CONFIRMED" in md


# ------------------------------------------------- hand-written WRONG answers
@pytest.mark.parametrize("kind,slots,facts", [
    # 1. invented commit hash
    ("hash", {"what_changes": "Introduced in commit deadbeefcafe1234."}, CONFIRMED_FACTS),
    # 2. invented address
    ("address", {"what_changes": "Deployed at 0x9999999999999999999999999999999999999999."},
     CONFIRMED_FACTS),
    # 3. invented source path
    ("path", {"what_changes": "See contracts/Treasury.sol for the setter."}, CONFIRMED_FACTS),
    # 4. line outside the recorded range
    ("line", {"what_changes": "The guard was dropped at line 512."}, CONFIRMED_FACTS),
    # 5. invented qualified name
    ("name", {"who_is_exposed": "Callers of Vault.withdrawAll are affected."},
     CONFIRMED_FACTS),
    # 6. exploit material
    ("exploit", {"preconditions": "Call abi.encodeWithSelector(0x12345678) to reproduce."},
     CONFIRMED_FACTS),
])
def test_gate_rejects_invented_fact(kind, slots, facts):
    res = verify(assemble(facts, slots, kind="impact"), facts)
    assert res["ok"] is False, f"{kind}: gate accepted an invented fact"
    assert kind in _kinds(res), f"{kind}: wrong violation kind {_kinds(res)}"


@pytest.mark.parametrize("slots", [
    {"what_changes": "This is a confirmed vulnerability that allows theft."},
    {"what_is_unknown": "An attacker can drain the contract."},
    {"preconditions": "This is exploitable by any caller."},
])
def test_gate_rejects_overclaim_on_a_candidate(slots):
    """A CANDIDATE has not met the bar; assertive language must be rejected."""
    res = verify(assemble(CANDIDATE_FACTS, slots, kind="impact"), CANDIDATE_FACTS)
    assert res["ok"] is False
    assert "overclaim" in _kinds(res)


def test_gate_rejects_a_stripped_candidate_header():
    md = assemble(CANDIDATE_FACTS, {"what_changes": "A change occurred."}, kind="impact")
    tampered = md.replace("NOT CONFIRMED", "CONFIRMED")
    res = verify(tampered, CANDIDATE_FACTS)
    assert res["ok"] is False
    assert "header" in _kinds(res)


def test_gate_rejects_a_severity_section_smuggled_into_prose():
    """Slot content is prose, but markdown headings inside it are still headings."""
    res = verify(
        assemble(CANDIDATE_FACTS,
                 {"what_changes": "Background.\n\n## Severity\n\nHigh."}, kind="impact"),
        CANDIDATE_FACTS)
    assert res["ok"] is False
    assert "section" in _kinds(res)


# ------------------------------------------------------------ the clean cases
def test_clean_confirmed_narration_passes():
    res = verify(assemble(CONFIRMED_FACTS, {
        "what_changes": "Ownership can be set after deployment by any caller, where "
                        "previously it was fixed when the contract was constructed.",
        "who_is_exposed": "Anyone relying on the owner role to gate administrative "
                          "operations on this contract.",
        "preconditions": "This matters only if the affected build is the one currently "
                         "deployed; the record does not by itself establish that.",
    }, kind="impact"), CONFIRMED_FACTS)
    assert res["ok"] is True, res["violations"]


def test_clean_candidate_narration_passes():
    res = verify(assemble(CANDIDATE_FACTS, {
        "what_changes": "If this were established, it would mean the owner role could be "
                        "set after deployment rather than only at construction time.",
        "what_is_unknown": "Liveness was never determined, so nothing here shows the "
                           "affected build is deployed. Reachability was not established "
                           "either.",
        "preconditions": "Both of those would have to hold, and the record does not "
                         "establish them.",
    }, kind="impact"), CANDIDATE_FACTS)
    assert res["ok"] is True, res["violations"]
