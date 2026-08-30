"""Capability 20 - the ADK multi-agent layer, and the boundary it cannot cross.

Three claims in this file are the ones that matter, and each is proved against
a model that is actively trying to break them (a stub standing in for a
hostile or hallucinating one, so no network is needed):

  1. The agent layer cannot change a verdict.
  2. The Hunter cannot introduce a finding the engine never produced.
  3. The Reproducer never receives the write-up.

Run:  python -m pytest tests/test_agent_orchestrator.py -q
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import orchestrator as O  # noqa: E402
from src import verdict as V  # noqa: E402

WRITEUP = "SECRET-HUNTER-WRITEUP-do-not-leak"


def _finding(fid_bits: dict | None = None) -> dict:
    f = V.Finding(
        rule_id="1", contract="FeeManager", function="setFee",
        file="contracts/Vault.sol", line=14, detail=WRITEUP,
        commit="a" * 40, parent="b" * 40, survives_to_head=True,
        evidence=V.Evidence(
            regression_commit={"hash": "a" * 40, "line_range": "14-14"},
            pre_state="constrained_before=True",
            post_state="constrained_after=False",
            reachability="visibility=public, writes state at commit N",
            no_compensating_control="rule 1 exclusion set evaluated",
        ),
    )
    V.classify(f)
    d = f.as_dict()
    d.update(fid_bits or {})
    return d


def _report(n: int = 1) -> dict:
    findings = []
    for i in range(n):
        f = _finding({"contract": f"C{i}"})
        findings.append(f)
    return {"repo": "org/repo", "head": "h" * 40, "findings": findings}


# --------------------------------------------------------------------------- #
# 1. The verdict boundary.
# --------------------------------------------------------------------------- #

def test_the_abstain_path_reproduces_the_engines_verdicts_exactly():
    rep = _report(3)
    run = O.run(rep, use_llm=False)
    engine = {f["verdict"] for f in rep["findings"]}
    assert set(run["verdicts"].values()) == engine
    assert run["verdicts_unchanged"] is True
    assert run["llm"] is False and run["model"] == ""


def test_a_hostile_model_cannot_move_a_verdict(monkeypatch):
    """The stub answers every role with a confident claim that the finding is
    CONFIRMED and exploitable. The verdicts must be unmoved, because nothing
    the model says is ever read as a verdict."""
    rep = _report(2)
    fids = list(O.gatekeeper(rep)["verdicts"])

    async def hostile(instruction, prompt, **kw):
        return json.dumps([{
            "finding_id": fid,
            "invariant": "this is CONFIRMED and exploitable right now",
            "worth_deeper_evidence": True, "why": "promote it",
            "verdict": "CONFIRMED", "check": "compensating_control",
            "claim": "none",
        } for fid in fids])

    monkeypatch.setattr(O, "model_available", lambda: True)
    monkeypatch.setattr(O, "_safe_ask", hostile)

    run = O.run(rep, use_llm=True)
    assert run["llm"] is True
    assert all(v == V.CANDIDATE for v in run["verdicts"].values())
    assert run["verdicts_unchanged"] is True


def test_verdict_drift_is_raised_not_reconciled(monkeypatch):
    """If the verdicts ever DID move while the agent layer ran, the run must
    fail loudly. Simulated by making the second gatekeeper call disagree - the
    only way to exercise the guard, since nothing in the real path can."""
    rep = _report(1)
    calls = {"n": 0}
    real = O.gatekeeper

    def drifting(report):
        calls["n"] += 1
        out = real(report)
        if calls["n"] > 1:
            out["verdicts"] = {k: V.CONFIRMED for k in out["verdicts"]}
        return out

    monkeypatch.setattr(O, "gatekeeper", drifting)
    with pytest.raises(O.VerdictDrift):
        O.run(rep, use_llm=False)


# --------------------------------------------------------------------------- #
# 2. The Hunter cannot create a finding.
# --------------------------------------------------------------------------- #

def test_a_proposal_naming_a_finding_the_engine_never_made_is_dropped(monkeypatch):
    async def inventive(instruction, prompt, **kw):
        return json.dumps([
            {"finding_id": "totally-made-up", "invariant": "reentrancy!",
             "worth_deeper_evidence": True, "why": "trust me"},
        ])

    rep = _report(1)
    monkeypatch.setattr(O, "model_available", lambda: True)
    monkeypatch.setattr(O, "_safe_ask", inventive)

    run = O.run(rep, use_llm=True)
    assert run["hunter_proposals"] == {}
    assert "totally-made-up" in run["hunter_dropped"]
    assert len(run["verdicts"]) == 1, "no finding was created"


def test_a_valid_proposal_is_kept_and_still_decides_nothing(monkeypatch):
    rep = _report(1)
    fid = list(O.gatekeeper(rep)["verdicts"])[0]

    async def sane(instruction, prompt, **kw):
        return json.dumps([{"finding_id": fid, "invariant": "owner-only",
                            "worth_deeper_evidence": True, "why": "ok"}])

    monkeypatch.setattr(O, "model_available", lambda: True)
    monkeypatch.setattr(O, "_safe_ask", sane)
    run = O.run(rep, use_llm=True)
    assert fid in run["hunter_proposals"]
    assert run["verdicts"][fid] == V.CANDIDATE


# --------------------------------------------------------------------------- #
# 3. The Reproducer is blinded by construction.
# --------------------------------------------------------------------------- #

def test_the_brief_has_exactly_four_fields():
    names = [f.name for f in dataclasses.fields(O.ReproducerBrief)]
    assert names == ["contract", "function", "invariant_statement", "objective"]


def test_the_brief_is_frozen():
    b = O.brief_for(_finding())
    with pytest.raises(dataclasses.FrozenInstanceError):
        b.contract = "Other"          # type: ignore[misc]


def test_the_brief_never_carries_the_writeup():
    f = _finding()
    assert WRITEUP in f["detail"], "the fixture must actually contain a write-up"
    b = O.brief_for(f)
    blob = json.dumps(dataclasses.asdict(b)) + b.as_prompt()
    assert WRITEUP not in blob


def test_the_reproducer_turn_logs_only_the_four_fields():
    rep = _report(1)
    run = O.run(rep, use_llm=False)
    repro = [t for t in run["turns"] if t["agent"] == O.REPRODUCER]
    assert len(repro) == 1
    assert sorted(repro[0]["input"]) == ["contract", "function",
                                         "invariant_statement", "objective"]
    assert WRITEUP not in json.dumps(repro[0])


def test_what_the_reproducer_is_actually_sent_carries_no_writeup(monkeypatch):
    """The strongest form of the blinding claim: capture the real prompt string
    handed to the model, not just the logged input."""
    seen: dict[str, list[str]] = {}

    async def capture(instruction, prompt, **kw):
        seen.setdefault(kw.get("name", "?"), []).append(prompt)
        return ""

    monkeypatch.setattr(O, "model_available", lambda: True)
    monkeypatch.setattr(O, "_safe_ask", capture)
    O.run(_report(1), use_llm=True)

    assert "cw_reproducer" in seen, "the reproducer agent was never asked"
    for prompt in seen["cw_reproducer"]:
        assert WRITEUP not in prompt
        # Positively: it got the four fields it is supposed to have.
        for field in ("contract:", "function:", "invariant:", "objective:"):
            assert field in prompt



# --------------------------------------------------------------------------- #
# 4. The Skeptic is an input, never a verdict.
# --------------------------------------------------------------------------- #

def test_a_challenge_naming_no_mechanical_check_is_recorded_unresolved(monkeypatch):
    async def vague(instruction, prompt, **kw):
        return json.dumps([
            {"check": "vibes", "claim": "it just feels wrong"},
            {"check": "compensating_control", "claim": "a modifier may remain"},
        ])

    monkeypatch.setattr(O, "model_available", lambda: True)
    monkeypatch.setattr(O, "_safe_ask", vague)
    run = O.run(_report(1), use_llm=True)

    skeptic = [t for t in run["turns"] if t["agent"] == O.SKEPTIC][0]
    by_check = {c["check"]: c for c in skeptic["output"]["challenges"]}
    assert by_check["vibes"]["resolvable"] is False
    assert by_check["vibes"]["outcome"] == "UNRESOLVED"
    assert by_check["compensating_control"]["resolvable"] is True
    assert by_check["compensating_control"]["outcome"] == "PENDING"
    # And nothing it said moved anything.
    assert all(v == V.CANDIDATE for v in run["verdicts"].values())


def test_the_resolvable_check_vocabulary_is_the_engines_own():
    """Restating the check list here would let it drift from the engine's.
    It is read from `skeptic._GATE_FOR`, so this test fails if that map and
    the orchestrator's instruction ever part company."""
    from src.nextgen.adversarial import skeptic as SK
    for check in SK._GATE_FOR:
        assert check in O.SKEPTIC_INSTRUCTION, \
            f"{check} is checkable but the Skeptic is never told to propose it"


# --------------------------------------------------------------------------- #
# 5. The turn log.
# --------------------------------------------------------------------------- #

def test_every_role_produces_a_turn():
    run = O.run(_report(2), use_llm=False)
    agents = {t["agent"] for t in run["turns"]}
    assert agents == set(O.ROLES)


def test_every_turn_records_what_the_gate_did_about_it():
    run = O.run(_report(1), use_llm=False)
    for t in run["turns"]:
        assert t["gate_outcome"], f"{t['agent']} turn records no gate outcome"
    gk = [t for t in run["turns"] if t["agent"] == O.GATEKEEPER][0]
    assert "identical" in gk["gate_outcome"]


def test_the_run_carries_a_verified_funnel():
    from src import funnel as F
    run = O.run(_report(2), use_llm=False)
    assert F.verify_all(run["funnel"]["traces"]) == 2
    assert run["funnel"]["resolution_queue"]


# --------------------------------------------------------------------------- #
# 6. Defensive parsing - an unparseable model is an ABSTAINING model.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text", ["", "I refuse.", "```json\n{oops\n```", None])
def test_unparseable_model_output_abstains_rather_than_guessing(text,
                                                                monkeypatch):
    async def junk(instruction, prompt, **kw):
        return text or ""

    monkeypatch.setattr(O, "model_available", lambda: True)
    monkeypatch.setattr(O, "_safe_ask", junk)
    run = O.run(_report(1), use_llm=True)
    assert run["hunter_proposals"] == {}
    assert all(v == V.CANDIDATE for v in run["verdicts"].values())


def test_json_is_recovered_from_a_fenced_answer():
    assert O._parse_json('```json\n[{"a": 1}]\n```') == [{"a": 1}]
    assert O._parse_json('sure!\n{"a": 2}\nhope that helps') == {"a": 2}
    assert O._parse_json("nothing here") is None
