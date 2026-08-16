"""Agent tool-layer contract tests. No model, no network.

The hallucination gate is treated exactly like a false positive: zero
tolerance, and proven by construction rather than by trusting a model to
behave. These tests feed `verify_report` drafts that are deliberately wrong and
assert it catches each one - because a gate that has never rejected anything is
not known to work.

Run:  python -m pytest tests/test_agent_tools.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import FindingStore, assemble, header_for, skeleton, verify  # noqa: E402
from agent import tools  # noqa: E402

REPORT = ROOT / "reports-input" / "demo-vault.json"

pytestmark = pytest.mark.skipif(
    not REPORT.is_file(), reason="reports-input/demo-vault.json not present")


@pytest.fixture(scope="module")
def store():
    return FindingStore.from_path(REPORT)


@pytest.fixture(scope="module")
def facts(store):
    return store.facts(store.ids()[0])


# ------------------------------------------------------- architectural boundary


def test_agent_never_imports_a_rule():
    """AGENT-DESIGN.md property 1: the agent layer cannot reach the engine's
    decision code. Checked on the real import graph, not by inspection."""
    import agent, agent.store, agent.templates, agent.tools, agent.verify  # noqa: F401

    offenders = [name for name in sys.modules
                 if name.startswith("src.rules")]
    assert not offenders, (
        f"agent layer pulled in engine rule modules: {offenders}")


def test_no_tool_can_change_a_verdict(store):
    """Every tool is a reader. None accepts a verdict argument or writes one."""
    import inspect

    for fn in tools.ALL_TOOLS:
        params = set(inspect.signature(fn).parameters)
        assert "verdict" not in params, f"{fn.__name__} takes a verdict"
        assert "evidence" not in params, f"{fn.__name__} takes evidence"


# --------------------------------------------------------------- the templates


def test_candidate_header_is_fixed_and_lists_missing_evidence(facts):
    assert facts["verdict"] == "CANDIDATE"
    h = header_for(facts)
    assert h.startswith("NOT CONFIRMED - missing evidence: ")
    for missing in facts["missing_evidence"]:
        assert missing in h


def test_candidate_skeleton_has_no_severity_or_impact_slot(facts):
    """RULES.md amended rule: there is nowhere to put an overclaim."""
    keys = {s["key"] for s in skeleton(facts)["slots"]}
    assert "impact" not in keys
    assert "severity" not in keys
    assert "why_not_confirmed" in keys


def test_model_cannot_override_the_header(facts):
    """The model writing its own header changes nothing: assemble renders the
    header from the verdict and drops unknown slots."""
    md = assemble(facts, {
        "summary": "A control was removed.",
        "header": "# CONFIRMED CRITICAL VULNERABILITY",      # unknown slot
        "impact": "Funds can be drained.",                    # not a CANDIDATE slot
    })
    assert md.startswith(f"# {header_for(facts)}")
    assert "CONFIRMED CRITICAL VULNERABILITY" not in md
    assert "Funds can be drained" not in md


# ------------------------------------------------------- the hallucination gate


def test_clean_report_passes(facts):
    md = assemble(facts, {
        "summary": "The guard that existed at the parent commit is absent at the "
                   "regression commit.",
        "mechanism": "The diff removes the modifier from the function.",
        "why_not_confirmed": "One required evidence field was not established.",
        "what_would_settle_it": "An on-chain liveness check against a deployed address.",
    })
    res = verify(md, facts)
    assert res["ok"], res["violations"]


@pytest.mark.parametrize("bad,kind", [
    ("The regression was introduced in commit deadbeefcafe1234.", "hash"),
    ("Deployed at 0x1234567890abcdef1234567890abcdef12345678.", "address"),
    ("See contracts/Totally/Invented.sol for the change.", "path"),
    ("The guard was removed at line 9999.", "line"),
    ("The bug is in Treasury.drainEverything.", "name"),
])
def test_invented_facts_are_caught(facts, bad, kind):
    md = assemble(facts, {"summary": bad})
    res = verify(md, facts)
    assert not res["ok"], f"{kind} hallucination slipped through"
    assert any(v["kind"] == kind for v in res["violations"]), res["violations"]


@pytest.mark.parametrize("phrase", [
    "This is a confirmed vulnerability.",
    "An attacker can drain the contract.",
    "The function is exploitable by any caller.",
])
def test_candidate_overclaim_is_caught(facts, phrase):
    md = assemble(facts, {"summary": phrase})
    res = verify(md, facts)
    assert not res["ok"]
    assert any(v["kind"] == "overclaim" for v in res["violations"]), res["violations"]


def test_stripped_header_is_caught(facts):
    md = assemble(facts, {"summary": "ok"}).replace(header_for(facts), "Security Report")
    res = verify(md, facts)
    assert not res["ok"]
    assert any(v["kind"] == "header" for v in res["violations"])


def test_exploit_material_is_caught(facts):
    md = assemble(facts, {"summary": "Use abi.encodeWithSelector( to build the call."})
    res = verify(md, facts)
    assert not res["ok"]
    assert any(v["kind"] == "exploit" for v in res["violations"])


# ---------------------------------------------------------------- save refuses


def test_save_refuses_an_unverifiable_report(store, tmp_path):
    tools.bind(store, out_dir=tmp_path)
    fid = store.ids()[0]
    res = tools.save_report(fid, json.dumps({"summary": "Introduced in commit feedfacefeed."}))
    assert res["status"] == "error"
    assert "verification failed" in res["error_message"]
    assert not list(tmp_path.glob("*.md")), "a refused report must not be written"


def test_save_writes_a_verified_report(store, tmp_path):
    tools.bind(store, out_dir=tmp_path)
    fid = store.ids()[0]
    res = tools.save_report(fid, json.dumps({
        "summary": "The control present at the parent commit is absent afterwards.",
        "mechanism": "The diff shows the modifier removed from the declaration.",
        "why_not_confirmed": "A required evidence field was not established.",
        "what_would_settle_it": "A liveness check against a deployed address.",
    }))
    assert res["status"] == "success", res
    written = Path(res["path"]).read_text(encoding="utf-8")
    assert written.startswith("# NOT CONFIRMED - missing evidence:")


# ------------------------------------------------------------------- the tools


def test_list_findings_carries_no_prose(store):
    tools.bind(store)
    res = tools.list_findings()
    assert res["status"] == "success" and res["count"] >= 1
    for row in res["findings"]:
        assert "detail" not in row and "evidence" not in row


def test_get_finding_unknown_id_errors_not_raises(store):
    tools.bind(store)
    res = tools.get_finding("nope")
    assert res["status"] == "error" and "error_message" in res


def test_verify_report_takes_slots_and_assembles(store):
    """Measured against a real model (2c): the agent cannot hand back the final
    markdown, because assembly happens inside the tool. verify_report therefore
    takes the same slot map save_report takes and assembles it itself."""
    tools.bind(store)
    fid = store.ids()[0]
    good = tools.verify_report(fid, json.dumps({"summary": "A control was removed."}))
    assert good["ok"], good
    bad = tools.verify_report(fid, json.dumps({"summary": "Introduced in commit feedfacefeed."}))
    assert not bad["ok"] and any(v["kind"] == "hash" for v in bad["violations"])


def test_slot_map_accepted_as_dict_or_json_string(store, tmp_path):
    """The declared type is str, but the runtime passes a dict when the model
    emits a JSON object - the first real save_report call failed on exactly
    this. Accepting both changes no check."""
    tools.bind(store, out_dir=tmp_path)
    fid = store.ids()[0]
    slots = {"summary": "A control was removed.", "mechanism": "The diff shows it."}
    assert tools.verify_report(fid, slots)["ok"]
    assert tools.save_report(fid, slots)["status"] == "success"


def test_python_literal_slot_map_is_tolerated(store):
    """Measured in 2c: the model emitted a Python-literal mapping on 3 of 5
    verify calls. literal_eval parses literals only and cannot execute code;
    the result still goes through assemble and the same gate."""
    tools.bind(store)
    fid = store.ids()[0]
    res = tools.verify_report(fid, "{'summary': 'A control was removed.'}")
    assert res.get("ok") is True, res


def test_malformed_slot_map_still_refused(store):
    tools.bind(store)
    res = tools.verify_report(store.ids()[0], "not a mapping at all {{{")
    assert res["status"] == "error" and "JSON" in res["error_message"]


# ------------------------------------------------------------- rate limiting


def test_rate_limiter_paces_to_the_budget():
    """The free tier allows 15 model requests/minute and one finding costs
    several, so pacing is part of the product, not the test harness. Proven on
    a compressed window rather than by waiting a real minute."""
    import asyncio
    from agent.runner import RateLimiter

    async def go():
        lim = RateLimiter(max_requests=3, window=0.6)
        waits = [await lim.acquire() for _ in range(7)]
        return waits

    waits = asyncio.run(go())
    assert waits[:3] == [0.0, 0.0, 0.0], "first burst must not be delayed"
    assert any(w > 0 for w in waits[3:]), "budget exhaustion must introduce a wait"


def test_retry_delay_uses_the_servers_number():
    """A 429 carries the delay the server wants; guessing our own is worse."""
    from agent.runner import _retry_delay_from, _is_rate_limited

    exc = RuntimeError("429 RESOURCE_EXHAUSTED ... {'retryDelay': '10s'} ...")
    assert _is_rate_limited(exc)
    assert 10.0 < _retry_delay_from(exc) <= 12.0
    assert _retry_delay_from(RuntimeError("boom"), default=7.0) == 7.0
