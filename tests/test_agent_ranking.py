"""Tests for rank_findings / verify_ranking.

Two things must hold and they are tested separately:

  1. The GATE rejects bad rankings - invented ids, dropped ids, duplicates,
     malformed rank sequences, and rationales asserting facts absent from the
     record. Hand-written wrong answers, no model involved.
  2. The known-correct ORDER is derivable from the record fields alone - a
     finding that is LIVE, survives to HEAD and CONFIRMED must outrank a
     CANDIDATE on a view that no longer survives. If the fields did not carry
     that signal, no amount of prompting would fix it, so this is checked as a
     property of the DATA the tool returns.

Run:  python -m pytest tests/test_agent_ranking.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import tools  # noqa: E402


# Three synthetic findings with a KNOWN correct relative priority:
#   HIGH   live, survives, CONFIRMED, moves value
#   MID    unknown liveness, survives, CANDIDATE, state-changing
#   LOW    candidate, does not survive, a view
REPORT = {
    "coverage": {"pairs_analyzed_pct": 100.0},
    "findings": [
        {"finding_id": "HIGH", "rule_id": "10", "owasp": "SC01",
         "verdict": "CONFIRMED", "liveness": "LIVE", "survives_to_head": True,
         "contract": "Vault", "function": "init", "file": "contracts/Vault.sol",
         "line": 12, "commit": "a" * 40,
         "detail": "treasury is written by an unguarded external initializer",
         "evidence": {}},
        {"finding_id": "MID", "rule_id": "1", "owasp": "SC01",
         "verdict": "CANDIDATE", "liveness": "UNKNOWN", "survives_to_head": True,
         "contract": "Vault", "function": "setFee", "file": "contracts/Vault.sol",
         "line": 40, "commit": "b" * 40,
         "detail": "access control removed from a state-changing setter",
         "evidence": {}},
        {"finding_id": "LOW", "rule_id": "5", "owasp": "SC06",
         "verdict": "CANDIDATE", "liveness": "PATCHED", "survives_to_head": False,
         "contract": "Vault", "function": "preview", "file": "contracts/Vault.sol",
         "line": 90, "commit": "c" * 40,
         "detail": "return check removed on a view function",
         "evidence": {}},
    ],
}

IDS = json.dumps(["HIGH", "MID", "LOW"])


class _Store:
    """Minimal stand-in for FindingStore over the synthetic report."""

    def __init__(self, report):
        self.report = report
        self._by_id = {f["finding_id"]: f for f in report["findings"]}

    def ids(self):
        return list(self._by_id)

    def index(self):
        return [{k: f.get(k) for k in ("finding_id", "rule_id", "verdict")}
                for f in self.report["findings"]]

    def facts(self, fid):
        return dict(self._by_id.get(fid, {}))


@pytest.fixture(autouse=True)
def _bind():
    tools.bind(_Store(REPORT))
    yield


def _kinds(res):
    return {v["kind"] for v in res["violations"]}


# ------------------------------------------------------------- tool contract
def test_rank_findings_returns_only_record_fields():
    res = tools.rank_findings(IDS)
    assert res["status"] == "success" and res["count"] == 3
    for item in res["findings"]:
        assert set(item) <= set(tools._RANK_FIELDS)


def test_rank_findings_takes_no_verdict_argument():
    """The hard constraint, checked on the signature not by inspection of prose."""
    import inspect
    for fn in (tools.rank_findings, tools.verify_ranking):
        params = set(inspect.signature(fn).parameters)
        assert "verdict" not in params and "evidence" not in params


def test_rank_findings_rejects_an_unknown_id():
    res = tools.rank_findings(json.dumps(["HIGH", "NOPE"]))
    assert res["status"] == "error" and "NOPE" in res["error_message"]


def test_rank_findings_needs_at_least_two():
    assert tools.rank_findings(json.dumps(["HIGH"]))["status"] == "error"


# ------------------------------------------- the known-correct order is in the data
def test_priority_signal_is_present_in_the_returned_fields():
    """If the record fields did not separate HIGH from LOW, no prompt could."""
    items = {i["finding_id"]: i for i in tools.rank_findings(IDS)["findings"]}
    assert items["HIGH"]["liveness"] == "LIVE"
    assert items["LOW"]["liveness"] != "LIVE"
    assert items["HIGH"]["survives_to_head"] is True
    assert items["LOW"]["survives_to_head"] is False
    assert items["HIGH"]["verdict"] == "CONFIRMED"
    assert items["LOW"]["verdict"] == "CANDIDATE"


def test_known_correct_ordering_passes_the_gate():
    ranking = json.dumps([
        {"finding_id": "HIGH", "rank": 1,
         "rationale": "Verdict CONFIRMED with liveness LIVE, and it survives to HEAD."},
        {"finding_id": "MID", "rank": 2,
         "rationale": "Survives to HEAD but liveness is UNKNOWN, so it stays a CANDIDATE."},
        {"finding_id": "LOW", "rank": 3,
         "rationale": "Does not survive to HEAD and liveness is PATCHED."},
    ])
    res = tools.verify_ranking(IDS, ranking)
    assert res["ok"] is True, res["violations"]


# --------------------------------------------- hand-written WRONG rankings
def test_gate_rejects_an_invented_finding():
    ranking = json.dumps([
        {"finding_id": "HIGH", "rank": 1, "rationale": "Live."},
        {"finding_id": "MID", "rank": 2, "rationale": "Unknown liveness."},
        {"finding_id": "LOW", "rank": 3, "rationale": "Patched."},
        {"finding_id": "GHOST", "rank": 4, "rationale": "Invented."},
    ])
    res = tools.verify_ranking(IDS, ranking)
    assert res["ok"] is False and "invented" in _kinds(res)


def test_gate_rejects_a_dropped_finding():
    ranking = json.dumps([
        {"finding_id": "HIGH", "rank": 1, "rationale": "Live."},
        {"finding_id": "MID", "rank": 2, "rationale": "Unknown liveness."},
    ])
    res = tools.verify_ranking(IDS, ranking)
    assert res["ok"] is False and "dropped" in _kinds(res)


def test_gate_rejects_a_duplicate():
    ranking = json.dumps([
        {"finding_id": "HIGH", "rank": 1, "rationale": "Live."},
        {"finding_id": "HIGH", "rank": 2, "rationale": "Live again."},
        {"finding_id": "MID", "rank": 3, "rationale": "Unknown."},
    ])
    res = tools.verify_ranking(IDS, ranking)
    assert res["ok"] is False and {"duplicate", "dropped"} & _kinds(res)


def test_gate_rejects_a_broken_rank_sequence():
    ranking = json.dumps([
        {"finding_id": "HIGH", "rank": 1, "rationale": "Live."},
        {"finding_id": "MID", "rank": 1, "rationale": "Unknown."},
        {"finding_id": "LOW", "rank": 5, "rationale": "Patched."},
    ])
    res = tools.verify_ranking(IDS, ranking)
    assert res["ok"] is False and "rank" in _kinds(res)


@pytest.mark.parametrize("kind,rationale", [
    ("address", "Holds funds at 0x9999999999999999999999999999999999999999."),
    ("path", "The same bug appears in contracts/Treasury.sol."),
    ("hash", "Introduced by commit deadbeefcafe1234."),
    ("name", "Reachable from Router.swapExactTokens."),
    ("exploit", "Reproduce with abi.encodeWithSelector(0xdeadbeef)."),
])
def test_gate_rejects_hallucinated_rationale_facts(kind, rationale):
    ranking = json.dumps([
        {"finding_id": "HIGH", "rank": 1, "rationale": rationale},
        {"finding_id": "MID", "rank": 2, "rationale": "Unknown liveness."},
        {"finding_id": "LOW", "rank": 3, "rationale": "Patched."},
    ])
    res = tools.verify_ranking(IDS, ranking)
    assert res["ok"] is False, f"{kind}: gate accepted an invented fact"
    assert kind in _kinds(res), f"{kind}: got {_kinds(res)}"


def test_gate_rejects_tvl_speculation_as_an_invented_number():
    """Real-world stakes are not in the record and must not be asserted."""
    ranking = json.dumps([
        {"finding_id": "HIGH", "rank": 1,
         "rationale": "Protects roughly $40M of deposits at 0x1234567890123456789012345678901234567890."},
        {"finding_id": "MID", "rank": 2, "rationale": "Unknown liveness."},
        {"finding_id": "LOW", "rank": 3, "rationale": "Patched."},
    ])
    res = tools.verify_ranking(IDS, ranking)
    assert res["ok"] is False and "address" in _kinds(res)
