"""Unit tests for the verdict classifier (src/verdict.py).

Fast - no compilation, no git. These pin the rules that decide whether a
finding is allowed to be called CONFIRMED, because that decision is the entire
false-positive defence and it must not drift silently.

Run:  python -m pytest tests/test_verdict.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import verdict as V  # noqa: E402

FULL_COMMIT = {"hash": "abc123def456", "author": "dev", "date": "2026-01-01T00:00:00Z",
               "line_range": "40-52", "parent": "0000aaaa"}

RECORD = {
    "rule_id": "1",
    "severity": V.CONFIRMED,
    "contract": "Vault",
    "function": "withdraw",
    "signature": "withdraw(uint256)",
    "file": "contracts/Vault.sol",
    "line": 44,
    "detail": "Vault.withdraw(uint256) lost its msg.sender constraint",
    "evidence": {
        "owasp": "SC01",
        "constrained_before": True,
        "constrained_after": False,
        "visibility_after": "external",
        "writes_state_after": True,
    },
}


def _build(**kw):
    args = {"commit": FULL_COMMIT, "survives_to_head": True, "liveness": V.LIVE}
    args.update(kw)
    return V.build(dict(RECORD), **args)


def test_all_six_present_and_live_is_confirmed():
    f = _build()
    assert f.verdict == V.CONFIRMED, f.downgrade_reasons
    assert not f.evidence.missing()


def test_no_address_means_no_confirmed():
    """The consequence people are surprised by: liveness is one of the six, so
    a repo-only scan cannot produce a CONFIRMED finding."""
    f = _build(liveness=None)
    assert f.verdict == V.CANDIDATE
    assert any("liveness" in r for r in f.downgrade_reasons)


def test_patched_on_chain_is_not_confirmed():
    f = _build(liveness=V.PATCHED)
    assert f.verdict == V.CANDIDATE
    assert any("PATCHED" in r for r in f.downgrade_reasons)


def test_regression_repaired_before_head_is_not_confirmed():
    """RULES.md: reachable at HEAD, not just at commit N. History is worth
    reporting; it is not a live exposure."""
    f = _build(survives_to_head=False)
    assert f.verdict == V.CANDIDATE
    assert any("HEAD" in r for r in f.downgrade_reasons)
    assert f.evidence.reachability is None


def test_undetermined_head_survival_is_not_proof():
    f = _build(survives_to_head=None)
    assert f.verdict == V.CANDIDATE


def test_internal_function_is_not_reachability_proof():
    rec = dict(RECORD)
    rec["evidence"] = {**RECORD["evidence"], "visibility_after": "internal"}
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert f.evidence.reachability is None


def test_read_only_function_is_not_reachability_proof():
    rec = dict(RECORD)
    rec["evidence"] = {**RECORD["evidence"], "writes_state_after": False}
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE


def test_rule_candidate_ceiling_is_never_raised():
    """RULES.md caps read-only reentrancy (2.10) and best-effort notification
    hooks (5.3) at CANDIDATE. Complete evidence must not promote them."""
    rec = dict(RECORD)
    rec["severity"] = V.CANDIDATE
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert any("caps this trigger class" in r for r in f.downgrade_reasons)


def test_missing_line_range_breaks_evidence_field_one():
    f = _build(commit={k: v for k, v in FULL_COMMIT.items() if k != "line_range"})
    assert f.verdict == V.CANDIDATE
    assert f.evidence.regression_commit is None


def test_unknown_rule_id_cannot_reach_confirmed():
    """A rule with no registered pre/post keys or exclusion set has not proved
    what the model requires, so it caps at CANDIDATE by construction."""
    rec = dict(RECORD)
    rec["rule_id"] = "99"
    f = V.build(rec, commit=FULL_COMMIT, survives_to_head=True, liveness=V.LIVE)
    assert f.verdict == V.CANDIDATE
    assert f.evidence.pre_state is None
    assert f.evidence.no_compensating_control is None


def test_every_shipped_rule_has_pre_post_and_exclusions():
    """Guards against adding a rule to the engine and forgetting the model."""
    from src.scan import RULE_ORDER

    for rid in RULE_ORDER:
        assert rid in V.PRE_POST, f"rule {rid} has no pre/post evidence mapping"
        assert rid in V.EXCLUSIONS_EVALUATED, f"rule {rid} has no exclusion record"
