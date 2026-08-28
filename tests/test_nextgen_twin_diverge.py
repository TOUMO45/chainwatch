"""Counterfactual Twin - Phase 4 version divergence (src/nextgen/twin/diverge.py).

Run:  python -m pytest tests/test_nextgen_twin_diverge.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.twin import diverge as D, model as M  # noqa: E402


def _fp(n_success=0, n_revert=0, callers_success=None, callers_revert=None,
        transfers_in=0, transfers_out=0, external_targets=None
        ) -> M.FunctionFingerprint:
    fp = M.FunctionFingerprint(address="0xdead", selector="0x1")
    fp.n_total = n_success + n_revert
    fp.n_success, fp.n_revert = n_success, n_revert
    fp.callers_success = set(callers_success or [])
    fp.callers_revert = set(callers_revert or [])
    fp.transfers_in, fp.transfers_out = transfers_in, transfers_out
    fp.external_call_targets = set(external_targets or [])
    return fp


def test_reject_to_accept_flip_detected():
    old = {"0x1": _fp(n_revert=3, callers_revert=["0xattacker"])}
    new = {"0x1": _fp(n_success=3, callers_success=["0xattacker"])}
    out = D._accept_reject_flips(old, new, "old", "new")
    assert len(out) == 1
    assert out[0].kind == M.REJECT_TO_ACCEPT


def test_accept_to_reject_flip_detected():
    old = {"0x1": _fp(n_success=3)}
    new = {"0x1": _fp(n_revert=3)}
    out = D._accept_reject_flips(old, new, "old", "new")
    assert out[0].kind == M.ACCEPT_TO_REJECT


def test_no_flip_when_selector_only_exists_on_one_side():
    old = {"0x1": _fp(n_success=3)}
    new = {"0x2": _fp(n_success=3)}
    assert D._accept_reject_flips(old, new, "o", "n") == []


def test_no_flip_when_behaviour_unchanged():
    old = {"0x1": _fp(n_success=3)}
    new = {"0x1": _fp(n_success=5)}
    assert D._accept_reject_flips(old, new, "o", "n") == []


def test_asset_flow_divergence_when_shape_changes():
    old = {"0x1": _fp(n_success=3, transfers_out=3)}
    new = {"0x1": _fp(n_success=3, transfers_in=3, transfers_out=3)}
    out = D._asset_flow_divergence(old, new, "o", "n")
    assert len(out) == 1 and out[0].kind == M.ASSET_FLOW_DIVERGENCE


def test_external_call_divergence_on_added_target():
    old = {"0x1": _fp(n_success=1, external_targets={("0xa", "0xsel")})}
    new = {"0x1": _fp(n_success=1, external_targets={("0xa", "0xsel"), ("0xb", "0xsel2")})}
    out = D._external_call_divergence(old, new, "o", "n")
    assert len(out) == 1
    assert out[0].detail["added"] == ["0xb"]


def test_boundary_missing_on_new_side_is_invariant_weakening():
    old_b = [M.Boundary(kind=M.CONSERVATION, statement="balances", selector="0x1",
                        status=M.TESTED)]
    out = D._boundary_divergence(old_b, [], "o", "n")
    assert len(out) == 1 and out[0].kind == M.INVARIANT_WEAKENING


def test_authorization_caller_widening_flagged():
    old_b = [M.Boundary(kind=M.AUTHORIZATION, statement="x", selector="0x1",
                        status=M.TESTED, detail={"callers": ["0xowner"]})]
    new_b = [M.Boundary(kind=M.AUTHORIZATION, statement="x", selector="0x1",
                        status=M.TESTED,
                        detail={"callers": ["0xowner", "0xattacker"]})]
    out = D._boundary_divergence(old_b, new_b, "o", "n")
    assert len(out) == 1 and out[0].kind == M.AUTHORIZATION_DIVERGENCE
    assert out[0].detail["added"] == ["0xattacker"]


def test_authorization_caller_narrowing_not_flagged_as_widening():
    old_b = [M.Boundary(kind=M.AUTHORIZATION, statement="x", selector="0x1",
                        status=M.TESTED,
                        detail={"callers": ["0xowner", "0xattacker"]})]
    new_b = [M.Boundary(kind=M.AUTHORIZATION, statement="x", selector="0x1",
                        status=M.TESTED, detail={"callers": ["0xowner"]})]
    assert D._boundary_divergence(old_b, new_b, "o", "n") == []


def test_compare_versions_aggregates_all_sub_checks():
    old_fp = {"0x1": _fp(n_revert=3, callers_revert=["0xa"])}
    new_fp = {"0x1": _fp(n_success=3, callers_success=["0xa"])}
    out = D.compare_versions(old_fp, new_fp, [], [], old_ref="v1", new_ref="v2")
    assert any(d.kind == M.REJECT_TO_ACCEPT for d in out)
    for d in out:
        assert d.old_ref == "v1" and d.new_ref == "v2"


def test_summarize_handles_empty_and_nonempty():
    assert "none found" in D.summarize([])
    d = M.Divergence(kind=M.ACCEPT_TO_REJECT, selector="0x1", statement="x")
    assert "ACCEPTED_NOW_REJECTED" in D.summarize([d])
