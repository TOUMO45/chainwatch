"""Phase 2 - invariant model + status discipline (src/nextgen/invariants/model.py).

Pure. Pins that only VALIDATED/USED invariants are `usable`, and that the
status machine is one-step-forward with a terminal REJECTED.

Run:  python -m pytest tests/test_nextgen_invariants_model.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.invariants import model as M  # noqa: E402


def _inv(**kw):
    base = dict(id="i1", kind=M.ACCESS_CONTROL, statement="only owner",
                source=M.SOURCE_GUARD, contract="Vault", functions=("withdraw",))
    base.update(kw)
    return M.CandidateInvariant(**base)


def test_new_invariant_is_inferred_and_not_usable():
    inv = _inv()
    assert inv.status == M.INFERRED
    assert inv.usable is False


def test_forward_one_step_only():
    inv = _inv()
    inv.advance(M.TESTED)
    inv.advance(M.VALIDATED)
    assert inv.usable is True
    with pytest.raises(M.InvariantStatusError):
        inv.advance(M.INFERRED)          # backward


def test_cannot_skip_a_status():
    inv = _inv()
    with pytest.raises(M.InvariantStatusError):
        inv.advance(M.VALIDATED)         # skipped TESTED


def test_reject_is_terminal():
    inv = _inv()
    inv.reject("did not re-verify")
    assert inv.status == M.REJECTED
    assert inv.contradiction == "did not re-verify"
    with pytest.raises(M.InvariantStatusError):
        inv.advance(M.TESTED)


def test_used_is_the_last_forward_step():
    inv = _inv()
    for s in (M.TESTED, M.VALIDATED, M.USED):
        inv.advance(s)
    assert inv.status == M.USED
    assert inv.usable is True


def test_bad_kind_and_bad_status_rejected_at_construction():
    with pytest.raises(ValueError):
        _inv(kind="MADE_UP")
    with pytest.raises(ValueError):
        _inv(status="HALF_SURE")


def test_subject_key_is_phrasing_independent():
    a = _inv(statement="only owner may withdraw",
             predicate={"guards": ["modifier:onlyOwner"]})
    b = _inv(statement="withdraw is restricted to the owner",
             predicate={"guards": ["inline:msg.sender"]})
    assert a.subject_key == b.subject_key


def test_invariant_set_views():
    s = M.InvariantSet(version_ref="HEAD")
    a = _inv(id="a")
    a.advance(M.TESTED)
    a.advance(M.VALIDATED)
    b = _inv(id="b", kind=M.STATE_MACHINE, source=M.SOURCE_INIT,
             functions=("initialize",))
    s.add(a)
    s.add(b)
    assert s.usable() == [a]
    assert s.by_kind(M.STATE_MACHINE) == [b]
    assert a.subject_key in s.index_by_subject()
