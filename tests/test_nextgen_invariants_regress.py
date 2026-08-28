"""Phase 2 - the invariant regression engine (src/nextgen/invariants/regress.py, spec §3).

Pure. Pins: only VALIDATED old invariants can regress; REMOVED vs WEAKENED; and
that each regression carries a concrete, structured search target.

Run:  python -m pytest tests/test_nextgen_invariants_regress.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.invariants import model as M  # noqa: E402
from src.nextgen.invariants import regress as R  # noqa: E402


def _validated(**kw):
    inv = M.CandidateInvariant(**kw)
    inv.advance(M.TESTED)
    inv.advance(M.VALIDATED)
    return inv


def _ac(roles=("MINTER_ROLE",), fn="mint", iid="i-mint"):
    # roles are part of the predicate, not the subject identity
    return dict(id=iid, kind=M.ACCESS_CONTROL,
               statement=f"only {list(roles)} may call {fn}", source=M.SOURCE_ROLE,
               contract="Token", functions=(fn,),
               predicate={"roles": list(roles)})


def test_removed_access_control_invariant_produces_a_call_succeeds_target():
    old = M.InvariantSet(version_ref="v1")
    old.add(_validated(**_ac()))
    new = M.InvariantSet(version_ref="v2")   # empty - guard gone entirely

    regs = R.diff_invariants(old, new)
    assert len(regs) == 1
    reg = regs[0]
    assert reg.regression_type == R.REMOVED
    assert reg.search_target.objective["type"] == "call_succeeds"
    assert reg.search_target.objective["function"] == "mint"
    assert reg.search_target.objective["caller"] == "unprivileged"


def test_weakened_when_role_set_shrinks():
    old = M.InvariantSet()
    old.add(_validated(**_ac(roles=("MINTER_ROLE", "ADMIN_ROLE"))))
    new = M.InvariantSet()
    new.add(_validated(**_ac(roles=("ADMIN_ROLE",))))

    regs = R.diff_invariants(old, new)
    assert len(regs) == 1
    assert regs[0].regression_type == R.WEAKENED
    assert "reduced" in regs[0].note


def test_unvalidated_old_invariant_cannot_regress():
    old = M.InvariantSet()
    old.add(M.CandidateInvariant(**_ac()))     # still INFERRED
    new = M.InvariantSet()
    assert R.diff_invariants(old, new) == []


def test_new_invariant_present_but_not_usable_counts_as_removed():
    old = M.InvariantSet()
    old.add(_validated(**_ac()))
    new = M.InvariantSet()
    tested_only = M.CandidateInvariant(**_ac())
    tested_only.advance(M.TESTED)               # not VALIDATED
    new.add(tested_only)

    regs = R.diff_invariants(old, new)
    assert len(regs) == 1
    assert regs[0].regression_type == R.REMOVED
    assert "TESTED" in regs[0].note


def test_initializer_once_to_recallable_is_weakened_with_reinit_target():
    old = M.InvariantSet()
    old.add(_validated(id="i-init", kind=M.STATE_MACHINE,
                       statement="initialize once", source=M.SOURCE_INIT,
                       contract="Vault", functions=("initialize",),
                       predicate={"cardinality": "once"}))
    new = M.InvariantSet()
    new.add(_validated(id="i-init", kind=M.STATE_MACHINE,
                       statement="initialize", source=M.SOURCE_INIT,
                       contract="Vault", functions=("initialize",),
                       predicate={"cardinality": "many"}))

    regs = R.diff_invariants(old, new)
    assert regs and regs[0].regression_type == R.WEAKENED
    assert regs[0].search_target.objective["type"] == "reinit"


def test_accounting_bound_relaxed_is_weakened_with_relation_target():
    old = M.InvariantSet()
    old.add(_validated(id="i-solv", kind=M.ECONOMIC,
                       statement="assets >= liabilities", source=M.SOURCE_SOLVENCY,
                       contract="Vault", variables=("totalAssets",),
                       predicate={"bound": "totalAssets >= totalLiabilities",
                                  "relation": "totalAssets >= totalLiabilities"}))
    new = M.InvariantSet()
    new.add(_validated(id="i-solv", kind=M.ECONOMIC,
                       statement="assets tracked", source=M.SOURCE_SOLVENCY,
                       contract="Vault", variables=("totalAssets",),
                       predicate={"relation": "totalAssets >= totalLiabilities"}))

    regs = R.diff_invariants(old, new)
    assert regs and regs[0].regression_type == R.WEAKENED
    assert regs[0].search_target.objective["type"] == "state_relation_violated"


def test_no_change_no_regression():
    old = M.InvariantSet()
    new = M.InvariantSet()
    for s in (old, new):
        s.add(_validated(**_ac()))
    assert R.diff_invariants(old, new) == []


def test_regression_is_json_safe():
    import json
    old = M.InvariantSet()
    old.add(_validated(**_ac()))
    regs = R.diff_invariants(old, M.InvariantSet())
    json.dumps([r.as_dict() for r in regs])
