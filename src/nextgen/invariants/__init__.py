"""Automatic security invariant discovery + regression (spec §2, §3).

    discover.py   infer CANDIDATE invariants from source structure (modifiers,
                  guards, roles, init state, upgrade auth, accounting shapes,
                  require/assert conditions, NatSpec "must/only/never" lines).
    validate.py   the INFERRED -> TESTED -> VALIDATED discipline. An inferred
                  invariant is a lead, not a security property, until it is
                  re-checked against the code and found un-contradicted.
    regress.py    diff two versions' VALIDATED invariant sets and produce the
                  concrete state an exploit would have to reach.
    model.py      the pure data types and status state machine shared by all
                  three.

Nothing here declares a verdict. A validated invariant regression feeds the
`security_invariant` gate in `state.py`; observing the violation (the
`invariant_violated` gate) needs execution and is a later phase.
"""

from __future__ import annotations
