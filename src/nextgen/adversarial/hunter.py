"""The Hunter (spec §8, "Agent A") - assembles the positive evidence chain.

The Hunter's job is to run the Phase 1-3 analyzers and set the corresponding
gates toward PASS. It is intentionally thin: it does not contain analysis logic
of its own, it orchestrates `gates.apply_*` in evidence order so that "the
Hunter ran" means the same thing every time and a reviewer has one list to
check. Like the Skeptic, it cannot declare CONFIRMED - it sets gates and
`state.classify` decides.
"""

from __future__ import annotations

from typing import Optional

from .. import gates as G
from .. import state as S


def assemble(fs: S.FindingState, *, timeline=None, buildenv_report=None,
             invariant_regressions=None, attack_paths=None,
             provenance_chain=None, deployment_facts=None,
             compensating_report=None, evidence_ref: Optional[str] = None
             ) -> S.FindingState:
    """Set every gate the supplied analyses speak to, in evidence order.
    Absent inputs leave their gates untouched (PENDING)."""
    if timeline is not None:
        G.apply_timeline(fs, timeline, evidence_ref=evidence_ref)
    if buildenv_report is not None:
        G.apply_buildenv(fs, buildenv_report, evidence_ref=evidence_ref)
    if invariant_regressions is not None:
        G.apply_invariant_regressions(fs, invariant_regressions,
                                      evidence_ref=evidence_ref)
    if attack_paths is not None:
        G.apply_attackgraph(fs, attack_paths, evidence_ref=evidence_ref)
    if compensating_report is not None:
        G.apply_compensating(fs, compensating_report, evidence_ref=evidence_ref)
    if provenance_chain is not None:
        G.apply_provenance(fs, provenance_chain, evidence_ref=evidence_ref)
    if deployment_facts is not None:
        G.apply_deployment(fs, deployment_facts, evidence_ref=evidence_ref)
    return fs
