"""Run benchmark cases through the next-gen pipeline and tally (spec §20).

`run_offline_case` executes the parts of the pipeline that need no network:
invariant discovery + regression (§2/§3), attack-path reachability (§4),
compensating-control analysis (§11), Hunter assembly, Skeptic sweep. It is the
suite used to demonstrate hard-negative discipline. Real-repo / on-chain cases
(a `repo` + `address`) are driven by the online runner in a later phase.
"""

from __future__ import annotations

from typing import Callable, Optional

from .. import state as S
from . import model as M


def run_offline_case(case: M.BenchmarkCase) -> M.BenchmarkResult:
    """Needs slither/solc. Any compile failure is reported as an error result
    (not a silent pass)."""
    try:
        from ..adversarial import hunter as H
        from ..adversarial import skeptic as SK
        from .. import attackgraph as AG
        from .. import compensating as C
        from .._solc import slither_for_source
        from ..invariants import discover as D
        from ..invariants import regress as R
        from ..invariants import validate as VAL
    except Exception as exc:  # noqa: BLE001
        return M.BenchmarkResult(case.id, case.nature, case.expected, "ERROR",
                                 error=f"import: {type(exc).__name__}: {exc}")

    try:
        old = D.discover_from_source(case.before_source, version_ref="before")
        VAL.validate_all_from_source(old, case.before_source)
        new = D.discover_from_source(case.after_source, version_ref="after")
        VAL.validate_all_from_source(new, case.after_source)
        regs = R.diff_invariants(old, new)

        after_sl = slither_for_source(case.after_source)
        paths = AG.find_attack_paths(
            AG.build_graph(after_sl),
            target_contract=case.contract, target_function=case.function)
        comp = C.analyze(after_sl, case.contract, case.function)

        fs = S.FindingState(case.id)
        # synthetic "regression identified between the two versions" signal
        fs.set_gate("regression_commit", S.PASS if regs else S.FAIL,
                    note=("a validated invariant regressed between the two "
                          "versions" if regs else
                          "no validated invariant regressed between the two "
                          "versions"))
        H.assemble(fs, invariant_regressions=regs, attack_paths=paths,
                   compensating_report=comp)
        skept = SK.sweep(compensating_report=comp, attack_paths=paths)
        from .. import gates as G
        G.apply_skeptic(fs, skept)

        fine, verdict, _ = S.classify(fs.gates)
        mismatches = [f"{g}: want {want}, got {fs.gates.get(g)}"
                      for g, want in (case.expect_gates or {}).items()
                      if fs.gates.get(g) != want]
        return M.BenchmarkResult(case.id, case.nature, case.expected, verdict,
                                 actual_state=fine, gate_mismatches=mismatches)
    except Exception as exc:  # noqa: BLE001
        return M.BenchmarkResult(case.id, case.nature, case.expected, "ERROR",
                                 error=f"{type(exc).__name__}: {exc}")


def run_suite(cases: list[M.BenchmarkCase],
              case_runner: Optional[Callable[[M.BenchmarkCase],
                                             M.BenchmarkResult]] = None
              ) -> tuple[list[M.BenchmarkResult], M.Metrics]:
    runner = case_runner or run_offline_case
    results = [runner(c) for c in cases]
    return results, M.tally(results)
