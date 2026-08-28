"""The end-to-end next-gen pipeline (spec §26) - the integration point.

Runs the full evidence chain over one candidate and produces a classified
`FindingState`, an evidence graph, a proof-quality score, and a report:

    Security Time Machine (§1)  -> regression_commit / security_invariant
    Build environment (§19)     -> build_environment
    Invariant regression (§2/§3)-> security_invariant (corroborates)
    Attack-path graph (§4/§12)  -> reachable_path
    Compensating control (§11)  -> no_compensating_control
    Composability (§13)         -> informational
    Provenance (§9)             -> bytecode_provenance   [needs address]
    Deployment-aware (§10)      -> target_live           [needs address]
    Economics (§14)             -> economically_feasible  [needs value inputs]
    Hybrid symbolic+concrete(§6)-> state_reachable
    Sequence search + PoC(§5/15)-> reproducer / invariant_violated / state_reachable
    Skeptic sweep (§7/§8)       -> independent_validation  + FAILs any disproved gate
    ----
    state.classify              -> CONFIRMED / UNKNOWN / REJECTED

Every step is wrapped: a step that cannot run (missing input, toolchain,
network) leaves its gate PENDING/UNKNOWN and the pipeline continues. The
easiest outcome is REJECT, then UNKNOWN; CONFIRMED needs every gate.

Nothing here decides a verdict - `state.classify` does, from the gates the
`gates.apply_*` helpers set (spec §22).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import evidence_graph as EG
from . import gates as G
from . import proofscore as PS
from . import report as RPT
from . import state as S


@dataclass
class PipelineInputs:
    candidate_id: str = "cand"
    contract: str = ""
    function: str = ""
    signature: str = ""
    call_args: str = ""
    constructor_args: str = ""
    pragma: str = "^0.8.0"
    invariant_kind: str = ""
    invariant_statement: str = ""
    type_label: str = "Security Regression"
    objective: dict = field(default_factory=lambda: {"type": "call_succeeds"})

    # history / source
    repo: Optional[str] = None
    defining_path: str = ""
    head: str = "HEAD"
    before_source: str = ""
    after_source: str = ""
    source_bundle: str = ""             # self-contained flattened source

    # on-chain
    address: str = ""
    rpc_url: Optional[str] = None
    vulnerable_impl: str = ""
    local_runtime_hex: str = ""
    build_settings: dict = field(default_factory=dict)
    build_context: Any = None          # a buildenv.BuildContext, optional

    # economics
    economic_inputs: Any = None        # an economics.EconomicInputs, optional

    # misc
    setup_functions: list = field(default_factory=list)  # [(name, sig, args)]
    attacker_is_unprivileged: bool = True
    known_duplicate: Optional[bool] = None
    run_reproducer: bool = True


@dataclass
class PipelineResult:
    finding_state: S.FindingState
    evidence_graph: EG.EvidenceGraph
    proof_score: PS.ProofScore
    report_text: str
    verdict: str
    state: str
    sub_reports: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "state": self.state,
                "finding_state": self.finding_state.as_dict(),
                "proof_score": self.proof_score.as_dict(),
                "evidence_graph": self.evidence_graph.as_dict(),
                "sub_reports": {k: _sub(v) for k, v in self.sub_reports.items()}}


def _sub(v):
    return v.as_dict() if hasattr(v, "as_dict") else v


def run(inp: PipelineInputs) -> PipelineResult:
    fs = S.FindingState(inp.candidate_id)
    g = EG.EvidenceGraph()
    sub: dict = {}
    reg_commit = ""

    # --- 1. Security Time Machine (§1) --------------------------------------
    timeline = None
    try:
        if inp.repo and inp.defining_path:
            from . import timemachine as TM
            from . import timemachine_probes as TP
            probe = TP.AccessControlProbe(inp.defining_path, inp.contract,
                                          inp.function)
            timeline = TM.walk_property(inp.repo, probe, head=inp.head)
            pid = timeline.to_evidence_graph(g)
            G.apply_timeline(fs, timeline, evidence_ref=pid)
            if timeline.regression_commit:
                reg_commit = timeline.regression_commit.at_short
            sub["timeline"] = timeline
    except Exception as exc:  # noqa: BLE001
        sub["timeline_error"] = f"{type(exc).__name__}: {exc}"

    # --- 2/3. Invariant discovery + regression (§2/§3) --------------------
    regs = None
    try:
        if inp.before_source and inp.after_source:
            from .invariants import discover as D
            from .invariants import regress as R
            from .invariants import validate as VAL
            old = VAL.validate_all_from_source(
                D.discover_from_source(inp.before_source, version_ref="before"),
                inp.before_source)
            new = VAL.validate_all_from_source(
                D.discover_from_source(inp.after_source, version_ref="after"),
                inp.after_source)
            regs = R.diff_invariants(old, new)
            sub["invariant_regressions"] = [r.as_dict() for r in regs]
            if timeline is None:
                # synthetic regression signal when there is no git history
                fs.set_gate("regression_commit", S.PASS if regs else S.FAIL,
                            note=("a validated invariant regressed between the "
                                  "two versions" if regs else
                                  "no validated invariant regressed"))
            G.apply_invariant_regressions(fs, regs)
            if regs and not inp.invariant_statement:
                inp.invariant_statement = regs[0].statement
                inp.invariant_kind = regs[0].kind
                if not inp.objective or inp.objective.get("type") == "call_succeeds":
                    inp.objective = regs[0].search_target.objective
    except Exception as exc:  # noqa: BLE001
        sub["invariant_error"] = f"{type(exc).__name__}: {exc}"

    after_src = inp.after_source or inp.source_bundle

    # --- 4/12. Attack-path graph (§4/§12) --------------------------------
    attack_paths = None
    try:
        if after_src:
            from . import attackgraph as AG
            from ._solc import slither_for_source
            graph = AG.build_graph(slither_for_source(after_src))
            attack_paths = AG.find_attack_paths(
                graph, target_contract=inp.contract,
                target_function=inp.function)
            ids = AG.to_evidence_graph(attack_paths[:3], graph, g)
            G.apply_attackgraph(fs, attack_paths,
                                evidence_ref=ids[0] if ids else None)
            sub["attack_paths"] = [p.as_dict() for p in attack_paths]
    except Exception as exc:  # noqa: BLE001
        sub["attackgraph_error"] = f"{type(exc).__name__}: {exc}"

    # --- 19. Build environment ------------------------------------------
    buildenv_report = None
    try:
        from . import buildenv as BE
        ctx = inp.build_context
        if ctx is None and (inp.build_settings or inp.pragma):
            bs = inp.build_settings or {}
            ctx = BE.BuildContext(
                pragma_expr=inp.pragma,
                pinned_solc=bs.get("pinned") or bs.get("compiler"),
                analysis_solc=bs.get("compiler") or bs.get("solc"),
                deployed_solc=bs.get("deployed_solc"),
                analysis_optimizer=bs.get("optimizer"),
                analysis_runs=bs.get("runs"))
        if ctx is not None:
            buildenv_report = BE.analyze(ctx)
            G.apply_buildenv(fs, buildenv_report)
            sub["build_environment"] = buildenv_report
    except Exception as exc:  # noqa: BLE001
        sub["buildenv_error"] = f"{type(exc).__name__}: {exc}"

    # --- 11. Compensating control -------------------------------------
    compensating_report = None
    try:
        if after_src and inp.contract and inp.function:
            from . import compensating as C
            from ._solc import slither_for_source
            compensating_report = C.analyze(slither_for_source(after_src),
                                            inp.contract, inp.function)
            G.apply_compensating(fs, compensating_report)
            sub["compensating"] = compensating_report
    except Exception as exc:  # noqa: BLE001
        sub["compensating_error"] = f"{type(exc).__name__}: {exc}"

    # --- 13. Composability (informational) ---------------------------
    try:
        if after_src and inp.contract:
            from . import composability as CO
            from ._solc import slither_for_source
            sub["composability"] = CO.analyze(slither_for_source(after_src),
                                              inp.contract)
    except Exception as exc:  # noqa: BLE001
        sub["composability_error"] = f"{type(exc).__name__}: {exc}"

    # --- 9. Provenance (§9) ----------------------------------------
    provenance_chain = None
    try:
        if inp.address and inp.local_runtime_hex:
            from . import provenance as PV
            provenance_chain = PV.run(
                inp.address, inp.local_runtime_hex, commit=reg_commit or None,
                rpc_url=inp.rpc_url)
            did = provenance_chain.to_evidence_graph(g)
            G.apply_provenance(fs, provenance_chain, evidence_ref=did)
            sub["provenance"] = provenance_chain
    except Exception as exc:  # noqa: BLE001
        sub["provenance_error"] = f"{type(exc).__name__}: {exc}"

    # --- 10. Deployment-aware (§10) -------------------------------
    deployment_facts = None
    try:
        if inp.address:
            from . import deployment as DEP
            deployment_facts = DEP.run(
                inp.address, vulnerable_impl=inp.vulnerable_impl or None,
                artifact_runtime_hex=inp.local_runtime_hex or None,
                rpc_url=inp.rpc_url)
            G.apply_deployment(fs, deployment_facts)
            sub["deployment"] = deployment_facts
    except Exception as exc:  # noqa: BLE001
        sub["deployment_error"] = f"{type(exc).__name__}: {exc}"

    # --- 14. Economics (§14) ------------------------------------
    try:
        if inp.economic_inputs is not None:
            from .execground import economics as ECON
            a = ECON.assess(inp.economic_inputs)
            ECON.apply_to_gate(fs, a)
            sub["economics"] = a
    except Exception as exc:  # noqa: BLE001
        sub["economics_error"] = f"{type(exc).__name__}: {exc}"

    # --- 6. Hybrid symbolic-sketch + concrete (§6) -------------
    try:
        if inp.source_bundle and inp.contract and inp.function:
            from ._solc import slither_for_source
            from .execground import hybrid as HY
            hy = HY.run(slither_for_source(inp.source_bundle),
                        contract=inp.contract, function=inp.function,
                        signature=inp.signature, source_bundle=inp.source_bundle,
                        constructor_args=inp.constructor_args, pragma=inp.pragma)
            fs.set_gate("state_reachable", hy.gate, note=hy.rationale)
            sub["hybrid"] = hy
    except Exception as exc:  # noqa: BLE001
        sub["hybrid_error"] = f"{type(exc).__name__}: {exc}"

    # --- 5/15. Sequence search + minimal PoC (§5/§15) ----------
    repro_result = None
    try:
        if inp.run_reproducer and inp.source_bundle and inp.contract and inp.function:
            from .execground import sequences as SEQ
            minimal, repro_result = SEQ.search(
                source_bundle=inp.source_bundle, contract=inp.contract,
                function=inp.function, signature=inp.signature,
                call_args=inp.call_args, constructor_args=inp.constructor_args,
                invariant_statement=inp.invariant_statement,
                objective=inp.objective, setup_functions=inp.setup_functions,
                pragma=inp.pragma)
            G.apply_reproducer(fs, repro_result)
            if minimal is not None:
                rid = g.add_node(EG.REPRODUCER, minimal.as_report(),
                                 established_by="foundry",
                                 data={"steps": len(minimal.steps),
                                       "status": repro_result.status})
                sub["sequence"] = minimal.as_dict()
                sub["sequence_report"] = minimal.as_report()
            sub["reproducer"] = repro_result
    except Exception as exc:  # noqa: BLE001
        sub["reproducer_error"] = f"{type(exc).__name__}: {exc}"

    # --- duplicate ----------------------------------------------------
    if inp.known_duplicate is True:
        fs.set_gate("not_duplicate", S.FAIL, note="explicitly marked a duplicate")
    elif inp.known_duplicate is False:
        fs.set_gate("not_duplicate", S.PASS, note="checked, not a duplicate")

    # --- 7/8. Skeptic sweep (§7/§8) ---------------------------------
    try:
        from .adversarial import skeptic as SK
        skept = SK.sweep(
            compensating_report=compensating_report,
            deployment_facts=deployment_facts,
            provenance_chain=provenance_chain,
            buildenv_report=buildenv_report,
            attack_paths=attack_paths,
            timeline=timeline,
            corpus_duplicate=inp.known_duplicate,
            economic_infeasible=(sub.get("economics").feasible is False
                                 if sub.get("economics") is not None else None))
        G.apply_skeptic(fs, skept)
        sub["skeptic"] = skept
    except Exception as exc:  # noqa: BLE001
        sub["skeptic_error"] = f"{type(exc).__name__}: {exc}"

    # --- classify + score + report -----------------------------------
    fine, verdict, _ = S.classify(fs.gates)
    score = PS.score(PS.signals_from_gates(
        fs.gates, extra={"attacker_is_unprivileged": inp.attacker_is_unprivileged}))
    ri = RPT.ReportInputs(
        finding_id=inp.candidate_id, type_label=inp.type_label,
        contract=inp.contract, function=inp.function,
        regression_commit=reg_commit,
        security_property=inp.invariant_statement,
        invariant_kind=inp.invariant_kind,
        attacker_capability=("UNPRIVILEGED EOA" if inp.attacker_is_unprivileged
                             else "requires a privileged role"))
    report_text = RPT.render(fs, ri, evidence_graph=g)

    return PipelineResult(fs, g, score, report_text, verdict, fine, sub)
