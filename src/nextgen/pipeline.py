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
    regression_commit: str = ""          # explicit sha (real-repo path)
    objective: dict = field(default_factory=lambda: {"type": "call_succeeds"})

    # history / source
    repo: Optional[str] = None
    defining_path: str = ""
    head: str = "HEAD"
    before_source: str = ""
    after_source: str = ""
    source_bundle: str = ""             # self-contained flattened source
    # pre-compiled Slither objects (real-repo path: dependency-resolved).
    # When set they are used instead of compiling `before_source`/`after_source`.
    before_slither: Any = None
    after_slither: Any = None

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
    # a pre-computed reproduction result (e.g. from the read-only
    # exploitability probe for a pre-0.6 pragma). When set, `run` uses it
    # directly and does not invoke Foundry.
    reproducer_result: Any = None


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
    reg_commit = inp.regression_commit or ""
    _sl: dict = {}

    def after_sl():
        if inp.after_slither is not None:
            return inp.after_slither
        if "a" not in _sl:
            src = inp.after_source or inp.source_bundle
            if src:
                from ._solc import slither_for_source
                _sl["a"] = slither_for_source(src)
            else:
                _sl["a"] = None
        return _sl["a"]

    def before_sl():
        if inp.before_slither is not None:
            return inp.before_slither
        if "b" not in _sl:
            if inp.before_source:
                from ._solc import slither_for_source
                _sl["b"] = slither_for_source(inp.before_source)
            else:
                _sl["b"] = None
        return _sl["b"]

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
            if timeline.regression_commit and not reg_commit:
                reg_commit = timeline.regression_commit.at_commit
            sub["timeline"] = timeline
    except Exception as exc:  # noqa: BLE001
        sub["timeline_error"] = f"{type(exc).__name__}: {exc}"

    # --- 2/3. Invariant discovery + regression (§2/§3) --------------------
    regs = None
    try:
        bsl, asl = before_sl(), after_sl()
        if bsl is not None and asl is not None:
            from .invariants import discover as D
            from .invariants import regress as R
            from .invariants import validate as VAL
            old = VAL.validate_all(
                D.discover_from_slither(bsl, version_ref="before"), bsl)
            new = VAL.validate_all(
                D.discover_from_slither(asl, version_ref="after"), asl)
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
                # prefer the regression that concerns the TARGET function, then
                # one whose search target names it, else the first.
                on_target = next((r for r in regs if inp.function in r.functions),
                                 None) \
                    or next((r for r in regs
                             if inp.function == r.search_target.objective.get("function")),
                            None)
                pick = on_target or regs[0]
                inp.invariant_kind = pick.kind
                if on_target is not None:
                    inp.invariant_statement = pick.statement
                else:
                    # control-migration shape (spec §10 rule): the target is a
                    # NEW unguarded entry that reaches state a one-shot path
                    # established. Name it, and cite the contradicted invariant.
                    inp.invariant_statement = (
                        f"{inp.contract}.{inp.function}() is an unguarded entry "
                        f"point reaching one-shot-established state; it "
                        f"contradicts: {pick.statement}")
                if not inp.objective or inp.objective.get("type") == "call_succeeds":
                    inp.objective = pick.search_target.objective
    except Exception as exc:  # noqa: BLE001
        sub["invariant_error"] = f"{type(exc).__name__}: {exc}"

    # --- 4/12. Attack-path graph (§4/§12) --------------------------------
    attack_paths = None
    try:
        sl = after_sl()
        if sl is not None:
            from . import attackgraph as AG
            graph = AG.build_graph(sl)
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
        sl = after_sl()
        if sl is not None and inp.contract and inp.function:
            from . import compensating as C
            compensating_report = C.analyze(sl, inp.contract, inp.function)
            G.apply_compensating(fs, compensating_report)
            sub["compensating"] = compensating_report
    except Exception as exc:  # noqa: BLE001
        sub["compensating_error"] = f"{type(exc).__name__}: {exc}"

    # --- 13. Composability (informational) ---------------------------
    try:
        sl = after_sl()
        if sl is not None and inp.contract:
            from . import composability as CO
            sub["composability"] = CO.analyze(sl, inp.contract)
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

    # A candidate already disproved on reachability or regression is not worth
    # spending execution cycles on - the verdict is settled.
    _settled_reject = (fs.gates.get("reachable_path") == S.FAIL
                       or fs.gates.get("regression_commit") == S.FAIL
                       or fs.gates.get("no_compensating_control") == S.FAIL)

    # --- 6. Hybrid symbolic-sketch + concrete (§6) -------------
    try:
        sl = after_sl()
        if sl is not None and inp.contract and inp.function \
                and inp.reproducer_result is None and not _settled_reject:
            from .execground import hybrid as HY
            hy = HY.run(sl, contract=inp.contract, function=inp.function,
                        signature=inp.signature,
                        source_bundle=inp.source_bundle or "",
                        constructor_args=inp.constructor_args, pragma=inp.pragma)
            fs.set_gate("state_reachable", hy.gate, note=hy.rationale)
            sub["hybrid"] = hy
    except Exception as exc:  # noqa: BLE001
        sub["hybrid_error"] = f"{type(exc).__name__}: {exc}"

    # --- 5/15. Sequence search + minimal PoC (§5/§15) ----------
    repro_result = None
    try:
        if inp.reproducer_result is not None:
            repro_result = inp.reproducer_result
            G.apply_reproducer(fs, repro_result)
            sub["reproducer"] = repro_result
        elif _settled_reject:
            sub["reproducer_skipped"] = ("candidate already disproved on "
                                         "reachability / regression - no "
                                         "reproduction attempted")
        elif inp.run_reproducer and inp.source_bundle and inp.contract and inp.function:
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

    # --- build environment rides on a byte-identical on-chain match ----
    # A normalized-bytecode MATCH is the strongest possible proof the analysis
    # build environment is the deployed one; promote an UNKNOWN (never a FAIL).
    if fs.gates.get("bytecode_provenance") == S.PASS \
            and fs.gates.get("build_environment") in (S.GATE_UNKNOWN, S.PENDING):
        fs.set_gate("build_environment", S.PASS,
                    note="the deployed bytecode is byte-identical to this build "
                         "- the build environment is proven correct")

    # --- duplicate ----------------------------------------------------
    if inp.known_duplicate is True:
        fs.set_gate("not_duplicate", S.FAIL, note="explicitly marked a duplicate")
    elif inp.known_duplicate is False:
        fs.set_gate("not_duplicate", S.PASS, note="checked, not a duplicate")
    else:
        try:
            from src import corpus as CORP
            avail = CORP.available()
            if not avail.get("available"):
                fs.set_gate("not_duplicate", S.PASS,
                            note="no findings corpus configured - deduplication "
                                 "not applicable (corpus degrades, never blocks)")
            else:
                hits = CORP.query_findings(
                    rule_id=inp.type_label[:2] if inp.type_label[:1].isdigit() else None,
                    repo=inp.repo or "", limit=200)
                match = any(h.get("commit") == reg_commit
                            and h.get("contract") == inp.contract
                            and h.get("function") == inp.function
                            and h.get("verdict") == "CONFIRMED" for h in hits)
                fs.set_gate("not_duplicate", S.FAIL if match else S.PASS,
                            note=("an identical CONFIRMED finding is already in "
                                  "the corpus" if match else
                                  f"checked {len(hits)} corpus finding(s) for "
                                  f"this repo - none identical"))
        except Exception as exc:  # noqa: BLE001
            sub["dedupe_error"] = f"{type(exc).__name__}: {exc}"

    # --- economic feasibility: only a GATING question for value classes --
    if fs.gates.get("economically_feasible") == S.PENDING:
        vk = (inp.invariant_kind or "").upper()
        if not vk.startswith(("ACCOUNTING", "ECONOMIC")):
            fs.set_gate("economically_feasible", S.SKIPPED,
                        note="not a value-extraction finding - economic "
                             "feasibility is not a gating question here")

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


# --------------------------------------------------------------------------- #
# real-repo entry (spec Tier 1) - dependency-aware, git-history-backed
# --------------------------------------------------------------------------- #

_RULE_TYPE_LABEL = {
    "1": "Access Control Security Regression",
    "3a": "Upgrade Authorization Security Regression",
    "3b": "Initializer Security Regression",
    "10": "Control Migrated to an Unguarded Entry Point",
}


def run_from_repo(*, repo: str, parent: str, commit: str, file: str,
                  contract: str, function: str, signature: str = "",
                  rule_id: str = "", address: str = "",
                  rpc_url: Optional[str] = None, vulnerable_impl: str = "",
                  candidate_id: str = "", type_label: str = "",
                  keep_context: bool = False) -> PipelineResult:
    """Run the full pipeline on a real (parent -> commit) pair of a real repo.

    Reconstructs each side's dependency environment via `nextgen.repo.RepoContext`
    (the classic engine's own machinery), compiles both with imports resolved,
    flattens the target for the reproducer, pulls deployed build settings +
    on-chain bytecode when an address is given, and - for a pre-0.6 pragma -
    uses the read-only exploitability probe instead of a Foundry reproducer.
    """
    from .repo import RepoContext
    from .execground.reproducer import _solc_floor

    rc = RepoContext(repo)
    notes: dict = {}
    before_sl = after_sl = None
    try:
        try:
            before_sl = rc.compiled(parent, file)
        except Exception as exc:  # noqa: BLE001
            notes["before_compile"] = f"{type(exc).__name__}: {exc}"[:300]
        try:
            after_sl = rc.compiled(commit, file)
        except Exception as exc:  # noqa: BLE001
            notes["after_compile"] = f"{type(exc).__name__}: {exc}"[:300]

        after_src = rc.source_at(commit, file) or ""
        before_src = rc.source_at(parent, file) or ""
        pragma = _pragma_of_text(after_src) or "^0.8.0"
        floor = _solc_floor(pragma, after_src)

        # derive the ABI signature from the real compilation if not supplied
        if not signature and after_sl is not None:
            try:
                for c in getattr(after_sl, "contracts_derived", after_sl.contracts):
                    if c.name != contract:
                        continue
                    for fn in c.functions:
                        if fn.name == function and fn.visibility in ("external", "public"):
                            signature = fn.full_name   # e.g. init(address,string,string)
                            break
            except Exception:  # noqa: BLE001
                pass

        # deployed build settings (Sourcify) + local runtime bytecode (§9/§19)
        build_settings: dict = {}
        local_runtime_hex = ""
        if address:
            evm_version = None
            try:
                from src import verified as VER
                vs = VER.settings_for(address)
                # verified.settings_for keys: compiler_version / optimize /
                # optimize_runs / evm_version (a tri-state `optimize`).
                comp = (vs.get("compiler_version") or "")
                build_settings = {
                    "compiler": comp or None,
                    "deployed_solc": comp or None,
                    "optimizer": vs.get("optimize"),
                    "runs": vs.get("optimize_runs"),
                    "evm": vs.get("evm_version"),
                }
                evm_version = vs.get("evm_version")
                notes["verified"] = (f"sourcify: solc {comp or '?'}, "
                                     f"optimize={vs.get('optimize')}, "
                                     f"runs={vs.get('optimize_runs')}, "
                                     f"evm={vs.get('evm_version')}, "
                                     f"found={vs.get('found')}")
            except Exception as exc:  # noqa: BLE001
                notes["verified"] = f"{type(exc).__name__}: {exc}"[:200]
            try:
                from src.scan import _runtime_bytecode
                info = rc.checkout(commit)
                local_runtime_hex = _runtime_bytecode(
                    info.path, file, contract,
                    optimize=build_settings.get("optimizer"),
                    optimize_runs=build_settings.get("runs"),
                    evm_version=evm_version,
                    compiler_version=build_settings.get("compiler")) or ""
                notes["runtime_bytecode"] = (
                    f"{len(local_runtime_hex)} hex chars"
                    if local_runtime_hex else "solc produced no runtime bytecode")
            except Exception as exc:  # noqa: BLE001
                notes["runtime_bytecode"] = f"{type(exc).__name__}: {exc}"[:200]

        # reproducer selection:
        #   pre-0.6 pragma + live address -> read-only exploit probe (§14 style)
        #   pre-0.6 pragma, no address    -> not reproducible offline (PENDING)
        #   modern pragma                 -> Foundry reproducer on a flat bundle
        pre_06 = floor is not None and floor < (0, 6, 2)
        reproducer_result = None
        run_forge_repro = True
        if pre_06 and address and rpc_url:
            reproducer_result = _exploit_probe_repro(
                address, rpc_url, rule_id or "10", contract, function, signature)
            notes["reproducer_method"] = "read-only eth_call (pre-0.6 pragma)"
            run_forge_repro = False
        elif pre_06:
            run_forge_repro = False
            notes["reproducer_method"] = (
                "not attempted: pragma < 0.6.2 (Foundry incompatible) and no "
                "--address/--rpc-url for the read-only probe")

        source_bundle = ""
        if run_forge_repro:
            source_bundle = rc.flatten(commit, file) or after_src

        bctx = rc.build_context(
            commit, target_file=file,
            deployed_solc=build_settings.get("deployed_solc"),
            deployed_optimizer=build_settings.get("optimizer"),
            deployed_runs=build_settings.get("runs"))

        inp = PipelineInputs(
            candidate_id=candidate_id or f"{contract}.{function}@{commit[:8]}",
            contract=contract, function=function, signature=signature,
            type_label=type_label or _RULE_TYPE_LABEL.get(rule_id, "Security Regression"),
            regression_commit=commit, pragma=pragma,
            before_source=before_src, after_source=after_src,
            before_slither=before_sl, after_slither=after_sl,
            source_bundle=source_bundle,
            build_context=bctx,
            address=address, rpc_url=rpc_url, vulnerable_impl=vulnerable_impl,
            local_runtime_hex=local_runtime_hex,
            reproducer_result=reproducer_result,
            run_reproducer=run_forge_repro,
        )
        res = run(inp)
        res.sub_reports.setdefault("repo_notes", {}).update(notes)
        if not res.finding_state.gates.get("regression_commit") == S.PASS \
                and "reg_commit" in notes:
            pass
        return res
    finally:
        if not keep_context:
            rc.close()


def _pragma_of_text(text: str) -> Optional[str]:
    import re
    m = re.search(r"pragma\s+solidity\s+([^;]+);", text or "")
    return m.group(1).strip() if m else None


def _exploit_probe_repro(address: str, rpc_url: str, rule_id: str,
                         contract: str, function: str, signature: str):
    """Use src/exploit_proof.py (read-only eth_call vs deployed bytecode) as the
    reproduction for a pre-0.6 pragma. OPEN -> REPRODUCED, CLOSED -> NOT."""
    from .adversarial.reproducer import ReproResult, REPRODUCED, NOT_REPRODUCED, PENDING
    try:
        from src import exploit_proof as XP
        from src import exposure as XE      # OPEN / CLOSED / UNKNOWN live here
        from src import liveness as L
        w3 = L._w3(rpc_url)
        pr = XP.prove(w3, {"rule_id": rule_id, "contract": contract,
                           "function": function, "signature": signature,
                           "address": address, "verdict": "CONFIRMED",
                           "liveness": "LIVE"})
        if pr.status == XE.OPEN:
            return ReproResult(REPRODUCED,
                               "read-only eth_call from an unprivileged address: "
                               f"{contract}.{function} does not revert against the "
                               "deployed bytecode (src/exploit_proof.py)",
                               artifacts={"method": "eth_call", "status": pr.status,
                                          "reason": pr.reason})
        if pr.status == XE.CLOSED:
            return ReproResult(NOT_REPRODUCED,
                               "the regressed function reverts for an unprivileged "
                               "caller against the deployed bytecode: " + pr.reason)
        return ReproResult(PENDING, f"exploitability probe: {pr.status} - {pr.reason}")
    except Exception as exc:  # noqa: BLE001
        return ReproResult(PENDING, f"exploit probe unavailable: {type(exc).__name__}: {exc}")
