"""Phase 10 - the Deep Hunt orchestrator (spec section 18) + coverage (section 28).

Wires every phase in evidence order over ONE deployed protocol:

    ProtocolModel (3) -> deep invariants (4/5) -> behaviour priors (6) ->
    ranked targets + planned sequences (9/21) -> counterfactual mutations (10) ->
    blinded reproduction on a local fork (11/15/16/17) -> asset flow + economics
    (13/14) -> Skeptic (16) -> classify_live -> DeepFinding (26/27)

Every step is wrapped: a missing input / toolchain / RPC leaves its gate
PENDING/UNKNOWN and the hunt continues. Nothing here decides - `classify_live`
does, from the gates the phase adapters set. The easiest outcome is REJECTED,
then UNKNOWN; CONFIRMED needs a deterministic, independently reproduced
invariant violation AND (for a live finding) the vulnerable implementation
proven deployed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Union

from .. import evidence_graph as EG
from .. import proofscore as PS
from .. import state as S
from ..adversarial import reproducer as RP
from . import assetflow as AF
from . import behavior as BH
from . import counterfactual as CF
from . import execadapter as EA
from . import findings as F
from . import invariants as INV
from . import protocolmodel as PM
from . import skeptic as DHS
from . import stateexplorer as SE

_CHAIN_NAMES = {1: "Ethereum", 56: "BNB Smart Chain", 8453: "Base",
                137: "Polygon", 42161: "Arbitrum One", 10: "Optimism",
                43114: "Avalanche"}


@dataclass
class HuntInputs:
    source: Union[str, dict, Any]          # verified Solidity (str / {path:content} / dir)
    target_contract: str = ""
    chain_id: int = 0
    block_number: Optional[int] = None
    address: str = ""
    rpc_url: Optional[str] = None
    behaviour_blocks: Optional[tuple[int, int]] = None
    budget_findings: int = 8
    budget_sequences: int = 16
    budget_mutations: int = 40
    use_llm: bool = False
    fork: bool = False                     # attempt execution grounding
    eth_price_usd: float = 3000.0


@dataclass
class DeepHuntResult:
    verdict: str
    model: PM.ProtocolModel
    invariants: list = field(default_factory=list)
    findings: list = field(default_factory=list)          # DeepFinding
    coverage: dict = field(default_factory=dict)
    evidence_graph: Optional[EG.EvidenceGraph] = None
    report_text: str = ""
    sub: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"verdict": self.verdict,
                "model": self.model.as_dict() if self.model else None,
                "n_invariants": len(self.invariants),
                "findings": [f.as_dict() for f in self.findings],
                "coverage": self.coverage,
                "evidence_graph": (self.evidence_graph.as_dict()
                                   if self.evidence_graph else None),
                "sub": {k: (v.as_dict() if hasattr(v, "as_dict") else v)
                        for k, v in self.sub.items()}}


def run(inp: HuntInputs) -> DeepHuntResult:
    g = EG.EvidenceGraph()
    sub: dict = {}
    cov = _fresh_coverage()

    # --- 1. ProtocolModel (section 3) -----------------------------------------
    model = PM.build_from_sources(inp.source, target=inp.target_contract)
    if not model.compiled:
        return DeepHuntResult(
            verdict=S.VERDICT_UNKNOWN, model=model, coverage=cov,
            evidence_graph=g,
            report_text=f"DEEP HUNT: the target did not compile - "
                        f"{model.reason}\n(UNMEASURED, not SAFE)")
    cov.update(model.coverage())
    tgt = model.target()
    tgt_name = tgt.name if tgt else inp.target_contract
    slither_obj = None
    try:
        slither_obj = PM.compile_source(inp.source, target=inp.target_contract)
    except Exception as exc:  # noqa: BLE001
        sub["slither_error"] = f"{type(exc).__name__}: {exc}"[:200]

    # --- 2. deep invariants (sections 4/5) --------------------------------------
    invs = INV.discover(model, use_llm=inp.use_llm)
    INV.validate(model, invs)
    cov["invariants_discovered"] = len(invs)
    cov["invariants_validated"] = sum(1 for i in invs if i.usable)
    cov["invariants_tested"] = sum(
        1 for i in invs if i.status in (INV.IM.TESTED, INV.IM.VALIDATED))
    sub["invariants"] = [i.as_dict() for i in invs]

    # --- 3. behaviour priors (section 6) - optional, RPC-gated ----------------
    learned = BH.LearnedBehavior(address=inp.address or "", available=False,
                                 reason="no address/RPC")
    signals: list = []
    if inp.address and inp.rpc_url and inp.behaviour_blocks:
        lo, hi = inp.behaviour_blocks
        learned = BH.learn(inp.address, inp.rpc_url, from_block=lo, to_block=hi)
        signals = BH.contrast(model, invs, learned)
    bumps = BH.priority_bumps(signals)
    cov["historical_tx_analyzed"] = learned.n_txs
    cov["historical_reverts"] = learned.n_revert
    sub["behaviour"] = learned.as_dict()
    sub["behaviour_signals"] = [s.as_dict() for s in signals]

    # --- 4. ranked targets + planned sequences (sections 9/21) --------------
    targets = SE.rank_targets(model, invs)
    for t in targets:
        fm = model.function(t.contract, t.function)
        if fm and fm.selector in bumps:
            t.priority += bumps[fm.selector]
    targets.sort(key=lambda t: (-t.priority, t.contract, t.function))
    seqs = SE.plan_sequences(model, invs, budget=inp.budget_sequences,
                             use_llm=inp.use_llm)
    cov["functions_explored"] = len({t.function for t in targets})
    cov["sequences_planned"] = len(seqs)

    # --- 5. counterfactual mutations (section 10) --------------------------
    muts = CF.mutate_all(seqs, model, invs, budget=inp.budget_mutations)
    cov["counterfactual_mutations"] = len(muts)

    # --- 6. execution grounding (sections 11/12) - optional ----------------
    source_bundle = inp.source if isinstance(inp.source, str) else ""
    from ..execground import foundry as _F
    toolchain = _F.resolve()
    cov["toolchain"] = toolchain.kind if toolchain else "none"
    fork_ctx = None
    if inp.fork and inp.address and inp.rpc_url:
        fork_ctx = EA.open_fork(inp.chain_id, inp.block_number or 0, inp.address,
                                inp.rpc_url)
        if not fork_ctx.start():
            sub["fork_error"] = fork_ctx.reason
            fork_ctx = None
        else:
            cov["fork_blocks_tested"] = 1

    # --- 7. per-candidate evaluation --------------------------------------
    ranked_invs = _rank_invariants(invs, targets)
    seqs_by_stmt: dict[str, list] = {}
    for s in seqs:
        seqs_by_stmt.setdefault(s.invariant_statement, []).append(s)

    findings: list[F.DeepFinding] = []
    for inv in ranked_invs[:inp.budget_findings]:
        cand_seqs = seqs_by_stmt.get(inv.statement) or seqs[:1]
        cand_muts = [m for m in muts
                     if m.sequence.invariant_statement == inv.statement][:3]
        fnd = _evaluate(inv, cand_seqs, cand_muts, model, slither_obj,
                        source_bundle, toolchain, fork_ctx, inp, g, cov, sub)
        findings.append(fnd)

    if fork_ctx is not None:
        fork_ctx.stop()

    cov["candidates_generated"] = len(findings)
    cov["candidates_rejected"] = sum(1 for f in findings
                                     if f.confidence == F.REJECTED)
    cov["candidates_reproduced"] = sum(
        1 for f in findings if f.gates.get("reproducer") == S.PASS)
    cov["confirmed_findings"] = sum(1 for f in findings
                                    if f.confidence == F.CONFIRMED)

    verdict = _overall_verdict(findings)
    report = _render(inp, model, invs, findings, cov, g, tgt_name)
    return DeepHuntResult(verdict=verdict, model=model, invariants=invs,
                          findings=findings, coverage=cov, evidence_graph=g,
                          report_text=report, sub=sub)


# --------------------------------------------------------------------------- #
# per-candidate evaluation
# --------------------------------------------------------------------------- #

def _evaluate(inv, cand_seqs, cand_muts, model, slither_obj, source_bundle,
              toolchain, fork_ctx, inp, g, cov, sub) -> F.DeepFinding:
    ftype = F.finding_type_for(inv)
    fid = f"DH-{inv.id[5:]}" if inv.id.startswith("dinv-") else f"DH-{inv.id}"
    fs = S.FindingState(fid)
    recipe = (inv.predicate or {}).get("test_recipe", {}) or {}
    fn = inv.functions[0] if inv.functions else recipe.get("function", "")
    lines: list[F.Line] = []

    # -- security_invariant: VALIDATED -> PASS; else a hypothesis ---------
    if inv.usable:
        fs.set_gate("security_invariant", S.PASS,
                    note=f"{inv.source}: {inv.statement}")
        lines.append(F.fact(f"invariant VALIDATED: {inv.statement}"))
    else:
        fs.set_gate("security_invariant", S.GATE_UNKNOWN,
                    note=f"{inv.source} invariant is only {inv.status} - a "
                         f"hypothesis, needs an execution observation")
        lines.append(F.inference(
            f"candidate invariant ({inv.status}): {inv.statement}"))

    # -- reachable_path: the model is the authority on the direct entry
    #    point's caller-identity guard; the attack-graph adds indirect paths --
    _apply_reachability(fs, model, slither_obj, inv.contract, fn, lines, sub, g)

    # -- no_compensating_control -------------------------------------------
    #    `nextgen.compensating` answers "a guard was removed - is there an
    #    equivalent reachable one?", which is meaningful only for the
    #    authorization / state-machine invariants. For a conservation /
    #    entitlement / oracle invariant, "is there a compensating control"
    #    is exactly what a successful end-to-end reproduction answers, so it
    #    is resolved after the reproduction step below.
    if inv.source in (INV.SRC_AUTH_REACH, INV.SRC_STATE_MACHINE) \
            and slither_obj is not None and inv.contract and fn:
        try:
            from .. import compensating as C
            rep = C.analyze(slither_obj, inv.contract, fn)
            fs.set_gate("no_compensating_control",
                        getattr(rep, "gate", S.GATE_UNKNOWN),
                        note=getattr(rep, "rationale", ""))
            sub.setdefault("compensating", {})[fid] = \
                getattr(rep, "as_dict", lambda: {})()
        except Exception as exc:  # noqa: BLE001
            fs.set_gate("no_compensating_control", S.GATE_UNKNOWN,
                        note=f"compensating check errored: {type(exc).__name__}")
    else:
        fs.set_gate("no_compensating_control", S.GATE_UNKNOWN,
                    note="resolved by the reproduction (a demonstrated violation "
                         "excludes a compensating control)")

    # -- reproduction (blinded) -----------------------------------------
    minimal_seq = None
    repro = RP.ReproResult(RP.PENDING, "not attempted")
    if toolchain is not None and source_bundle and cand_seqs:
        best = cand_seqs[0]
        # try the plain sequence, then the highest-weight mutation
        attempts = [best] + [m.sequence for m in cand_muts]
        from . import reproduce as REP
        fm = model.function(inv.contract, fn)
        bt = RP.BlindTarget(
            contract=inv.contract, function=fn,
            invariant_statement=inv.statement, objective=recipe,
            address=inp.address, signature=fm.signature if fm else f"{fn}()",
            call_args=(best.steps[-1].args if best.steps else ""),
            pragma=_pragma(source_bundle))
        for seq in attempts:
            m2, repro = REP.reproduce(bt, seq, source_bundle=source_bundle,
                                      toolchain=toolchain)
            cov["mutations_executed"] = cov.get("mutations_executed", 0) + 1
            if repro.status == RP.REPRODUCED:
                minimal_seq = m2 or seq
                break
    _apply_repro(fs, repro, lines)

    # a demonstrated end-to-end violation grounds the invariant (execution is
    # the validator the relationship invariants were waiting for) AND excludes
    # a compensating control (nothing stopped it).
    if fs.gates.get("reproducer") == S.PASS:
        if not inv.usable:
            INV._advance_to(inv, INV.IM.VALIDATED,
                            "violation reproduced on a local fork")
        fs.set_gate("security_invariant", S.PASS,
                    note=f"{inv.source}: {inv.statement} - grounded by the "
                         f"local-fork reproduction")
        if fs.gates.get("no_compensating_control") in (S.GATE_UNKNOWN, S.PENDING):
            fs.set_gate("no_compensating_control", S.PASS,
                        note="the reproduction ran end to end - no control "
                             "prevented the violation")

    # -- asset flow + economics (only when a fork replayed it) ----------
    flow = None
    if fork_ctx is not None and fork_ctx.available and minimal_seq is not None:
        # raw calls would need calldata encoding - out of v1 scope; record intent
        sub.setdefault("assetflow_note", "fork replay of the minimised sequence "
                       "for balance deltas is Phase 11 (calldata encoding)")
    if ftype not in (F.ACCOUNTING, F.ECONOMIC):
        fs.set_gate("economically_feasible", S.SKIPPED,
                    note="not a value-extraction finding - economic feasibility "
                         "is not a gating question here")
    elif flow is not None:
        a = AF.assess(flow, {AF.ETH: inp.eth_price_usd})
        fs.set_gate("economically_feasible", a.gate, note=a.rationale)
        sub.setdefault("economics", {})[fid] = a.as_dict()
    elif fs.gates.get("reproducer") == S.PASS:
        fs.set_gate("economically_feasible", S.SKIPPED,
                    note="the violation was reproduced (real protocol loss); "
                         "USD impact not quantified without a fork replay")
    else:
        fs.set_gate("economically_feasible", S.GATE_UNKNOWN,
                    note="value finding with no measured asset flow")

    # -- provenance / deployment (address + rpc) ----------------------
    _apply_deployment(fs, inp, lines, sub, fid)

    # -- duplicate: no deep-hunt corpus -> degrade to PASS ---------
    fs.set_gate("not_duplicate", S.PASS,
                note="no deep-hunt findings corpus configured - deduplication "
                     "not applicable (degrades, never blocks)")

    # -- Skeptic (base + deep-hunt) -----------------------------------
    skept = DHS.sweep(
        base=_skeptic_base(sub, fid),
        model=model, invariant=inv,
        sequence=minimal_seq or (cand_seqs[0] if cand_seqs else None),
        asset_flow=flow)
    DHS.apply(fs, skept)
    sub.setdefault("skeptic", {})[fid] = skept.as_dict()

    # -- classify (live profile) -----------------------------------
    state, verdict, reasons = F.classify_live(fs.gates)
    conf = F.confidence_for(verdict, fs.gates)
    sev = F.severity_for(conf, ftype)

    fnd = F.DeepFinding(
        finding_id=fid, finding_type=ftype,
        title=_title(inv, ftype),
        confidence=conf, severity=sev,
        target=inp.address or inv.contract,
        chain=_CHAIN_NAMES.get(inp.chain_id, str(inp.chain_id) if inp.chain_id else ""),
        block=inp.block_number, contract=inv.contract,
        implementation=sub.get("deployment", {}).get(fid, {}).get("implementation", ""),
        function=fn,
        security_property=inv.statement,
        why_it_should_hold=(inv.predicate or {}).get("rationale", ""),
        how_discovered=f"deep invariant discovery ({inv.source}); "
                       f"{'reproduced on a local fork' if fs.gates.get('reproducer') == S.PASS else 'not reproduced'}",
        min_sequence=[s.as_text() for s in minimal_seq.steps] if minimal_seq else
        ([s.as_text() for s in cand_seqs[0].steps] if cand_seqs else []),
        execution_proof=(repro.detail if repro.status == RP.REPRODUCED else ""),
        bytecode_provenance=sub.get("deployment", {}).get(fid, {}).get("rationale", ""),
        independent_reproduction=("agrees" if fs.gates.get("independent_validation") == S.PASS
                                  else "not established"),
        lines=lines, gates=dict(fs.gates), reasons=reasons)
    return fnd


# --------------------------------------------------------------------------- #
# adapters
# --------------------------------------------------------------------------- #

def _apply_reachability(fs, model, slither_obj, contract, fn, lines, sub, g):
    """The MODEL is the authority on whether the direct entry point restricts
    the caller's identity (`access_controlled`, the SHARP signal - a
    `require(ok)` after `msg.sender.call` is not access control). The
    attack-graph only adds an INDIRECT unprivileged path when the direct one is
    guarded."""
    fm = model.function(contract, fn)
    if fm is not None and fm.external and not fm.access_controlled:
        fs.set_gate("reachable_path", S.PASS,
                    note=f"{contract}.{fn}() is external with no caller-identity "
                         f"guard - directly callable by an unprivileged EOA")
        lines.append(F.fact(
            f"{contract}.{fn}() is externally callable by any address "
            f"(no role / owner check)"))
        return

    if slither_obj is not None and contract and fn:
        try:
            from .. import attackgraph as AG
            graph = AG.build_graph(slither_obj)
            paths = AG.find_attack_paths(graph, target_contract=contract,
                                         target_function=fn,
                                         require_sensitive=False)
            unpriv = [p for p in paths if getattr(p, "unprivileged", False)]
            if unpriv:
                fs.set_gate("reachable_path", S.PASS,
                            note=f"{len(unpriv)} indirect unprivileged path(s) "
                                 f"to {contract}.{fn}")
                lines.append(F.inference(
                    f"an indirect unprivileged path reaches {contract}.{fn}()"))
                return
        except Exception as exc:  # noqa: BLE001
            sub["attackgraph_error"] = f"{type(exc).__name__}: {exc}"[:200]

    if fm is None:
        fs.set_gate("reachable_path", S.GATE_UNKNOWN, note="target fn not modelled")
    elif fm.access_controlled:
        fs.set_gate("reachable_path", S.FAIL,
                    note=f"{contract}.{fn}() restricts the caller's identity and "
                         f"no indirect unprivileged path was found")
    elif not fm.external:
        fs.set_gate("reachable_path", S.GATE_UNKNOWN,
                    note=f"{contract}.{fn} is internal - needs an external reacher")
    else:
        fs.set_gate("reachable_path", S.GATE_UNKNOWN, note="reachability undetermined")


def _apply_repro(fs, repro, lines):
    if repro.status == RP.REPRODUCED:
        fs.set_gate("reproducer", S.PASS, note=repro.detail)
        fs.set_gate("invariant_violated", S.PASS,
                    note="observed during the local-fork reproduction")
        fs.set_gate("state_reachable", S.PASS,
                    note="the required state was constructed in the reproducer")
        lines.append(F.fact("the invariant violation was reproduced on a local "
                            "fork (forge test [PASS])"))
    elif repro.status == RP.NOT_REPRODUCED:
        fs.set_gate("reproducer", S.FAIL, note=repro.detail)
        lines.append(F.fact("the invariant held under every attempted sequence "
                            "(forge test [FAIL])"))
    else:
        fs.set_gate("reproducer", S.PENDING, note=repro.detail)
        lines.append(F.assumption("reproduction not attempted: " + repro.detail))


def _apply_deployment(fs, inp, lines, sub, fid):
    if not (inp.address and inp.rpc_url):
        fs.set_gate("bytecode_provenance", S.GATE_UNKNOWN,
                    note="no address/RPC - deployment not verified (source-only)")
        fs.set_gate("target_live", S.GATE_UNKNOWN,
                    note="no address/RPC - liveness not verified")
        lines.append(F.assumption(
            "analysis is source-only: the deployed bytecode is assumed to "
            "correspond to this source, not proven"))
        return
    try:
        from .. import deployment as DEP
        facts = DEP.run(inp.address, rpc_url=inp.rpc_url)
        fs.set_gate("target_live", getattr(facts, "gate", S.GATE_UNKNOWN),
                    note=getattr(facts, "rationale", ""))
        sub.setdefault("deployment", {})[fid] = getattr(facts, "as_dict", lambda: {})()
        fs.set_gate("bytecode_provenance", S.GATE_UNKNOWN,
                    note="no local build artifact to match against on-chain "
                         "bytecode (needs a compiled + settings-matched build)")
    except Exception as exc:  # noqa: BLE001
        fs.set_gate("target_live", S.GATE_UNKNOWN,
                    note=f"deployment check errored: {type(exc).__name__}")
        fs.set_gate("bytecode_provenance", S.GATE_UNKNOWN, note="not established")


def _skeptic_base(sub: dict, fid: str) -> dict:
    base: dict = {}
    comp = sub.get("compensating", {}).get(fid)
    if comp:
        base["compensating_report"] = _Wrap(comp)
    dep = sub.get("deployment", {}).get(fid)
    if dep:
        base["deployment_facts"] = _Wrap(dep)
    return base


class _Wrap:
    """Adapt a sub-report dict back to the .gate / .rationale attribute shape
    the base Skeptic expects."""

    def __init__(self, d: dict) -> None:
        self.gate = d.get("gate")
        self.rationale = d.get("rationale", "")


# --------------------------------------------------------------------------- #
# ranking / rendering
# --------------------------------------------------------------------------- #

def _rank_invariants(invs: list, targets: list) -> list:
    prio: dict[str, int] = {}
    for t in targets:
        prio[t.invariant_id] = max(prio.get(t.invariant_id, 0), t.priority)
    strength_rank = {"strong": 3, "medium": 2, "weak": 1}
    return sorted(
        invs,
        key=lambda i: (-prio.get(i.id, 0),
                       -strength_rank.get(i.strength, 0),
                       0 if i.usable else 1, i.source, i.statement))


def _title(inv, ftype: str) -> str:
    fn = inv.functions[0] if inv.functions else "?"
    return f"{ftype.replace('_', ' ').title()}: {inv.contract}.{fn} may violate "\
           f"'{inv.statement[:80]}'"


def _overall_verdict(findings: list) -> str:
    if any(f.confidence == F.CONFIRMED for f in findings):
        return S.VERDICT_CONFIRMED
    if all(f.confidence == F.REJECTED for f in findings) and findings:
        return S.VERDICT_REJECTED
    return S.VERDICT_UNKNOWN


def _pragma(text: str) -> str:
    import re
    m = re.search(r"pragma\s+solidity\s+([^;]+);", text or "")
    return m.group(1).strip() if m else "^0.8.0"


def _fresh_coverage() -> dict:
    return {
        "contracts_modeled": 0, "functions_modeled": 0, "functions_explored": 0,
        "invariants_discovered": 0, "invariants_tested": 0,
        "invariants_validated": 0, "historical_tx_analyzed": 0,
        "historical_reverts": 0, "sequences_planned": 0,
        "counterfactual_mutations": 0, "mutations_executed": 0,
        "fork_blocks_tested": 0, "candidates_generated": 0,
        "candidates_rejected": 0, "candidates_reproduced": 0,
        "confirmed_findings": 0, "toolchain": "none",
    }


def _render(inp, model, invs, findings, cov, g, tgt_name) -> str:
    out = ["=" * 78, "CHAINWATCH DEEP HUNT", "=" * 78, "",
           f"target      {inp.address or tgt_name}",
           f"chain       {_CHAIN_NAMES.get(inp.chain_id, inp.chain_id or 'n/a')}"
           f"    block {inp.block_number or 'n/a'}",
           f"toolchain   {cov.get('toolchain', 'none')}", "",
           "DEEP COVERAGE (spec section 28)", "-" * 30,
           f"  Contracts modeled          {cov['contracts_modeled']}",
           f"  Functions analyzed         {cov['functions_modeled']}",
           f"  Functions explored         {cov['functions_explored']}",
           f"  Security invariants        {cov['invariants_discovered']}",
           f"  Invariants tested          {cov['invariants_tested']}",
           f"  Invariants validated       {cov['invariants_validated']}",
           f"  Historical tx analyzed     {cov['historical_tx_analyzed']}",
           f"  Historical reverts         {cov['historical_reverts']}",
           f"  Sequences planned          {cov['sequences_planned']}",
           f"  Counterfactual mutations   {cov['counterfactual_mutations']}",
           f"  Mutations executed         {cov.get('mutations_executed', 0)}",
           f"  Fork blocks tested         {cov['fork_blocks_tested']}", "",
           f"  Candidates generated       {cov['candidates_generated']}",
           f"  Candidates rejected        {cov['candidates_rejected']}",
           f"  Candidates reproduced      {cov['candidates_reproduced']}",
           f"  Confirmed findings         {cov['confirmed_findings']}", ""]
    if not findings:
        out.append("No candidate invariant survived to a reportable finding.")
    for f in findings:
        out.append("")
        out.append(f.render())
    out += ["", g.render_text()]
    return "\n".join(out)
