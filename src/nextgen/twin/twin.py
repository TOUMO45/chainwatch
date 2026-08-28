"""The orchestrator - `CounterfactualTwin(address, rpc_url, from_block,
to_block).run() -> TwinResult`, wiring Phases 1-10 together.

Verdict rule (spec, stated directly rather than routed through
`nextgen/state.classify` - that machinery is built around the SOURCE-DRIVEN
pipeline's named gates, most of which the Twin structurally cannot produce
since it never reads a git commit):

    CONFIRMED  iff  a violation reproduced on the fork
                AND deployment facts confirm the vulnerable implementation
                    is what is CURRENTLY live (the Twin's own equivalent of
                    "provenance MATCH" - it has no git commit to match a
                    build against, only a live address to match an
                    implementation against)
                AND the Skeptic sweep did not disprove it
                AND the blinded Reproducer independently agrees

    REJECTED   the Skeptic disproved it, OR deployment facts show the
               implementation the violation was found against is no longer
               live, OR the blinded Reproducer could not reproduce it

    UNKNOWN    no violation was found in the sampled budget (say so - this is
               NOT "safe", only "not found here"), or a violation was found
               but validation could not complete (no RPC / no Foundry
               toolchain) - never promoted, never silently dropped
"""

from __future__ import annotations

from typing import Optional

from .. import state as S  # noqa: F401  (imported for symmetry with sibling modules)
from ..adversarial import reproducer as REPRO
from ..adversarial import skeptic as SKEP
from ..deployment import run as deployment_run
from ..deployment import DeploymentFacts
from ..execground import foundry as F
from ..provenance import run as provenance_run
from . import boundaries as B
from . import checks as CH
from . import collect as C
from . import diverge as DV
from . import enrich as E
from . import fingerprint as FP
from . import model as M
from . import mutate as MU
from . import replay as R
from .rpc import RpcClient

_MAX_TXS_TO_MUTATE = 8
_MAX_MUTATIONS_PER_TX = 3


class CounterfactualTwin:
    def __init__(self, address: str, rpc_url: str, from_block: int, to_block: int,
                *, max_txs_to_mutate: int = _MAX_TXS_TO_MUTATE,
                max_mutations_per_tx: int = _MAX_MUTATIONS_PER_TX,
                toolchain: Optional[F.Toolchain] = None,
                on_event: Optional[callable] = None) -> None:
        self.address = address.lower()
        self.rpc_url = rpc_url
        self.from_block = from_block
        self.to_block = to_block
        self.max_txs_to_mutate = max_txs_to_mutate
        self.max_mutations_per_tx = max_mutations_per_tx
        self.tc = toolchain
        self._on_event = on_event

    def _emit(self, msg: str) -> None:
        if self._on_event:
            try:
                self._on_event(msg)
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ run

    def run(self) -> M.TwinResult:
        res = M.TwinResult(address=self.address, from_block=self.from_block,
                           to_block=self.to_block)
        rpc = RpcClient(self.rpc_url)

        self._emit(f"Phase 1: collecting real txs for {self.address} "
                   f"[{self.from_block}, {self.to_block}]")
        try:
            collection = C.collect(rpc, self.address, from_block=self.from_block,
                                   to_block=self.to_block)
        except Exception as exc:  # noqa: BLE001
            res.verdict = M.TWIN_UNKNOWN
            res.reason = f"Phase 1 (collect) failed: {type(exc).__name__}: {exc}"
            return res
        res.collection = collection
        if not collection.txs:
            res.verdict = M.TWIN_UNKNOWN
            res.reason = "no transactions found in this block window"
            return res

        tc = self.tc or F.resolve()
        if tc is None or not F.anvil_available():
            res.notes.append("no Foundry/anvil toolchain reachable - traces are "
                             "tx-only and Phases 5-10 cannot run")
            traces: dict = {tx.hash: M.Trace(tx=tx, source="tx-only")
                           for tx in collection.txs}
        else:
            self._emit("enriching: re-executing candidate txs on a local "
                       "Anvil fork for deep traces")
            traces = E.enrich_many(collection, fork_rpc_url=self.rpc_url,
                                   toolchain=tc,
                                   max_txs=self.max_txs_to_mutate * 3)

        self._emit("Phase 2: building behavioural fingerprints")
        fingerprints = FP.build_fingerprints(collection, traces)
        res.fingerprints = fingerprints

        self._emit("Phase 3: mining behavioural boundaries")
        bounds = B.mine_boundaries(fingerprints, collection.transfers, traces)
        res.boundaries = bounds

        divergences = self._phase4_divergence(rpc, collection, fingerprints, bounds)
        res.divergences = divergences
        changed_selectors = {d.selector for d in divergences}

        if tc is None or not F.anvil_available():
            res.verdict = M.TWIN_UNKNOWN
            res.reason = "no Foundry/anvil toolchain reachable - Phases 5-10 " \
                         "(mutation, replay, checks, validation) did not run"
            return res

        self._emit("Phase 5: generating counterfactual mutations")
        candidates = self._select_candidates(collection, fingerprints, bounds)
        planned: list[M.Mutation] = []
        for tx in candidates:
            trace = traces.get(tx.hash)
            sel_bounds = [b for b in bounds if b.selector == tx.selector]
            muts = MU.generate_mutations(
                tx, trace, ctx={"boundaries": sel_bounds,
                                "related_txs": collection.txs},
                changed_selectors=changed_selectors)
            muts.sort(key=lambda m: -m.weight)
            planned.extend(muts[:self.max_mutations_per_tx])

        self._emit(f"Phase 6/7: replaying {len(planned)} mutation(s) on "
                   f"isolated forks and checking for violations")
        violations, first_violating_mutation = self._replay_and_check(
            tc, planned, traces, bounds)
        res.mutations_tried = len(planned)
        res.violations = violations

        if not violations:
            res.verdict = M.TWIN_UNKNOWN
            res.reason = (f"{len(planned)} mutation(s) replayed across "
                          f"{len(candidates)} real transaction(s); none crossed "
                          f"a mined boundary - not evidence of safety, only "
                          f"that nothing was found within this budget")
            return res

        self._emit(f"Phase 8: minimising the reproducing mutation")
        minimal = self._phase8_minimize(tc, first_violating_mutation, bounds,
                                        traces.get(first_violating_mutation.base_tx))
        res.minimal_repro = minimal

        self._emit("Phase 9: provenance / deployment")
        impl_addr = self._impl_at_replay(collection, first_violating_mutation)
        deployment_facts = deployment_run(self.address, vulnerable_impl=impl_addr,
                                          rpc_url=self.rpc_url)
        provenance_chain = provenance_run(self.address, None, commit=None,
                                          rpc_url=self.rpc_url)
        res.deployment_facts = deployment_facts
        res.provenance_chain = provenance_chain

        self._emit("Phase 10: Skeptic sweep + blinded reproduction")
        skeptic_report = SKEP.sweep(deployment_facts=deployment_facts,
                                    provenance_chain=provenance_chain)
        res.skeptic_report = skeptic_report

        violation = violations[0]
        target = REPRO.BlindTarget(
            contract="", function=violation.selector,
            invariant_statement=violation.statement,
            objective={"type": "boundary_violation", "kind": violation.kind},
            address=self.address)

        def _runner(bt: REPRO.BlindTarget) -> REPRO.ReproResult:
            rr = R.replay_on_fresh_fork(tc, self.rpc_url, minimal)
            if rr.error or not rr.executed:
                return REPRO.ReproResult(REPRO.ERROR, rr.error or "did not execute")
            vs = CH.check_violations(traces.get(minimal.base_tx), rr, bounds)
            if any(v.kind == violation.kind for v in vs):
                return REPRO.ReproResult(REPRO.REPRODUCED,
                                         "independent fresh-fork replay "
                                         "reproduced the same violation kind",
                                         artifacts={"violations": [v.as_dict() for v in vs]})
            return REPRO.ReproResult(REPRO.NOT_REPRODUCED,
                                     "independent fresh-fork replay did not "
                                     "reproduce this violation")

        reproducer_result = REPRO.attempt(target, runner=_runner)
        res.reproducer_result = reproducer_result

        res.verdict, res.reason = self._classify(deployment_facts, skeptic_report,
                                                  reproducer_result)
        return res

    # -------------------------------------------------------------- helpers

    def _select_candidates(self, collection: M.Collection,
                           fingerprints: dict, bounds: list[M.Boundary]
                           ) -> list[M.TxRecord]:
        """Prefer txs whose selector has at least one mined boundary - a
        mutation against a selector with no boundary has nothing for Phase 7
        to check it against. Falls back to the most recent txs if no boundary
        was mined at all (still worth trying ACTOR_SUBSTITUTION/REPETITION,
        which need no boundary)."""
        bounded_selectors = {b.selector for b in bounds if b.selector}
        with_boundary = [t for t in collection.txs if t.selector in bounded_selectors]
        pool = with_boundary or list(collection.txs)
        # de-dupe by selector so a chatty selector doesn't crowd out the rest
        seen: set = set()
        out = []
        for t in reversed(pool):     # most recent first
            if t.selector in seen:
                continue
            seen.add(t.selector)
            out.append(t)
            if len(out) >= self.max_txs_to_mutate:
                break
        return out

    def _phase4_divergence(self, rpc: RpcClient, collection: M.Collection,
                           fp_new: dict, b_new: list[M.Boundary]
                           ) -> list[M.Divergence]:
        upgrades = collection.upgrades
        if not upgrades:
            return []
        upgrade_block = upgrades[-1][0]
        old_lo = max(collection.from_block, upgrade_block - 2000)
        old_hi = max(upgrade_block - 1, old_lo)
        if old_hi <= old_lo:
            return []
        self._emit(f"Phase 4: an implementation change was observed at block "
                   f"{upgrade_block} - collecting a pre-upgrade window "
                   f"[{old_lo}, {old_hi}] to compare against")
        try:
            old_collection = C.collect(rpc, self.address, from_block=old_lo,
                                       to_block=old_hi, max_txs=100)
        except Exception as exc:  # noqa: BLE001
            return [M.Divergence(kind=M.INVARIANT_WEAKENING, selector="",
                                statement=f"could not collect the pre-upgrade "
                                         f"window: {type(exc).__name__}: {exc}")][:0]
        if not old_collection.txs:
            return []
        fp_old = FP.build_fingerprints(old_collection, {})
        b_old = B.mine_boundaries(fp_old, old_collection.transfers, {})
        old_impl = next((i for b, i in collection.impl_samples if b < upgrade_block and i),
                        "old")
        new_impl = upgrades[-1][1]
        return DV.compare_versions(fp_old, fp_new, b_old, b_new,
                                   old_ref=old_impl, new_ref=new_impl)

    def _replay_and_check(self, tc: F.Toolchain, planned: list[M.Mutation],
                          traces: dict, bounds: list[M.Boundary]
                          ) -> tuple[list[M.Violation], Optional[M.Mutation]]:
        by_block: dict[int, list[M.Mutation]] = {}
        for m in planned:
            by_block.setdefault(m.fork_block, []).append(m)

        violations: list[M.Violation] = []
        first_mutation: Optional[M.Mutation] = None
        for fork_block, muts in by_block.items():
            try:
                with F.AnvilFork(tc, fork_url=self.rpc_url, fork_block=fork_block,
                                 timeout=120) as fork:
                    frpc = RpcClient(fork.rpc_url, timeout=45)
                    snap = None
                    try:
                        snap = frpc.anvil_snapshot()
                    except Exception:  # noqa: BLE001
                        snap = None
                    for m in muts:
                        rr = R.replay(frpc, m)
                        vs = CH.check_violations(traces.get(m.base_tx), rr, bounds)
                        if vs and first_mutation is None:
                            first_mutation = m
                        violations.extend(vs)
                        if snap:
                            try:
                                frpc.anvil_revert(snap)
                                snap = frpc.anvil_snapshot()
                            except Exception:  # noqa: BLE001
                                pass
            except Exception:  # noqa: BLE001
                continue        # this fork window failed - the rest still run
        return violations, first_mutation

    def _phase8_minimize(self, tc: F.Toolchain, mutation: M.Mutation,
                         bounds: list[M.Boundary], baseline: Optional[M.Trace]
                         ) -> M.Mutation:
        target_kind_holder: list[str] = []

        def _verify(candidate: M.Mutation) -> bool:
            rr = R.replay_on_fresh_fork(tc, self.rpc_url, candidate)
            if rr.error or not rr.executed:
                return False
            vs = CH.check_violations(baseline, rr, bounds)
            if not target_kind_holder:
                return bool(vs)
            return any(v.kind == target_kind_holder[0] for v in vs)

        # establish which violation kind we're minimising for, from the
        # ORIGINAL (unminimised) mutation, before delta-debugging changes it.
        rr0 = R.replay_on_fresh_fork(tc, self.rpc_url, mutation)
        vs0 = CH.check_violations(baseline, rr0, bounds) if not rr0.error else []
        if vs0:
            target_kind_holder.append(vs0[0].kind)
        return R.minimize_calls(mutation, _verify)

    def _impl_at_replay(self, collection: M.Collection, mutation: M.Mutation
                        ) -> Optional[str]:
        candidates = [i for b, i in collection.impl_samples
                     if i and b <= mutation.fork_block + 1]
        return candidates[-1] if candidates else (
            collection.impl_samples[-1][1] if collection.impl_samples else None)

    def _classify(self, deployment_facts: DeploymentFacts,
                 skeptic_report: SKEP.SkepticReport,
                 reproducer_result: REPRO.ReproResult) -> tuple[str, str]:
        if skeptic_report.disproved:
            bad = next(c for c in skeptic_report.challenges if c.outcome == SKEP.DISPROVED)
            return M.TWIN_REJECTED, f"Skeptic disproved it: {bad.name} - {bad.detail}"
        if deployment_facts.gate == S.FAIL:
            return M.TWIN_REJECTED, ("the implementation the violation was found "
                                     "against is not what is currently deployed: "
                                     + deployment_facts.rationale)
        if reproducer_result.status == REPRO.NOT_REPRODUCED:
            return M.TWIN_REJECTED, ("independent blinded reproduction did not "
                                     "agree: " + reproducer_result.detail)
        if (deployment_facts.gate == S.PASS
                and reproducer_result.status == REPRO.REPRODUCED
                and not skeptic_report.disproved):
            return M.TWIN_CONFIRMED, ("a violation reproduced on an isolated fork, "
                                      "the vulnerable implementation is currently "
                                      "live, the Skeptic could not disprove it, "
                                      "and an independent blinded replay agrees")
        return M.TWIN_UNKNOWN, ("a violation reproduced on the fork but "
                                "provenance/independent-reproduction could not be "
                                f"fully established (deployment gate="
                                f"{deployment_facts.gate}, reproducer="
                                f"{reproducer_result.status}) - not disproved, "
                                f"just not fully validated")
