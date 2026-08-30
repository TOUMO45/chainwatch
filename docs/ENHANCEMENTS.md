# Enhancements — one section per shipped phase

Each entry records what was built, the constraint it had to respect, and how
that constraint is *proved* rather than asserted. A phase with no test is not
a phase.

The invariants every entry below respects, unchanged:

1. Verdict semantics never change — any blocking gate FAIL → REJECTED; any gate
   not PASS → UNKNOWN; all PASS → CONFIRMED. No new promotion paths.
2. The 5 hard gates block CONFIRMED outright.
3. The Skeptic can only FAIL a gate, never pass one.
4. The Reproducer stays blinded.
5. The 10 finding types and 8 rejection states keep their meanings.
6. Every report line is tagged FACT / INFERENCE / ASSUMPTION.
7. Source-only scans still produce zero CONFIRMED findings.
8. The LLM cannot create a finding.
9. All pre-existing tests pass unchanged; no CLI flag, API route, report
   section or Firestore collection is removed or renamed.

---

## Capability 19 — funnel instrumentation and the resolution queue

**The problem.** "0 CONFIRMED" is not one result. *Every candidate was
disproved* and *every candidate died one gate short of an address nobody
supplied* are opposite situations that a count cannot distinguish, and the
report had no way to tell them apart.

**What shipped.**

| Piece | Where |
|---|---|
| The trace model, both gate models, verification, queue, summary | `src/funnel.py` |
| A trace per finding, attached to every scan report | `src/scan.py::_funnel_section` |
| `--funnel`, `--funnel-format {text,json,csv}`, `--verify-funnel` | `chainwatch.py` |
| `GET /api/scan/{id}/funnel`, re-verified on every read | `webapp/server.py` |
| Resolution-queue panel | `webapp/static/app.js::renderFunnel` |
| `funnel_traces` collection, written in the scan's own batch | `src/corpus.py` |

Per candidate a trace records `gate_states`, `kill_gate` (the first gate that
FAILED, in evidence order), `blocking_gates`, `distance_to_confirmed`,
`required_inputs`, and one machine-readable **evidence request** per unresolved
gate naming the deterministic input that would let that gate run — plus
`repo`, `commit_pair`, `engine`, `rule_class`, `finding_type`,
`toolchain_versions` and a timestamp.

**The constraint, and how it is proved.**

The funnel must never become a second opinion about what CONFIRMED means. Three
things enforce that:

- `verify()` recomputes the stored verdict from the stored gate states using
  **the engine's own gate function** and raises `TraceDivergence` on any
  mismatch. It is called by the scan, by the API on every read, by
  `--verify-funnel` (exit 1 on divergence), and by the tests.
- `distance_to_confirmed` is a count of gates that have not run. Not a score,
  not a likelihood. A killed candidate has distance `None`, not `0` — no
  evidence moves it, and it sorts last.
- The classic six-field model is restated as gates so it can be traced, and the
  restatement is proved equivalent to `verdict.classify` across **all 768
  shapes** a classic finding can take
  (`tests/test_funnel.py::test_classic_gate_model_agrees_with_verdict_classify`).

**A bug this found in its own first draft.** The exhaustive equivalence test
failed on its first run: the funnel read the LIVE requirement from
`Finding.liveness` while the evidence-presence check read
`Evidence.liveness`, and the test fixture set them independently — a shape
`verdict.build` never produces. The fixture was wrong, not the module, so the
fix was to build findings the way `build` does *and* pin the coupling in
`test_build_couples_the_two_liveness_fields`, so the simplification cannot rot
silently.

**Tests.** `tests/test_funnel.py` (38), `tests/test_funnel_api.py` (5), plus two
new cases in `tests/test_corpus.py`. Real committed scan artifacts
(`.scan-88mph-r10.json`, `.e2-full-aave.json`) are traced and verified, not only
synthetic gate maps.

**Verified end to end**, not only in unit tests: a real two-commit repository
scanned through the CLI to one rule-1 CANDIDATE, its trace verified, the same
data served by the API and drawn by the web UI's resolution queue.

---

## Capability 20 — the ADK multi-agent layer

**The problem.** The submission needed a real agent framework, and the project
needed one without letting a model anywhere near a verdict. Those pull in
opposite directions unless the boundary is enforced by code rather than by a
prompt.

**What shipped.** Four roles in `agent/orchestrator.py`, reachable as
`chainwatch agent --repo <url>` (or `--agent`):

| Role | Kind | May propose | May decide |
|---|---|---|---|
| Hunter | Gemini 3.5 via ADK `LlmAgent` | which engine candidates deserve deeper evidence work, and each one's invariant in a sentence | nothing |
| Skeptic | Gemini 3.5 via ADK `LlmAgent` | disproof challenges | nothing — challenges are inputs |
| Reproducer | Gemini 3.5 via ADK `LlmAgent` | a reproduction plan from four fields | nothing |
| Gatekeeper | **deterministic code** | — | **everything** |

**Three constraints, each enforced structurally rather than by instruction.**

1. **The layer cannot change a verdict.** The engine runs first and its
   verdicts are snapshotted *before a single token is generated*. At the end
   the verdicts are recomputed and compared; a difference raises
   `VerdictDrift` and the run fails. This runs on every invocation, in
   production — not only under test.
2. **The Hunter cannot create a finding.** A proposal naming an id the engine
   never produced is dropped and the drop is recorded in the turn log. Proved
   against a stub that invents one.
3. **The Reproducer is blinded by the type system.** It receives a frozen
   `ReproducerBrief` with exactly four fields — contract, function, invariant
   statement, objective. There is no code path that could add the write-up,
   and the test captures the *actual prompt string* sent to the model and
   asserts the write-up is absent from it.

**The abstain path is the control experiment.** With no API key, every model
turn abstains and the same orchestration runs. It must produce identical
verdicts — and a test asserts it. If the two paths ever diverged, the model
would be deciding something.

**Observed on real output** (`gemini-3.5-flash-lite`, a real two-commit repo):
the Reproducer's own `unknowns` came back as *"the exact function signature"*
and *"the method used for access control"* — precisely the things it was not
told. The blinding is visible in the model's answer, not just in the code.

**Persistence.** `agent_runs` + `agent_turns` in Firestore (additive
collections), one document per run and one per turn, carrying what each agent
saw, said, and what the gate did about it.

**Tests.** `tests/test_agent_orchestrator.py` (20), each of the three
constraints tested against a stub model that is actively trying to break it.

---

## Capability 21 — the unattended sweep

**The problem.** Every other path in Chainwatch is started by a human who then
reads the answer. A scheduled sweep has nobody present, and that changes
exactly one requirement: **a failing target must not end the sweep.** A run
that died on repo four of twenty looks identical to a completed run with a
short list.

**What shipped.**

| Piece | Where |
|---|---|
| Target parsing, per-target isolation, totals, digest, self-check | `src/sweep.py` |
| `chainwatch sweep --repos <file\|list>`, `--sweep-agent` | `chainwatch.py` |
| `sweeps` collection; tracebacks dropped, error messages kept | `src/corpus.py` |
| `GET /api/sweeps` and the Sweeps panel | `webapp/server.py`, `static/app.js` |
| Cloud Run Job + Cloud Scheduler recipe | `deploy/sweep-job.md` |

Every target is wrapped; a failure is recorded **with its reason** and the
sweep continues. `totals.failed` sits next to `totals.ok`, and both the CLI
digest and the web panel draw failures at the same weight as successes — the
same discipline as the coverage invariant: what could *not* be done is part of
the report, never an absence in it.

`deploy/sweep-job.md` sets `--max-retries 1` deliberately: a repository that
will not clone fails the same way on a retry, while the other nineteen have
already been walked. A job that exits non-zero because three of twenty repos
were unreachable gets muted within a week, and a muted job is not running at
all.

**Honest limitation, stated rather than papered over.** A sweep over public
repositories has no deployed addresses, so liveness is UNKNOWN and **nothing a
sweep finds can reach CONFIRMED**. That is the verdict model working exactly as
designed, and it is why the sweep's product is the funnel — which candidates
are one address away — rather than a CONFIRMED count.

**Tests.** `tests/test_sweep.py` (14), centred on the isolation property: one
target exploding *inside the scan* must not stop the two around it.

**Verified end to end**: a two-target sweep where one repository does not
exist — the good target completed, the broken one was recorded with its error,
the sweep finished, and persistence degraded to "not recorded" without failing
the run.
