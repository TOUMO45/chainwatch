# Chainwatch — Next-Generation Security Regression & Proof Engine

> This file is the roadmap for the upgrade begun 2026-08-28. It does **not**
> replace `CHARTER.md`. The classic pipeline (`src/scan.py` → `src/verdict.py`
> → three verdicts, six evidence fields) is unchanged and stays the default.
> Everything here is **additive**, lives under `src/nextgen/`, and is reached
> only behind an explicit flag.

> **Status 2026-08-28: all 27 sections implemented** across phases 0–6 (see the
> per-phase acceptance checks below). `src/nextgen/` is imported by nothing on
> the classic path; `./guard.sh check` stays `INTEGRITY OK` and the pre-existing
> `pytest tests/` count is unchanged (509 passed / 3 skipped at the Phase 3
> boundary), plus ~190 new `test_nextgen_*` tests. The execution-grounding
> layer (§5/§6/§15/§21) is proven end to end against real Foundry via WSL.
> Deferred by explicit decision, not omission: a symbolic solver (§6 uses a
> Python constraint sketch), and the `unauthorized_upgrade` /
> `state_relation_violated` reproducer generators (§15 Phase 5b follow-up).

> **Tier 1 (2026-08-28) — real-repo scanning.** `src/nextgen/repo.py`
> (`RepoContext`) reconstructs each commit's dependency environment with the
> classic engine's own machinery (`src/history.py` mirror clone + per-commit
> worktree + `detect_env`/`install`, `src/rules/_shared` compile with the right
> solc + remappings), so a next-gen analysis of a real commit sees what the
> classic scanner sees. `pipeline.run_from_repo(repo, parent, commit, file,
> contract, function, [address, rpc_url])` and the `chainwatch.py --nextgen
> FILE:CONTRACT:FUNCTION` flag drive it. **Verified on the real 88mph
> disclosure**: from `realworld-test/88mph-src` at `a4c48d61` with the live
> address `0xDe71B24F…`, the pipeline reaches **`CONFIRMED`** — regression
> commit, dependency-resolved invariant regression, `EOA → NFT.init`
> unprivileged path, byte-identical on-chain bytecode provenance, `target_live`
> YES, and a read-only `eth_call` reproduction (the correct method for a 0.5.17
> pragma; Foundry needs ≥ 0.6.2). On `reserve-protocol` at `e27227b2`
> (`ActFacet.revenueOverview`, a `try/catch` removed from a non-mutating
> function) it correctly returns **`NOT A FINDING`** — no validated invariant
> regressed and no unprivileged path reaches a sensitive sink.

## Mission

Upgrade Chainwatch from a smart-contract security **regression scanner** into an
**execution-grounded security research and proof engine** for EVM systems.

The goal is **not** to maximise vulnerability reports. It is to maximise

```
CONFIRMED findings
─────────────────────   with the strongest possible evidence.
FALSE POSITIVES
```

A candidate is **not** a finding. A candidate becomes `CONFIRMED` only when an
independent evidence chain proves every link:

```
historical security property
  → security regression
  → exact regression commit
  → vulnerable implementation
  → correct build environment
  → reachable attacker-controlled path
  → required state can actually exist
  → no compensating protection exists
  → security invariant is violated
  → reproducer succeeds (local fork)
  → deployed bytecode corresponds to the vulnerable build
  → target is still relevant / live
  → independent validation agrees
  → CONFIRMED
```

LLM confidence is never one of those links. Deterministic evidence closes each
one, or the finding does not reach `CONFIRMED` — it reaches `UNKNOWN`.

## Core principle (spec §25)

> A vulnerability is not a pattern. A vulnerability is a violated security
> property that an attacker can actually reach and reproduce under the real
> execution environment.

```
pattern            ≠ vulnerability
suspicion          ≠ vulnerability
LLM confidence     ≠ vulnerability
static warning     ≠ vulnerability
historical bug     ≠ current vulnerability
deployed vuln code ≠ exploitable vulnerability
```

The system is built so the **easiest outcome is REJECT**, `CONFIRMED` is
deliberately difficult, and when evidence is incomplete the answer is `UNKNOWN`,
never a guess.

## How this relates to the existing pipeline

- **Nothing in `src/verdict.py`, `src/scan.py`, `src/rules/`, `fixtures*/`, or
  the 346 existing tests is modified by this work.** `./guard.sh check` stays
  `INTEGRITY OK`; `python scorer.py --all` stays precision = 1.00.
- The next-gen pipeline is opt-in: `CHAINWATCH_NEXTGEN=1` (env) or `--nextgen`
  (CLI, added in a later phase). Off by default.
- A next-gen `CONFIRMED` must **first** pass the classic gate
  (`verdict.classify` → `CONFIRMED`), **then** clear the additional evidence
  chain on top. The next-gen layer can only ever be *stricter*, never looser.
- The Gemini agent layer is unchanged in role: it hypothesises and explains, it
  never decides a verdict (spec §22, already the architecture — see
  `agent/verify.py`).

## Charter carve-out (recorded in CHARTER.md, 2026-08-28 amendment)

The classic charter forbids fuzzing, symbolic execution, and PoC/exploit
generation outright. For the next-gen pipeline only, that is narrowed to:

| Allowed (next-gen only)                                   | Still forbidden, always |
|----------------------------------------------------------|-------------------------|
| Execution against a **local forked EVM** (anvil)         | Any transaction broadcast to a real network |
| A minimal reproducer that **demonstrates an invariant violation** | Turnkey / weaponised exploit code, reusable attack contracts |
| Foundry-based regression fuzzing between two commits      | Auto-disclosure, auto-filing, contacting a project |
| Rough economic-feasibility estimation                    | Selling, holding, or moving any asset |
| A Python "symbolic sketch" of path constraints           | A full symbolic engine as a trust root (deferred, not banned) |

On-chain access stays strictly read-only (`eth_getCode`, `eth_getStorageAt`,
read-only `eth_call`) exactly as today. The fork is local state; it never
touches mainnet.

## Dependency decisions (CHARTER rule 3 — asked and answered 2026-08-28)

| Dependency | Phase | Status |
|---|---|---|
| Foundry (`forge`, `anvil`) | 5 | **Approved and available.** `forge`/`anvil` `1.8.0` are installed in **WSL** (`kali-linux`, `/home/kali/.foundry/bin`), not on Windows. Verified end to end (`forge init`/`build`/`test`, svm solc auto-download). Phase 5 shells to WSL via a `nextgen/execground/` adapter and still degrades to `UNKNOWN` (never `CONFIRMED`) when no `forge` is reachable — same as `liveness.py` without an RPC. |
| `halmos` / `hevm` (symbolic) | later | Deferred. §6's symbolic half starts as a Python constraint sketch. |
| No other new runtime deps in phases 0–4. | — | — |

**WSL Foundry invocation** (from the Windows/Git-Bash host): argv path mangling
must be disabled, and the toolchain PATH set explicitly —
`MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' wsl.exe -d kali-linux --exec /bin/bash <script.sh>`,
where the script does `export PATH="$HOME/.foundry/bin:/usr/local/bin:/usr/bin:/bin"`.
Run forge in an isolated `/tmp` dir so it does not auto-load the repo `.env`.

## Section → module map

Legend: **done** · **wip** · **planned** · *(extends existing module)*

| §  | Title | Module | Status |
|----|-------|--------|--------|
| 1  | Security Time Machine | `nextgen/timemachine.py` + `timemachine_probes.py` | **done (Phase 1)** |
| 2  | Automatic security invariant discovery | `nextgen/invariants/discover.py` + `validate.py` + `model.py` | **done (Phase 2)** |
| 3  | Invariant regression engine | `nextgen/invariants/regress.py` | **done (Phase 2)** |
| 4  | Attack-path graph | `nextgen/attackgraph.py` | **done (Phase 3a)** |
| 5  | Stateful multi-transaction reasoning | `nextgen/execground/sequences.py` | **done (Phase 5b)** |
| 6  | Symbolic + concrete hybrid validation | `nextgen/execground/hybrid.py` (constraint sketch + concrete; solver deferred) | **done (Phase 5b)** |
| 7  | Adversarial false-positive killer | `nextgen/adversarial/hunter.py`, `skeptic.py` | **done (Phase 4)** |
| 8  | Three-agent independent validation | `nextgen/adversarial/reproducer.py` (blinded interface; exec is Phase 5) | **interface done (Phase 4)** |
| 9  | Git → build → bytecode → deployment provenance | `nextgen/provenance.py` *(composes `liveness.py`, `verified.py`)* | **done (Phase 3b)** |
| 10 | Deployment-aware security | `nextgen/deployment.py` *(composes `liveness.resolve_implementation`)* | **done (Phase 3b)** |
| 11 | Compensating-control analysis | `nextgen/compensating.py` *(deepens evidence field 5)* | **done (Phase 3b)** |
| 12 | Cross-contract security regressions | `nextgen/attackgraph.py` (protocol graph) | **partly done (Phase 3a — cross-contract paths); regression diff Phase 3b** |
| 13 | Cross-protocol / composability analysis | `nextgen/composability.py` | **done (Phase 6, best-effort)** |
| 14 | Economic exploitability engine | `nextgen/execground/economics.py` | **done (Phase 5a)** |
| 15 | Automatic minimal PoC generation | `nextgen/execground/reproducer.py` + `foundry.py` | **done (Phase 5a — call_succeeds / reinit; upgrade + relation Phase 5b)** |
| 16 | Proof quality score | `nextgen/proofscore.py` | **wip (Phase 0)** |
| 17 | Finding state machine | `nextgen/state.py` | **wip (Phase 0)** |
| 18 | Security evidence graph | `nextgen/evidence_graph.py` | **wip (Phase 0)** |
| 19 | Compiler / build-environment security | `nextgen/buildenv.py` *(extends `history.py`, `verified.py`)* | **done (Phase 1)** |
| 20 | Known-exploit replay benchmark | `nextgen/benchmark/` *(offline hard-negative suite done; online suite Phase 5/6)* | **done (Phase 4)** |
| 21 | Regression fuzzing | `nextgen/execground/regfuzz.py` | **done (Phase 5b)** |
| 22 | Do not trust the LLM | architecture-wide; enforced by `proofscore` hard gates + `state` | **wip (Phase 0)** |
| 23 | Reporting mode | `nextgen/report.py` | **done (Phase 4)** |
| 24 | `UNKNOWN` security regression | `nextgen/state.py` (`UNKNOWN` outcome) | **wip (Phase 0)** |
| 25 | Core principle | this file + `proofscore` hard gates | **wip (Phase 0)** |
| 26 | Final architecture | `nextgen/pipeline.py` — the end-to-end orchestrator | **done (Phase 6)** |
| 27 | Ultimate objective | `nextgen/benchmark/` metric: CONFIRMED / FALSE-POSITIVE | planned (Phase 4) |

## Phase gates

Every phase ends only when, on raw output pasted into the commit or HANDOFF:

1. `./guard.sh check` → `INTEGRITY OK`
2. `python -m pytest tests/ -q` → the pre-existing count still passes, plus the
   phase's new tests
3. the phase's own acceptance check (named in that phase's section below)

## Phase 0 — substrate (in progress, 2026-08-28)

Delivers the shared machinery every later phase writes into:

- `nextgen/state.py` — the explicit finding state machine (§17), the gate
  model, and `UNKNOWN` as a first-class outcome distinct from a rejection
  (§24). Deterministic `classify_nextgen(gates) → (state, verdict, reasons)`.
- `nextgen/evidence_graph.py` — findings stored as typed evidence nodes and
  relationships (§18), so every statement in a report is traceable to what
  produced it; LLM hypotheses are marked as such and are not evidence.
- `nextgen/proofscore.py` — the deterministic +/- score from spec §16, plus
  the **hard gates the score can never override**.
- `nextgen/__init__.py` — the `CHAINWATCH_NEXTGEN` feature flag. Imported by
  nothing in the hot path yet.

**Acceptance check (Phase 0):**
`python -m pytest tests/test_nextgen_state.py tests/test_nextgen_evidence_graph.py tests/test_nextgen_proofscore.py -q`
passes, and it includes: a score of +100 with a failed hard gate still yields
`permits_confirmed == False`; a gate set with one `UNKNOWN` and no `FAIL`
yields verdict `UNKNOWN` (not `REJECTED`, not `CONFIRMED`); an illegal state
transition raises. **Met** (48 passed).

## Phase 1 — Security Time Machine + build-environment security (done, 2026-08-28)

- `nextgen/timemachine.py` — a probe-agnostic engine that walks the WHOLE
  history of a security property's defining files and classifies every change
  as INTRODUCED / MODIFIED / REMOVED / RESTORED. `regression_commit` is the
  REMOVED that explains why the property is absent NOW (the last one not
  followed by a RESTORED); it is `None` whenever the property is in force at
  HEAD. Unmeasurable commits (no file, would not compile) are skipped, never
  read as "absent". Emits into the evidence graph (§18).
- `nextgen/timemachine_probes.py` — `AccessControlProbe` and
  `InitializerOneShotProbe`, built on `src/rules/_shared` (`constrains_msg_sender`,
  `has_init_guard`) so the Time Machine and the classic rules agree on what a
  property is. Phase 1 cut, stated in the module: probes compile the defining
  file in ISOLATION, so a commit whose meaning needs unresolved imports is
  reported `measurable=False`, not guessed. Per-commit dependency
  reconstruction is wired in a later phase.
- `nextgen/buildenv.py` — the five compiler-version-risk patterns (§19):
  RANGE_PRAGMA, HISTORICAL_MISMATCH (a solc semantic boundary crossed between
  the pinned and the used version), KNOWN_BUGGY_COMPILER (matches a documented
  advisory, trigger-gated on `--via-ir` / ABIEncoderV2), EVM_VERSION_DRIFT
  (Shanghai/PUSH0), OPTIMIZER_DRIFT. `analyze()` returns a `build_environment`
  gate that is FAIL only for a provable drift, PASS only for an exact build
  proven identical to the deployed one, UNKNOWN otherwise.
- `nextgen/gates.py` — `apply_timeline` / `apply_buildenv`: the one place
  Phase 1 outputs set Phase 0 gates, so every phase does it the same way.

**Acceptance check (Phase 1):**
`python -m pytest tests/test_nextgen_timemachine.py tests/test_nextgen_buildenv.py tests/test_nextgen_gates.py tests/test_nextgen_timemachine_probes.py -q`
passes, and includes: introduce→remove→restore over a real synthetic git repo
(no compiler) yields exactly `[INTRODUCED, REMOVED, RESTORED]` with no live
regression; a second removal after a restore IS the live regression; a
semantic-boundary compiler mismatch fails the build-environment gate; a
property present at HEAD fails the regression gate. **Met** (38 passed; the 4
`AccessControlProbe` cases run when a working `solc` is present, else skip
visibly).

## Phase 2 — invariant discovery + regression engine (done, 2026-08-28)

- `nextgen/invariants/model.py` — `CandidateInvariant` with the
  INFERRED → TESTED → VALIDATED → USED status discipline (one step forward at a
  time; REJECTED terminal). Only `VALIDATED`/`USED` invariants are `usable` -
  may influence a verdict. `subject_key` identifies what an invariant is ABOUT
  (kind, contract, functions, state-variable subject, source) independent of
  how it is currently phrased, so a shrunk role set reads as WEAKENED, not
  REMOVED.
- `nextgen/invariants/discover.py` (§2) — six mechanical inference rules built
  on `src/rules/_shared`: GUARDED_ACTION / ROLE_GATED (access control),
  INITIALIZER_ONCE (state machine), UPGRADE_AUTH (deployment),
  SUPPLY_ACCOUNTING (ERC20 shape), REQUIRE_CONDITION (weak code invariants).
  Test/mock paths are skipped. Everything produced is `INFERRED`.
- `nextgen/invariants/validate.py` — the re-check. INFERRED → TESTED when the
  structural pattern still holds; TESTED → VALIDATED when nothing in the same
  contract contradicts it (an unguarded sibling that writes the same state
  holds the invariant at TESTED with the contradiction recorded, rather than
  discarding it). An upgrade hook with no guard is REJECTED (the classic UUPS
  empty-`_authorizeUpgrade` footgun). Cross-contract contradiction hunting is
  Phase 3.
- `nextgen/invariants/regress.py` (§3) — `diff_invariants(old, new)` over two
  versions' VALIDATED sets: REMOVED (gone / no longer validated) or WEAKENED
  (still holds but constrains less). Each regression carries a structured
  `SearchTarget` — `call_succeeds` / `reinit` / `state_relation_violated` /
  `unauthorized_upgrade` — the objective a reproducer drives from in Phase 5.
- `nextgen/gates.py` gains `apply_invariant_regressions`: a validated
  regression sets `security_invariant` PASS; `invariant_violated` stays PENDING
  (observing the violation needs execution).

**Acceptance check (Phase 2):**
`python -m pytest tests/test_nextgen_invariants_model.py tests/test_nextgen_invariants_regress.py tests/test_nextgen_invariants_discover.py -q`
passes, and includes: only VALIDATED old invariants can regress; a guarded
action that loses its guard between two real compiled sources produces exactly
one REMOVED regression with a `call_succeeds` target; an unguarded upgrade hook
is REJECTED and never `usable`. **Met** (24 passed; the 8 compile-backed cases
run with `solc` present, else skip visibly).

## Phase 3a — attack-path graph (done, 2026-08-28)

- `nextgen/attackgraph.py` (§4, §12) — a `ProtocolGraph` built from a Slither
  compilation: nodes are protocol roles (EOA, CONTRACT, PROXY,
  IMPLEMENTATION, ORACLE, TOKEN, BRIDGE, GOVERNANCE, VAULT, POOL,
  CALLBACK_SINK, and a FUNCTION node per external entry point); edges are the
  moves an attacker can make (CALL, DELEGATECALL, STATICCALL, TRANSFER,
  APPROVE, PERMIT, UPGRADE, INITIALIZE, CALLBACK, ORACLE_READ, BRIDGE_MESSAGE,
  GOVERNANCE_EXECUTION). Contract shape is classified structurally (a
  `upgradeTo`/`_authorizeUpgrade` contract is a PROXY, an oracle-method
  contract is an ORACLE, …). A FUNCTION node carries `guarded`
  (`constrains_msg_sender`) and `mutates_sensitive` (writes an access-control /
  supply / impl-slot variable). External `HighLevelCall`s resolve to the
  concrete callee function when it is in-unit, so cross-contract paths are
  real edges, not guesses.
- `find_attack_paths` — BFS from the EOA over traversable edges to every
  sensitive sink (or a named target function). A path is `unprivileged` iff it
  crossed no guarded edge; `crosses_contracts` marks a §12 path. Simple-path,
  depth-capped, deterministic ordering (unprivileged first, then shortest).
- `gates.apply_attackgraph` — an unprivileged path to the sink sets
  `reachable_path` PASS; paths that all cross a guard, or no path at all, set
  it FAIL → UNREACHABLE. `state_reachable` and `invariant_violated` are NOT
  touched here — proving the preconditions can be met, and that a run violates
  the invariant, are execution questions (Phase 5).

**Acceptance check (Phase 3a):**
`python -m pytest tests/test_nextgen_attackgraph.py tests/test_nextgen_attackgraph_build.py -q`
passes, and includes: an unprivileged direct path to an unguarded sensitive
writer; a guard-only path classified `unprivileged=False` → gate FAIL →
UNREACHABLE; a cross-contract path `EOA → Router.go → Vault.drain` found from
real compiled sources; a callback-mediated path to an otherwise-unreachable
sink. **Met** (18 passed; 6 compile-backed).

## Phase 3b — provenance, deployment-aware security, compensating controls (done, 2026-08-28)

- `nextgen/provenance.py` (§9) — `build_chain` assembles
  `commit → build settings → local runtime bytecode → on-chain runtime
  bytecode → MATCH`, composing `src/verified.settings_for` and
  `src/liveness.check_against_artifact`. `bytecode_provenance` gate: PASS on a
  LIVE match, FAIL → DEPLOYMENT_MISMATCH on PATCHED, UNKNOWN when any link is
  unestablished. A missing build-settings link never yields a PASS-with-
  `complete`. `run()` is the thin live wrapper; every failure degrades to
  INCOMPLETE.
- `nextgen/deployment.py` (§10) — `assess` turns
  `liveness.resolve_implementation` output into a `target_live` gate: PASS when
  the address currently serves the vulnerable implementation (matched impl
  address, or an immutable EIP-1167 clone proven LIVE), FAIL → PATCHED when the
  proxy now points elsewhere or there is no code, UNKNOWN when unresolved.
  Records `upgradeable` from the EIP-1967 admin slot.
- `nextgen/compensating.py` (§11) — explicit semantic-equivalence search before
  a "guard removed" claim stands: TRANSITIVE_GUARD (a reachable guard still
  gates on msg.sender), CALLER_GUARD (every external reacher of an internal
  target is guarded), STATE_PRECONDITION (reverts unless a state var only a
  guarded / one-shot path can set), GLOBAL_HALT (an inherited pause/mutex a
  guarded actor controls). A control found FAILS `no_compensating_control` →
  the candidate is REJECTED as FALSE_POSITIVE.
- `gates.py` gains `apply_provenance` / `apply_deployment` / `apply_compensating`.

**Acceptance check (Phase 3b):**
`python -m pytest tests/test_nextgen_provenance.py tests/test_nextgen_deployment.py tests/test_nextgen_compensating.py -q`
passes, and includes: PATCHED liveness → `bytecode_provenance` FAIL →
DEPLOYMENT_MISMATCH; a proxy now pointing elsewhere → `target_live` FAIL →
PATCHED; an immutable clone proven LIVE → PASS; a renamed `auth()` modifier
that still checks msg.sender → `no_compensating_control` FAIL → FALSE_POSITIVE;
a genuinely open function → PASS. **Met** (20 passed; 5 compile-backed).

## Phase 4 — adversarial validation, benchmark, report mode (done, 2026-08-28)

- `nextgen/adversarial/skeptic.py` (§7) — an independent, deterministic
  rejection sweep. Each check is DISPROVED / NOT_DISPROVED / INAPPLICABLE; a
  DISPROVED check FAILS its mapped gate (the Skeptic overrides a Hunter PASS —
  disproving is the point). The Skeptic never PASSES a gate; "failed to
  disprove" only lets the positive evidence stand.
- `nextgen/adversarial/hunter.py` (§8 Agent A) — thin orchestrator that runs
  the Phase 1–3 `gates.apply_*` helpers in evidence order. No analysis logic
  of its own, so "the Hunter ran" means the same thing every time.
- `nextgen/adversarial/reproducer.py` (§8 Agent C) — the BLINDED interface:
  `BlindTarget` carries only contract / function / invariant statement /
  objective — never the Hunter's write-up. `attempt()` is PENDING with no
  runner (execution is Phase 5) and never PASSES on its own.
- `gates.apply_skeptic` / `apply_reproducer` — `independent_validation`
  reaches PASS **only** when the Skeptic sweep is clean over ≥3 checks AND the
  blinded reproducer already agrees. A REPRODUCED result also PASSES
  `invariant_violated` and `state_reachable` (the run observed them).
- `nextgen/report.py` (§23) — a deterministic security-research report in
  three shapes chosen by `state.classify`: CONFIRMED (with a conservative
  severity), UNKNOWN (naming every unresolved gate, no severity), REJECTED
  ("NOT A FINDING", with the disproving reason). Every evidence-chain line is
  pulled from a gate result and its recorded note; an evidence-graph appendix
  flags any LLM hypothesis as "not evidence".
- `nextgen/benchmark/` (§20, §27) — `Metrics` (precision, recall,
  false-positive rate, and the §27 CONFIRMED/FALSE-POSITIVE ratio, which is
  `None` — the good case — when there are no false positives) plus an OFFLINE
  suite of synthetic cases that is **hard-negative-heavy**: renamed modifier,
  modifier→inline check, function-became-view, still-present-at-HEAD (all must
  REJECT), and one genuine removal (UNKNOWN offline — CONFIRM needs deployment
  + a reproducer).

**Acceptance check (Phase 4):**
`python -m pytest tests/test_nextgen_report.py tests/test_nextgen_adversarial.py tests/test_nextgen_benchmark.py -q`
passes, and includes: a compensating control found → Skeptic DISPROVED → gate
FAIL → REJECTED; a clean sweep without a reproducer leaves
`independent_validation` UNKNOWN; the reproducer is PENDING with no runner; the
offline benchmark runs with **zero false positives** and every case correct.
**Met** (29 passed with report+adversarial+economics+benchmark).

## Phase 5a — execution grounding: Foundry adapter, reproducer, economics (done, 2026-08-28)

CHARTER carve-out in force: local fork only, no weaponised artifact, no
broadcast tx, no auto-disclosure. The generated test lives in a throwaway
`/tmp` project and is deleted after the run.

- `nextgen/execground/foundry.py` — the toolchain adapter. Discovery order:
  `CHAINWATCH_FORGE` env path → native `forge` on PATH → **WSL**
  (`wsl.exe -d kali-linux --exec /bin/bash <script>`, PATH set explicitly,
  argv `_sh_quote`d, files written via base64 to dodge every quoting hazard,
  all subprocess I/O `utf-8`/`errors=replace` so forge's box-drawing output
  never crashes a reader thread). `resolve()` returns `None` when nothing is
  reachable and every caller degrades to PENDING.
- `nextgen/execground/reproducer.py` (§15) — `generate_and_run(target,
  source_bundle)`: scaffolds a minimal Foundry project with a vendored
  `forge-std/Test.sol` shim (no `forge install`, no git, no network),
  generates a minimal test for the §3 objective (`call_succeeds` → an
  unprivileged `vm.prank` call that must NOT revert; `reinit` → a second
  initialise that must NOT revert), runs `forge build` + `forge test`, and
  returns REPRODUCED on `[PASS] test_invariant_is_violated`, NOT_REPRODUCED on
  `[FAIL]`. `make_runner` wires this into the §8 blinded interface.
  `unauthorized_upgrade` / `state_relation_violated` return a clear
  "Phase 5b" reason.
- `nextgen/execground/economics.py` (§14) — a documented rough model
  (gas cost, flash-loan fee, capital ceiling for a lone attacker). The
  `economically_feasible` gate PASSES only when estimated profit clears a
  worthwhile threshold, FAILS (→ ECONOMICALLY_INFEASIBLE) on a money-losing or
  capital-walled attack, UNKNOWN with no extraction estimate. Never confirms.

**Acceptance check (Phase 5a):**
`python -m pytest tests/test_nextgen_economics.py tests/test_nextgen_execground_foundry.py tests/test_nextgen_execground_reproducer.py -q`
passes, and includes: a real WSL `forge build` + `forge test` run in which an
unguarded `setOwner` yields REPRODUCED and an `onlyOwner`-guarded `setOwner`
yields NOT_REPRODUCED; `$40M`-capital / `$2k`-profit → ECONOMICALLY_INFEASIBLE;
no toolchain → PENDING. **Met** (20 passed; 8 exercise real forge via WSL).

## Phase 5b — multi-tx sequences, hybrid validation, regression fuzzing (done, 2026-08-28)

- `nextgen/execground/sequences.py` (§5) — `enumerate_sequences` builds
  candidate tx sequences (bare call, then one/two setup-prefixed variants from
  the attack-path graph), `search` runs them shortest-first, and `minimize`
  delta-debugs a working one to the smallest sub-sequence that still
  reproduces (the objective step is never dropped). Output is the spec's
  "Minimal attack sequence: 1. … 2. …" form.
- `nextgen/execground/hybrid.py` (§6) — `sketch_constraints` classifies every
  guard on the target path: ATTACKER_PARAM (reads only call params →
  satisfiable), MSG_SENDER (compares msg.sender to a trusted identity →
  BLOCKING, unless that identity has an unguarded writer), STATE (needs a
  prior tx → hand to §5). `synthesize_calldata` picks literals that satisfy
  the param bounds (`> 100` → `101`). `run` short-circuits to
  `state_reachable` FAIL on a BLOCKING constraint, else runs the concrete
  reproducer and PASSES on a demonstrated violation. The symbolic solver stays
  deferred (charter amendment).
- `nextgen/execground/regfuzz.py` (§21) — `run_regression_fuzz` generates a
  Foundry fuzz test that deploys `OldTarget` and `NewTarget` (renamed copies
  of the two versions), fuzzes the changed function, and asserts the two
  revert on the same inputs. A `[FAIL]` counterexample →
  DIVERGENCE_FOUND (a corroborating regression signal, not a confirmation).

**Acceptance check (Phase 5b):**
`python -m pytest tests/test_nextgen_sequences.py tests/test_nextgen_hybrid.py tests/test_nextgen_regfuzz.py -q`
passes, and includes: `minimize` drops redundant setup steps but never the
objective; a real 2-step `deposit → drain` sequence is found and minimised; an
`onlyOwner` guard is classified MSG_SENDER → `state_reachable` FAIL without
even running; `require(v > 100)` → synthesised arg `101` and a concrete PASS;
a removed guard yields a fuzz DIVERGENCE_FOUND while identical versions do not.
**Met** (19 passed; real WSL forge for the end-to-end cases).

## Phase 6 — composability + the end-to-end pipeline (done, 2026-08-28)

- `nextgen/composability.py` (§13) — structural
  ASSUMPTION → ACTUAL BEHAVIOUR → MISMATCH from how an external call's return
  is consumed: an unchecked `latestAnswer()` assumes price freshness; an
  ignored `latestRoundData().updatedAt` assumes the round is current;
  `getReserves` / `getAmountsOut` used as a valuation assumes spot == fair
  value; `balanceOf(address(this))` as accounting truth assumes no direct
  transfers / rebasing; an unchecked `transfer` return assumes it reverts on
  failure. Informational (a report section), never a gate.
- `nextgen/pipeline.py` (§26) — `run(PipelineInputs) → PipelineResult`. Runs
  every phase's analyzer in evidence order, each wrapped so a missing input /
  toolchain / network leaves its gate PENDING and the pipeline continues,
  then `state.classify` → verdict, `proofscore.score` → the §16 tally, and
  `report.render` → the §23 report with the §18 evidence-graph appendix.
  Nothing here decides — the `gates.apply_*` helpers set gates, `classify`
  decides (spec §22).

**Acceptance check (Phase 6):**
`python -m pytest tests/test_nextgen_composability.py tests/test_nextgen_pipeline.py -q`
passes, and includes: a genuine offline removal → verdict UNKNOWN with
`regression_commit` / `security_invariant` / `reachable_path` /
`no_compensating_control` (and, with forge, `reproducer` / `invariant_violated`)
all PASS; a renamed modifier → REJECTED; a still-present guard → REJECTED on
`regression_commit`; a garbage source → still a classified result, not a raise.

---

## Counterfactual Protocol Twin (trace-driven; separate 10-phase build)

A complement to the source/git-history pipeline above: reason from REAL
ON-CHAIN BEHAVIOUR, not code. Architecture (user-supplied):

    1 collect      real txs for an address (calldata/sender/value/block/order/
                   success/logs/token transfers/proxy impl; deep call traces +
                   state diffs by RE-EXECUTING on a local Anvil fork, not a
                   paid trace RPC)
    2 fingerprint  per function: accepted vs rejected inputs, callers, state
                   transitions, asset flows, events, cross-contract calls
    3 boundaries   MINE conservation / authorization / accounting / state-
                   machine / replay / collateral / withdrawal / oracle-freshness
                   / governance constraints from behaviour. Inference != proof.
    4 diverge      compare fingerprints + boundaries across impl versions
    5 mutate       counterfactual variants of REAL traces (actor sub, boundary
                   values, repetition, reorder, delay, callback insert, state
                   timing, oracle state, permission change, cross-contract call
                   variation); prioritised near changed code
    6 replay       execute candidates in an isolated Anvil fork at exact
                   historical state; never broadcast
    7 check        invariant violation / unauthorized transition / asset
                   conservation / unexpected balance gain / loss / unexpected
                   success / revert-boundary bypass
    8 minimize     smallest real tx sequence that reproduces it
    9 provenance   git → build → bytecode → impl → proxy → live (reuses
                   nextgen/provenance + deployment)
    10 validate    independent Hunter / Skeptic / Reproducer (reuses
                   nextgen/adversarial). Only then CONFIRMED; else REJECTED /
                   UNKNOWN.

Delivery: 3 phased commits under `src/nextgen/twin/`.

### Twin commit 1/3 — model + Phase 1 + Anvil + Phase 2 (done, 2026-08-28, `18907d6`)

- `twin/rpc.py` — stdlib JSON-RPC (reads, batching, feature probe, anvil-only
  helpers). `twin/model.py` — the record types. `twin/collect.py` (Phase 1) —
  `alchemy_getAssetTransfers` → else `eth_getLogs` → optional deep block scan;
  decodes ERC-20/721/1155 transfers; samples EIP-1967 impl to spot upgrades.
  `twin/enrich.py` — deep traces via **local Anvil re-execution** (one fork per
  span window, snapshot/revert per tx, callTracer + prestateTracer diff).
  `twin/fingerprint.py` (Phase 2) — per-selector behavioural aggregate;
  `caller_exclusive` surfaces a candidate authorization boundary.
- `execground/foundry.AnvilFork` — isolated fork lifecycle. **The Alchemy
  gotcha**: `anvil --fork-url` probes the upstream with `anvil_nodeInfo` /
  `anvil_metadata`, Alchemy's proxy answers HTTP 400, anvil aborts. Fix: an
  embedded JSON-RPC shim (`_RPC_SHIM` in foundry.py) run in WSL that returns
  `-32601` for those two methods and forwards the rest (with retry). anvil
  forks against `http://127.0.0.1:<shim>`; a persistent `wsl.exe` launcher with
  an EXIT `trap` keeps it alive (`--exec` reaps `nohup`'d children on return);
  Windows reaches anvil at `127.0.0.1:<port>` via WSL2 localhost forwarding.

**Acceptance check (Twin 1/3):**
`python -m pytest tests/test_nextgen_twin_model.py tests/test_nextgen_twin_collect.py tests/test_nextgen_twin_anvil.py -q`
→ 15 passed (2 anvil-gated). Live-verified: 80 WETH txs collected + fingerprinted;
AnvilFork up/serve/down in ~10s; a real router tx re-executed to a depth-8 call
tree with 41 external calls, 11 state-diff addresses, 12 transfers.

### Twin commit 2/3 — Phases 3–5 (done, 2026-08-28)

- `twin/boundaries.py` (Phase 3) — `mine_boundaries(fingerprints, transfers,
  traces)`: independent miners for all nine boundary kinds. AUTHORIZATION
  from `caller_exclusive`; CONSERVATION from one-sided transfer shape;
  ACCOUNTING from a storage slot written on every call that also moves a
  token; REPLAY_PROTECTION from a slot that writes a distinct value on every
  sampled call; STATE_MACHINE from a selector that both succeeds and reverts
  for the SAME caller (rules out authorization as the explanation);
  ORACLE_FRESHNESS from a Chainlink-shaped external staticcall (stays
  INFERRED forever — staleness itself is not observable from a call trace);
  GOVERNANCE from one caller set gatekeeping MULTIPLE distinct selectors, a
  stronger signal than any single AUTHORIZATION boundary; COLLATERAL /
  WITHDRAWAL from outflow-plus-storage-write shape. `Boundary` (already
  scaffolded in commit 1/3, same INFERRED→TESTED→VALIDATED lifecycle as
  `invariants.CandidateInvariant`) is the return type directly — a thin
  `to_candidate_invariant()` bridge was considered and NOT built, since
  nothing downstream (Phase 9/10 wiring) needed the Twin's own boundaries to
  pass through the source-pipeline's invariant machinery; `source=SOURCE_TRACE`
  stays defined in `model.py` for a future caller that does.
- `twin/diverge.py` (Phase 4) — `compare_versions(fp_old, fp_new, b_old, b_new,
  old_ref=, new_ref=)` → accept↔reject flips, asset-flow shape changes,
  external-call target changes, and boundary divergence (a TESTED+ boundary
  present on the old side with no counterpart on the new one = weakening; an
  AUTHORIZATION caller set that strictly WIDENED = its own divergence kind).
  Wired into the orchestrator: `Collection.upgrades` gives the split block: a
  second `collect()` call over a bounded pre-upgrade window, fingerprinted and
  mined the same way, feeds `compare_versions` automatically when an
  implementation change was observed in the sample.
- `twin/mutate.py` (Phase 5) — `generate_mutations(tx, trace, ctx,
  changed_selectors)` → every kind fires independently; two are honestly
  weaker approximations, documented in the module rather than hidden:
  CALLBACK_INSERT re-issues the same call immediately after itself (no
  contract-deploy step exists to stage a real callback contract) and
  PERMISSION_CHANGE/CROSS_CONTRACT_VARIATION can only touch what a local fork
  actually exposes without an ABI — the standardised EIP-1967 admin slot, an
  ETH balance — not an arbitrary dependency's own storage layout.
  ORACLE_STATE is the one worth calling out as genuinely real, not an
  approximation: a forked oracle's own `updatedAt` does not advance with the
  fork's local clock, so jumping the fork's time forward reproduces a stale
  read exactly as it would happen for real.

**Acceptance check (Twin 2/3):**
`python -m pytest tests/test_nextgen_twin_boundaries.py tests/test_nextgen_twin_diverge.py tests/test_nextgen_twin_mutate.py -q`
→ 39 passed, all pure (no network/fork needed for Phases 3–5's own logic).

### Twin commit 3/3 — Phases 6–10 + orchestrator (done, 2026-08-28)

- `twin/replay.py` (Phase 6) — `replay(fork_rpc, mutation) → ReplayResult`:
  applies `state_overrides` via `anvil_setStorageAt`, a `delay_seconds` via
  `evm_increaseTime`, impersonates every sender in `mutation.calls`, submits
  each via the LOCAL fork's `eth_sendTransaction` (never signed, never
  broadcast), and reads back the receipt + `debug_trace_call_tree` +
  prestate diff + before/after balances for every address the calls touch.
  Reuses `enrich.py`'s own tracer parsers so a replayed trace is
  structurally identical to an enriched Phase-1 one. Phase 8 —
  `minimize_calls(mutation, verify)`: the SAME delta-debugging algorithm as
  `execground/sequences.minimize`, reimplemented (not literally called) to
  operate on a `Mutation`'s real `calls` list rather than generated
  Foundry-test source — the two pipelines replay through genuinely different
  mechanisms (a live RPC fork vs. a compiled `forge test`), so the shared
  thing is the ddmin ALGORITHM, stated as such in the module docstring
  rather than forced into a shared function signature that would not fit.
- `twin/checks.py` (Phase 7) — `check_violations(baseline_trace,
  replay_result, boundaries) → list[Violation]`: six independent, deliberately
  conservative checks, each needing a CONCRETE signal (a replay succeeded
  where a TESTED boundary predicted a revert, a balance moved in the
  disallowed direction) — never "this differs from baseline" alone.
  Authorization bypass, a net ETH gain for the calling address, a net ETH
  loss for the target, an unexpected success against a TESTED
  state-machine/oracle/conservation boundary, a replay-guard bypass, and a
  doubled one-sided outflow from a same-tx repetition.
- `twin/twin.py` — `CounterfactualTwin(address, rpc_url, from_block,
  to_block).run() → TwinResult`, wiring Phases 1–10. Phase 9 calls BOTH
  `deployment.run(address, vulnerable_impl=<impl at the violating replay's
  fork block>)` (CAN reach PASS — the Twin always has a live address) and
  `provenance.run(address, local_runtime_hex=None, commit=None)` (deliberately,
  honestly, always reports INCOMPLETE — the Twin never reads a git commit or
  compiles source, so it structurally cannot claim a commit-level bytecode
  match the way the source pipeline does; calling it anyway states that gap
  in the record rather than skipping it). Phase 10: `adversarial.skeptic.sweep`
  fed the Phase 9 facts, and a blinded `adversarial.reproducer.attempt` whose
  `runner` independently replays the MINIMISED mutation on a completely fresh
  fork and re-checks for the same violation KIND — genuinely blind to the
  Hunter-side reasoning, not a re-run of the same call. Verdict rule (stated
  directly in `twin.py`, not routed through `nextgen/state.classify` — see
  the module's own docstring for why): CONFIRMED only if a violation
  reproduced on the fork AND the vulnerable implementation is still what is
  currently live AND the Skeptic did not disprove it AND the blinded replay
  agrees; the Skeptic disproving something, the implementation no longer
  being live, or the blinded replay disagreeing are each independently
  REJECTED; anything else (most commonly: no violation found in the sampled
  budget, or validation could not complete) is UNKNOWN, never silently
  promoted. `chainwatch.py --twin <address> --blocks lo:hi` added.

**Acceptance check (Twin 3/3):** see the resume file (HANDOFF.md) for the
exact command and pass count this arc closed with — full suite plus a real,
live end-to-end `CounterfactualTwin.run()` against a real address.
