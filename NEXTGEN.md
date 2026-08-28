# Chainwatch — Next-Generation Security Regression & Proof Engine

> This file is the roadmap for the upgrade begun 2026-08-28. It does **not**
> replace `CHARTER.md`. The classic pipeline (`src/scan.py` → `src/verdict.py`
> → three verdicts, six evidence fields) is unchanged and stays the default.
> Everything here is **additive**, lives under `src/nextgen/`, and is reached
> only behind an explicit flag.

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
| 4  | Attack-path graph | `nextgen/attackgraph.py` | planned (Phase 3) |
| 5  | Stateful multi-transaction reasoning | `nextgen/execground/sequences.py` | planned (Phase 5) |
| 6  | Symbolic + concrete hybrid validation | `nextgen/execground/hybrid.py` | planned (Phase 5) |
| 7  | Adversarial false-positive killer | `nextgen/adversarial/hunter.py`, `skeptic.py` | planned (Phase 4) |
| 8  | Three-agent independent validation | `nextgen/adversarial/reproducer.py` *(extends `agent/`)* | planned (Phase 4) |
| 9  | Git → build → bytecode → deployment provenance | `nextgen/provenance.py` *(extends `liveness.py`, `verified.py`)* | planned (Phase 3) |
| 10 | Deployment-aware security | `nextgen/deployment.py` *(extends `liveness.py`)* | planned (Phase 3) |
| 11 | Compensating-control analysis | `nextgen/compensating.py` *(deepens evidence field 5)* | planned (Phase 3) |
| 12 | Cross-contract security regressions | `nextgen/attackgraph.py` (protocol graph) | planned (Phase 3) |
| 13 | Cross-protocol / composability analysis | `nextgen/composability.py` | planned (Phase 3, best-effort) |
| 14 | Economic exploitability engine | `nextgen/execground/economics.py` | planned (Phase 5) |
| 15 | Automatic minimal PoC generation | `nextgen/execground/reproducer.py` | planned (Phase 5) |
| 16 | Proof quality score | `nextgen/proofscore.py` | **wip (Phase 0)** |
| 17 | Finding state machine | `nextgen/state.py` | **wip (Phase 0)** |
| 18 | Security evidence graph | `nextgen/evidence_graph.py` | **wip (Phase 0)** |
| 19 | Compiler / build-environment security | `nextgen/buildenv.py` *(extends `history.py`, `verified.py`)* | **done (Phase 1)** |
| 20 | Known-exploit replay benchmark | `nextgen/benchmark/` *(extends `backtest.py`)* | planned (Phase 4) |
| 21 | Regression fuzzing | `nextgen/execground/regfuzz.py` | planned (Phase 5) |
| 22 | Do not trust the LLM | architecture-wide; enforced by `proofscore` hard gates + `state` | **wip (Phase 0)** |
| 23 | Reporting mode | `nextgen/report.py` *(extends `agent/templates.py`)* | planned (Phase 4) |
| 24 | `UNKNOWN` security regression | `nextgen/state.py` (`UNKNOWN` outcome) | **wip (Phase 0)** |
| 25 | Core principle | this file + `proofscore` hard gates | **wip (Phase 0)** |
| 26 | Final architecture | integration target — see the diagram in the spec | ongoing |
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
