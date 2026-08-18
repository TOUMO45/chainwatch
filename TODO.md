# Deferred (documented in LIMITATIONS.md, not yet fixed)

## PHASE 6 (2026-08-15) — engine became a product

What shipped, each with the command whose raw output was read:

| | Gate | Result |
|---|---|---|
| 14 frozen fixture sets | `scorer.py --fixtures <set>` ×14 | 14/14 PASS, per-rule TP/FP/FN **byte-identical** before and after every change below |
| attribution contract | `pytest tests/test_attribution.py` | 14/14 — every fire attributable, every quiet rule silent |
| verdict model | `pytest tests/test_verdict.py` | 11/11 |
| real repo, 0 FP | `pytest tests/test_realworld_reserve.py` | **3/3 in 18m** — 4/4 pairs analysed, five fixed FPs quiet, the one true positive still fires |
| trajectory-mode file comparisons | live Reserve walk, 4 pairs | 8/8 comparisons OK, **0 rule errors** (was 6 errored comparisons per rule on the same window, all 3 Curve\* root-relative-import files — see the correction note below) |
| end-to-end product path | web app on a seeded repo | 2/2 regressions found, attributed to function + line + commit, verdicts correct |
| RC-AST1 fixture is genuine | `fixtures-r3c-ast1` against **pre-fix** `_storage.py`/`rule3c.py` in a throwaway worktree | pre-fix **FAIL**, precision 0.67 (`N3c-ast1-01` fires); post-fix **PASS**, precision 1.00 |

**CORRECTION (recorded, not quietly edited).** An earlier version of this table
claimed "Rule 3c in trajectory mode: 42/42 errors -> 0 errors". That pairing was
wrong and is retracted. The 42/42 figure is a pre-existing entry describing a
DIFFERENT, larger run — HIST-L1's 29-pair / 46-file-comparison window — and it
was paired with a 4-pair, 8-file measurement from PHASE 6, which is not the same
workload. The measured figure for the 4-pair window is **6 errored comparisons,
identical for all nine rules** (3 Curve\* files x 2 pairs), recorded in
`.walker-out.json` / `-v2` / `-v3`. Those errors are the root-relative-import
failure (HIST-L1 residual), not a Rule 3c defect: Rule 3c completed 12 of its 18
comparisons on that window and correctly fired on FP5 before the RC-AST1 fix.
See LIMITATIONS.md §WALK-L2 for what this means for that finding's status.

New surface: `src/scan.py` (the one pipeline), `chainwatch.py` (CLI, CHARTER
success criterion 4), `webapp/` (FastAPI + SSE + UI), `src/verdict.py` (X-L1),
`tests/`.

### Open after PHASE 6

- [x] **CHARTER success criterion 6 — CLOSED AS A SCOPE FINDING, not as a pass.**
      See SUBMISSION-NOTES.md. Criterion #6 as literally written is
      unsatisfiable within responsible-disclosure constraints: CONFIRMED needs
      `liveness == LIVE`, a live unfixed regression is an undisclosed
      vulnerability on a funded contract, and every responsibly-publishable
      target is already patched (therefore PATCHED, therefore CANDIDATE). Five
      disclosed-incident candidates were searched and each rejected with a
      reason (Sense Finance, OZ TimelockController, Audius, 88mph, Nomad). The
      real-world demonstration is Reserve `ActFacet.revenueOverview` at
      `e27227b2` — real repo, real commit, same-name/same-signature control
      removal, attributed to lines 117-118 — which caps at CANDIDATE because
      evidence field 4 requires externally-callable AND state-changing and the
      function is a view. The capability is proven (capability 11 returns LIVE
      on real mainnet bytecode); what is missing is an appropriate target.
- [ ] Liveness is attached per (file, contract) by compiling the HEAD version of
      the finding's contract and comparing to the deployed implementation.
      Per 11-R3 a mismatch returns UNKNOWN rather than PATCHED, so on most real
      repos this will refuse to conclude. Measure the UNKNOWN rate on a real
      target before claiming the gate is usable end-to-end.
- [ ] `walker.py` is superseded by `src/scan.py` (same worktree/env machinery,
      plus attribution, verdicts, coverage and HEAD-survival). Kept as-is
      because PHASE 3-5 provenance in LIMITATIONS.md refers to its output
      format. Decide whether to retire it or reduce it to a thin wrapper.
- [ ] The web app runs one scan at a time, has no authentication, and binds to
      127.0.0.1. That is the correct posture for a local research tool; any
      change to it needs an explicit threat model first, because starting a
      scan installs a target repository's dependencies.

## Phase 3 / PHASE 5 (Reserve FP loop) — status

**PHASE 5 live result (2026-08-15), all four pairs re-run against
`realworld-test/reserve-src` under current HEAD, after the WALK-L1 cache
defect was fixed:**

| FP | pair | result |
|---|---|---|
| FP1/FP2 | `43533959..b2cfd51a` | 0 fires — DESIGN-L2 confirmed live |
| FP4 | `f43202a3..e27227b2` | AllowanceLib phantom gone — DESIGN-L2 confirmed live |
| FP3 | `f43202a3..e27227b2` | 1 fire, Rule 5, ActFacet.sol — **TRUE POSITIVE**, not an FP |
| FP5 | `cef2f655..7f65c030` | 0 fires — R5-L1 + RC-AST1 confirmed live |
| FP6 | `6481e75d..92ff272f` | 0 fires — RC-ROLE confirmed live |

Five of the six original false positives are eliminated and re-measured on the
real repository. The sixth (FP3) was never a false positive: it is a genuine
`try/catch` removal around `reg.assets[i].price()` in `ActFacet.sol`, which
LIMITATIONS.md already classified as "a true trigger with wrong severity per
RULES.md 5.3". **This run also recovers FP3's commit hash (`e27227b2`), which
was never recorded anywhere** — the reason it was previously unrunnable.

- [x] **RC-5 — NOT the FP6 mechanism; FP6's real cause found and fixed.** An
      earlier entry here claimed RC-5 was a "confirmed mislabel" on the
      strength of a walker run that WALK-L1 had corrupted; that claim was
      retracted. The corrected run showed FP6 still firing, and the real cause
      is RC-ROLE (role-based gate invisible to STEP 4's equality-only
      discriminator). The FP6 diff contains no rename — `cast` is DELETED and
      folded into `supported` — so the literal RC-5 mechanism is still not what
      drove it. The rename mechanism remains **empirically unobserved**;
      Rules 2b/4/5 do key by `canonical_name` across commits, so it stays
      plausible and unproven. A future real-repo hit is a NEW finding under a
      new label, not RC-5. Full provenance chain: LIMITATIONS.md, DESIGN-L2 §.

- [x] **RC-ROLE — Rule 2b admin-gate missed role-based access control.**
      FIXED. `_admin_gated` in rule2b.py now accepts an authority call (takes
      msg.sender, returns bool) alongside the `msg.sender == <state addr>`
      equality form. The bool-return restriction is measured-necessary:
      without it `balanceOf(msg.sender)` guards are misread as access control
      and genuine re-entrancy goes silent. Locked by `fixtures-r2b-role/`
      (N2b-role-01 quiet / P2b-role-01 fires, 1.00/1.00). Live: FP6 quiet.
      See LIMITATIONS.md §RC-ROLE — including the finding that STEP 4's
      fixture reproduced castSpell's shape but not its mechanism, which is how
      a green gate shipped an unfixed real case.

- [x] **RC-AST1 — Rule 3c astId-in-type-string phantom fire.** FIXED via
      `canonical_type()` in `_storage.py`, applied at both rule3c comparison
      sites. Locked by `fixtures-r3c-ast1/` (3 cases, 1.00/1.00) including an
      over-strip guard proving array LENGTHS are not stripped. Live: FP5 quiet.
      See LIMITATIONS.md §RC-AST1.

- [x] **WALK-L1 — path-keyed caches replayed the previous commit's analysis.**
      FIXED via `reset_caches()` in `_shared`/`_storage`, called by walker.py
      after every checkout. This defect produced a FALSE CONCLUSION that was
      committed to LIMITATIONS.md before being caught; both the defect and the
      retraction are recorded there. See LIMITATIONS.md §WALK-L1.

- [x] **FP3 severity question — ANSWERED BY THE VERDICT MODEL, no special case
      needed (PHASE 6).** Rule 5 correctly fires on the `try/catch` removal in
      `ActFacet.sol` at `e27227b2`. The open question was severity: should a
      try/catch removal on a non-state-changing view be CONFIRMED or CANDIDATE?

      With attribution and `src/verdict.py` in place the question resolves
      itself. The live run now reports:

          CANDIDATE rule 5  contracts/facade/facets/ActFacet.sol
                            ActFacet.revenueOverview  line 117  range 117-118
            try/catch removed around the high call to .price();
            a failure now passes silently
            evidence: visibility_after=external, writes_state_after=FALSE
            why not confirmed: missing evidence: reachability, liveness

      Required evidence field 4 is "externally callable **and** state-changing".
      `revenueOverview` is external but writes no state, so field 4 is not
      established and the finding caps at CANDIDATE — which is exactly the
      severity a facade view helper deserves, reached mechanically rather than
      by a hand-written exception. **No rule change, and no new fixture, is
      needed.** The general principle now holds for every rule: a regression on
      a read-only function can never reach CONFIRMED.

- [x] Cosmetic: Rule 5's attribution reuses its cross-commit matching key as
      the human-facing destination, so an unresolved dynamic target prints as
      `other:REF_61`. The key itself must not change (it is what R5-L1's
      injectivity fix depends on); add a separate display label that says
      "an unresolved destination" instead of leaking a Slither temporary name.
      **DONE** — `_dest_label()` formats for the report only; the raw key is
      still carried as `destination_key` in the evidence, and the matching key
      is untouched.

- [x] **STEP 5 — RC-OZ5-R6: fix Rule 6 false-fire on OZ5 assembly-assigned
      namespace pointers.** DONE (commit 924ff41): fixed in rule6.py via the
      `_is_storage_struct_pointer_local()` gate, locked by `fixtures-r6-oz5/`
      (N6-oz5-01 quiet / P6-oz5-01 fires, 1.00/1.00), and the original symptom
      fixture `fixtures-ext/N3b-ratelimit-oz5` cleared. Original plan retained
      below for provenance. Ordered AFTER Reserve STEPS 2/3/4 (DESIGN-L2,
      RC-2 R5-L1, RC-4 Rule 2b castSpell class), because it does not touch
      the same rules or the walker. Mechanism, evidence and fix direction
      recorded in LIMITATIONS.md under `RC-OZ5-R6`. Prerequisites:
      - Build a dedicated `fixtures-r6-oz5/` set FIRST (fixtures-first
        discipline).
        - **Negative:** function whose removed guard reads only
          `block.timestamp` and a namespaced state member reached via an
          assembly-assigned `$` pointer, verifiably parameter-INDEPENDENT.
          Expected: quiet after the fix (currently fires).
        - **Paired positive:** function whose removed guard genuinely reads
          the parameter through the same namespace-pointer indirection.
          Expected: fires both before and after the fix, so the fix cannot
          pass by blanket-silencing the namespace-pointer shape.
      - Do NOT rely on `fixtures-ext/negative/N3b-ratelimit-oz5` doubling
        as this fixture — it was built to test Rule 3b's rate-limit
        discriminator and is scored under Rule 3b, not Rule 6.
      - Fix in `rule6.py` (and possibly `_shared`'s data-dependency helper):
        require a real read path from the guard's condition to the parameter
        (the parameter itself, or a direct-storage read of a state variable
        the parameter was written into) before accepting Slither's
        `is_dependent` verdict; treat a sole hit through an assembly-assigned
        local as inconclusive.
      - Verify: fixtures-r6-oz5 goes negative→quiet / positive→fires; all
        frozen fixture sets (including `fixtures-r6` and OZ 4 rate-limit
        fixture `fixtures-ext/N3b-ratelimit-oz4`) still 1.00 / 1.00; the
        pre-existing `fixtures-ext/N3b-ratelimit-oz5` Rule 6 fire clears.

## Walker known limitations

Deferred surface issues in `walker.py` / `src/history.py` that surfaced during
PHASE 5 (2026-08-15). Both are trajectory-mode-only; scorer harness and
frozen fixtures unaffected. Do not fix without measurement first.

- [x] `derive_remaps` doesn't emit self-mapping for absolute-repo-path imports
      (e.g. `import "contracts/interfaces/IAsset.sol"`) — causes `SlitherError`
      on any changed file importing this way. Affects 3 Curve* files in
      Reserve's FP1/FP2/FP4 pairs (did not change those FPs' verdicts, all
      target files unaffected).
      **FIXED (PHASE 6).** `derive_remaps` now falls through to a self-mapping
      `<dir>/=<root>/<dir>/` when a non-relative import prefix names a
      directory that exists in the checkout but in neither `node_modules/` nor
      `lib/`. Emitted only when the directory is really there, so it cannot
      mask a genuinely missing dependency.

- [ ] `rule3c.py`'s solc invocation (`_storage.py`) does not honor walker's
      `SOLC_VERSION` env var, falls back to ambient PATH solc (0.7.6) instead
      of the pinned 0.8.28. Same 3 Curve* files affected. Root-cause + fix
      needed before walker is trusted on repos with mixed pragma files.
      **STILL OPEN — the PHASE 6 entry that closed this is RETRACTED.**
      PHASE 6 rewrote the solc invocation (`_root_and_remaps`, per-checkout
      `cwd`/`--allow-paths`/remaps — see LIMITATIONS.md §WALK-L2/§WALK-L3) and
      claimed this item as fixed on the strength of a "42/42 errors -> 0 errors"
      measurement. That measurement was a mispairing of two different runs and
      has been retracted; see the correction note at the top of this file.
      What is actually established:
      - `SOLC_VERSION` *is* inherited (`env = dict(os.environ)` copies it), so
        the literal wording of the original entry was wrong.
      - The 6 errored comparisons on the 4-pair window were the root-relative
        import failure, affecting **all nine rules identically** — not a Rule 3c
        or solc-version problem.
      - **RESOLVED BY MEASUREMENT (88mph run, 2026-08-15).** The symptom is now
        reproducible, and the mechanism is neither SOLC_VERSION propagation nor
        a cwd problem. `solc 0.5.17 --combined-json storage-layout` returns
        `Invalid option to --combined-json: storage-layout` — **that compiler
        has no storage-layout output at all** (`solc --help` lists none). The
        first attempt therefore fails for a reason that has nothing to do with
        versions, execution falls into `solc_candidates`' retry loop, and the
        ranking tries 0.7.6 LAST — so `proc` holds 0.7.6's pragma complaint and
        the human is shown "current compiler is 0.7.6". **The "falls back to
        ambient 0.7.6" report was the retry loop's last attempt, exactly as
        WALK-L2 predicted for a different failure.** Third instance in this
        project of a fallback impersonating a root cause.
      - Consequence, and it is a real limitation rather than a bug: **Rule 3c
        has a compiler floor.** It cannot run on any commit pinned below the
        solc version that first supports `--combined-json storage-layout`. On
        such commits it must report UNSUPPORTED, not error — today it raises,
        which costs the whole file's coverage accounting (the 88mph run reports
        `files 0/1` even though eight rules produced verdicts). Fix direction:
        detect the unsupported option and return a distinct "not applicable at
        this compiler version" signal.
      - Still unexplained: the original **42/42** figure. This measurement does
        not account for it (that window was solc 0.8.x, where the option
        exists). Re-running the HIST-L1 29-pair window is still the way to
        settle what that number described.

## Older deferred items

- [ ] 3a-L2 — widen Rule 3a trigger from "constraint removed" to "caller set
      widened." Needs fixture: onlyOwner → require(msg.sender == mutablePublicVar).
      Real regression shape, currently invisible.
- [x] X-L1 — implement verdict.py three-state model (DISCARDED/CANDIDATE/CONFIRMED).
      Convert 3a.1 and 2.10 from silent discard to CANDIDATE.
      **DONE (PHASE 6).** `src/verdict.py` classifies mechanically: all six
      required evidence fields present AND liveness LIVE -> CONFIRMED, else
      CANDIDATE with every downgrade reason recorded and surfaced. 2.10 and 5.3
      already returned the string `"candidate"` from their rules; that ceiling
      is now carried through the model as `severity_hint` and can never be
      raised by the classifier. Consequence, stated in README and in the UI: a
      repo-only scan with no `--address` yields zero CONFIRMED findings,
      because liveness is one of the six.
- [ ] 3x-L1 — segment-based test/mock path matching (currently substring).
      `latest/`, `contest/`, `greatest/`, `protests/` are all silently skipped
      today. Match a directory named exactly test/tests/mock/mocks/script, or a
      filename `*.t.sol` / `*Mock*` / `*Harness*`. Silent FN across 3a/3b/3c.
- [ ] 3x-L3 — detect ERC-7201 init machinery structurally: a modifier reading a
      constant namespace slot and writing through an assembly pointer, so
      Signal A (defines_init_machinery) works on OZ 5. Today Rules 3b and 3c
      CANNOT FIRE AT ALL on any OZ 5.x project — proven with synthetic
      regressions matching P3b-01/P3b-02 and P3c-01. This is the unlock for
      full OZ 5 support (3b + 3c), and pairs with the deferred 3c-v2 slot
      comparator. Highest-value deferred item.
- [ ] 3x-L2 — pre-screen must check OZ import paths, not just storage style.
      Sequential storage does not imply OZ 4.x; Monetrix uses OZ 5 paths
      (utils/ not security/) with sequential storage. Cost this time: 4 of 20
      files unmeasured, including MonetrixVault.
- [ ] 3c-oz5-L1 — build an OZ 5 __gap fixture, THEN implement exclusion 3c.2
      for the namespaced-struct path. Fixture first: shipping an untested
      exclusion trades a false positive for a silent false negative. Today,
      shrinking a __gap inside an ERC-7201 struct fires as an FP. Exposure low
      (per-contract namespacing reduces gap usage) but real.
- [ ] 3c-oz5-L2 — handle hybrid contracts holding BOTH declared state variables
      and a namespaced struct. Mode selection keys on whether solc's layout is
      empty, so a hybrid takes the OZ 4 path and its namespaced struct is never
      compared. Fix: run both comparators when a namespaced struct is present
      rather than treating the modes as mutually exclusive.
- [ ] 3b-L-ratelimit — add a discriminator separating set-once init flags from
      per-call rate-limit writes. Today gate-on-and-write-same-var matches both,
      so MonetrixVault.keeperBridge (block.timestamp rate limit) is classified
      as init-guarded; removing such a require would be reported as an
      initializer regression — a mislabeled finding. Affects OZ4 AND OZ5 paths.
      Needs a rate-limit negative fixture first (N3b: function with a
      block.timestamp rate-limit guard, must NOT fire).
- [ ] 3c-oz5-realworld-gap — find a real protocol using ERC-7201 namespaced
      storage in its OWN contracts and run the 3c OZ5 comparator against it.
      Monetrix did not exercise that path at all (all contracts took OZ4 mode),
      so the comparator is fixture-validated only.
- [ ] Rule 6 (input validation) — when built, ensure removal of a
      set-once-address guard (VaultAlreadySet-style: `if (x != address(0))
      revert; x = arg`) is covered there. It was deliberately excluded from
      Rule 3b by the 3b-L-ratelimit constant-write discriminator, since a
      set-once setter is configuration, not SC10 proxy initialization. Needs a
      positive fixture: a set-once-address guard removed across a commit.
- [ ] DESIGN-L1 — when building Rules 5/6 (both diff-based), apply the
      canonical_name rule for ANY cross-commit set operation: `before.sol` and
      `after.sol` are separate Slither compilations, so StateVariable/Function
      objects are distinct instances and identity-based set ops never cancel
      shared entities (this fired Rule 2b's N2b-02 as a false positive). Diff by
      `canonical_name`, keep same-compilation objects only for within-commit
      intersections. Add a guard/test that an entity present in both commits
      cancels. See DESIGN-L1 in LIMITATIONS.md.
- [ ] Rule 2b 2.9 sub-case — a var moved after the call but read back only by a
      DIFFERENT state-changing function (not this function's own guard, not a
      view) currently routes to quiet. No fixture exercises it; the choice is
      precision-safe (a miss, not a false alarm). Revisit — extend the
      re-entry-path read set to all external entry points — if a real case
      appears.
- [ ] Rule 6 exclusion 6.4 (type-change makes the check redundant, e.g.
      `uint256` → `uint8` bounding a range) — not implemented, no fixture. A
      parameter-guard loss on such a narrowed type would currently fire as a
      false positive. Build fixture + logic if a real case appears; shipping an
      untested exclusion trades an FP for a silent FN.
- [ ] Rule 6 exclusion 6.6 (enforced by the type system / a validated struct at
      the call boundary) — not implemented, no fixture. Same posture as 6.4:
      build the fixture first, then the logic, if a real case appears.
- [ ] HIST-L1 mitigation option A — AST-only mode. **Superseded by measurement;
      see AST-MODE in LIMITATIONS.md.** Measured outcome: 8 of 9 rule ids
      (1, 2a, 2b, 3a, 3b, 4, 5, 6) give IDENTICAL verdicts on AST-only parse
      across 621 comparisons; only 3c is full-compile-only (it needs
      `solc --combined-json storage-layout`, a separate non-AST artifact).
      BUT it does **not** mitigate HIST-L1: solc still resolves every import to
      emit an AST, so a missing dependency tree still fails with `ParserError`.
      Build it for speed (~21%) and codegen-failure immunity, NOT for coverage.
- [ ] Implement the AST-only execution path, selectable per run, for the 8
      AST-only-capable rule ids, falling back to full-compile for 3c (and for
      any future rule needing a non-AST solc artifact). Trajectory output must
      LABEL each finding with the mode it was detected in (ast-only vs
      full-compile) so a reader can see the confidence basis of every finding.
      Note the labels carry equal weight on the frozen sets — verdicts were
      measured identical — so the label documents provenance, not reliability.
- [x] HIST-L1 mitigation option B — per-commit environment reconstruction.
      **DONE, MEASURED.** Implemented in `src/history.py`; reserve-protocol's
      failing window went **0/29 -> 28/29 analyzable** (28/28 of comparable
      pairs), 43/46 file comparisons, 387 rule executions, 13.0 min wall clock.
      Cache keyed on the resolved dependency set (lockfiles + package.json +
      foundry.toml + .gitmodules + remappings.txt + solc pin), so the window's
      single distinct yarn.lock cost ONE install (2m09s) and every later commit
      was a zero-cost cache hit. Compiler pins resolved themselves via the
      framework build (solc 0.8.28 + 0.6.12 in one build). See HIST-L1.
- [x] **DONE (PHASE 6) for the ratio half; the precision half stays open.**
      `src/scan.py` carries a `Coverage` record through every scan
      (pairs total / analyzed / skipped with a per-skip reason, plus file
      comparisons ok/error), `chainwatch.py` prints it ABOVE the findings, and
      the web UI renders it above the findings table with an explicit
      "unmeasured, not safe" warning whenever coverage is partial.
      `tests/test_realworld_reserve.py` asserts coverage first, so a quiet
      real-repo result cannot pass the suite by having analysed nothing. What
      is NOT yet automated is the VERIFIED PRECISION figure printed beside it —
      that still comes from running the fixture sets and the Reserve
      regression test by hand.
- [ ] HIST-L1 — trajectory output must ALWAYS surface the analyzable/skipped
      pair ratio, with a per-skip reason, so "0 detections" can never be
      mistaken for "clean history". Treat a missing coverage ratio as a broken
      report, not a clean one. This is a reporting invariant, not a nice-to-have
      — it is the same failure mode as 3x-L1, where only timing revealed that a
      confident clean result had analysed nothing. Now that coverage is high,
      the report must carry a VERIFIED PRECISION figure beside it: the Reserve
      run went 0 -> 10 false positives precisely because pairs started
      compiling. Coverage without precision is not trustworthiness.
- [ ] R5-L1 — Rule 5 fires on unchanged code when one function calls the same
      method on the same destination more than once and any one site is inside a
      `try/catch`: the `(kind, destination, method)` key is stable across commits
      but NOT injective within one, so `before_checked` retains the try/catch
      record and every other site matches it. 10 confirmed FPs on Reserve.
      FIXTURE FIRST (the approve-reset idiom, unchanged across commits, must stay
      quiet), then make the within-commit map injective (node id / source offset)
      while keeping the cross-commit key stable. See R5-L1 in LIMITATIONS.md.
- [ ] DESIGN-L2 fix — 8 of 9 rule ids iterate `slither_obj.contracts_derived`
      (the whole compilation, imports included) without a source-file scope. On
      a real repo whose changed file transitively imports an unchanged file
      containing the trigger pattern, the rule fires on the unchanged code and
      attributes the finding to the changed file. Only Rule 4 is scoped
      (`_file_of(contract) != target`); rules 1/2a/2b/3a/3b/3c/5/6 are exposed.
      Confirmed source of FP1/FP2/FP4 on Reserve. Scope every rule's iteration
      to declarations in the commit's changed files - either loop-side (harness
      passes changed_files, filters each rule's findings) or rule-side (per-rule
      `_file_of` filter, symmetric to Rule 4's).
      **MUST be locked by MULTI-FILE fixtures first**: a changed `.sol` that
      imports an unchanged `.sol` carrying the R5 approve-reset pattern (and one
      per other exposed rule). Current single-file fixtures structurally cannot
      exercise closure iteration, which is why DESIGN-L2 shipped past every
      frozen set. Without such fixtures, a future refactor can silently
      reintroduce this exposure. See DESIGN-L2 in LIMITATIONS.md.
- [ ] Trajectory loop pairing — the walker builds pairs from consecutive
      `.sol`-touching commits (`git log -- pathspec`). When a `.sol`-touching
      commit's actual git parent does NOT touch `.sol`, the walker pairs it with
      an older `.sol`-touching commit instead of the true parent. Measured on
      Reserve: 2 of 4 fire commits were mispaired this way (e27227b2's true
      parent is `f43202a3`, walker used `11c03f3f`; 7f65c030's true parent is
      `cef2f655`, walker used `e27227b2`). Fix: for each `.sol`-touching commit,
      pair it with its first git parent regardless of whether that parent
      touched `.sol` (the `.sol` diff is identical either way for linear
      history; for merges use first-parent). Note: this changes coverage
      accounting but did not change any verdict in the observed run — all 6 FPs
      persist under correct pairing, so this fix is precision-neutral for the
      observed cases. Fix it anyway for report correctness.
- [x] HIST-L1 residual — repo-root-relative imports (`contracts/interfaces/…`)
      fail under bare solc because only Hardhat resolves them implicitly from the
      project root. 3 of 46 file comparisons on Reserve. Fix: emit
      `<dir>/=<root>/<dir>/` remaps for top-level source dirs in `derive_remaps`.
      **FIXED (PHASE 6)** — implemented exactly as specified above.
- [ ] Rule 3c cannot run in trajectory mode at all — 42/42 errors on the Reserve
      window. `_storage.storage_layouts` builds paths relative to THIS repo's
      root, so it cannot address a scratch worktree. Make the layout extractor
      take the project root as a parameter.
      **CODE CHANGE SHIPPED, CLAIM RETRACTED.** The extractor now resolves the
      checkout that owns the file and runs solc there with that checkout's own
      remaps (LIMITATIONS.md §WALK-L2/§WALK-L3), and a live 4-pair Reserve walk
      showed 8/8 file comparisons with 0 rule errors. But that does NOT close
      this item, because **the premise was never reproduced**: on the same
      4-pair window BEFORE the change, Rule 3c errored on 6 of 18 comparisons —
      the same 6 every other rule failed — and fired correctly on the other 12.
      "Cannot run at all" is not what that window shows. Either the 42/42 came
      from a different window (most likely HIST-L1's 29-pair run) or from a
      configuration nobody recorded. Stays open until the 42/42 workload is
      re-run and its error text captured. See the correction note at the top of
      this file.
- [ ] HIST-L1 residual — `dep-gone-from-registry` was never exercised (the tested
      window is 2 months old). Older history will hit unpublished/yanked
      transitive deps; measure on a multi-year window before claiming "any repo".
## Open after the 88mph measurement (2026-08-15)

- [ ] **Retry loops must report the FIRST failure, not just the last.**
      `_shared._compile` and `_storage.storage_layouts` both keep only the last
      candidate's error, which has now produced three wrong diagnoses (see
      LIMITATIONS.md §METHODOLOGY). Retain and report both:
      `first attempt (<ambient>): <error>; after N fallbacks (<last>): <error>`.
      Cheap, and it would have prevented all three.
- [ ] **Rule 3c needs a compiler floor, reported as UNSUPPORTED not an error.**
      `--combined-json storage-layout` does not exist below roughly solc 0.6.x;
      on 0.5.17 the rule raises, and one raising rule marks the whole file
      errored in the coverage accounting even when the other eight produced
      verdicts (88mph: `files 0/1` despite 8 rules running). Detect the
      unsupported option and return a distinct not-applicable signal.
- [x] **RC-RENAME1 rule** — DONE (`f8c8a24`). Rule 10, keyed on the contract's
      external surface (T1/T2/T3), locked by `fixtures-r10/` with 1 positive and
      5 negatives — two more than planned: 10.1 and 10.2 are separate code paths
      one fixture cannot lock, and N10-05 locks T2, the condition that keeps the
      rule a REGRESSION detector. Closed empirically on 88mph `a4c48d61`
      (1 finding, CANDIDATE, correctly capped pending liveness). Two design
      assumptions were wrong and were caught by measuring the real parse before
      trusting a fixture: §R10-M1, §R10-M2.
- [ ] Section 1c performance profiling is still not done; the 25-pair stress run
      gives a throughput number to start from once it completes.
- [x] **RC-INLINE2 (2026-08-17) — DONE.** `cei_correct` and rule 2a's evidence
      set both resolve delegated bodies via `_cfg.after_call_writes_resolved`,
      which rule 2b now shares instead of keeping a local copy. Locked by
      `fixtures-r2a-inline/` (1.00/1.00). No real-world case exercises the
      positive direction; P2ai-01 is its only proof, stated in LIMITATIONS.md.
      Original item text follows.
      ~~Original: de-inlining direction, false-negative risk on
      Rule 2a's `cei_correct` (already flagged as residual in RC-INLINE1's Step 1)
      needs its own fixture-first pass, separate from RC-INLINE1's fix.~~

## Open after the Step 5 real-world scans (2026-08-18)

Five false-positive classes found by real-repo contact on Uniswap v3-core,
v3-periphery and Aave v2. All DOCUMENTED with mechanism/evidence/scope/fix-direction in
LIMITATIONS.md and deliberately NOT fixed during the scan run, per the
"log it, keep scanning, fix afterward" discipline. Each needs its own
fixture-first pass.

- [ ] **RC-MUTEX1 — a set/clear reentrancy mutex satisfies
      `is_oneshot_init_guard`. HIGHEST PRIORITY of the four: the helper is
      SHARED and the shape is ubiquitous.** `lock() { require(unlocked == 1);
      unlocked = 0; _; unlocked = 1; }` gates on a flag, writes that flag, and
      writes compile-time constants, so it passes every test the helper
      applies. The `3b-L-ratelimit` discriminator cannot separate it because a
      mutex writes constants in BOTH directions. Missing property is
      MONOTONICITY - an initializer closes its gate permanently, a mutex
      reopens it - and `_cfg.has_setclear_mutex` already detects that shape
      without being consulted.

      **TWO DIRECTIONS, AND THE ONE THAT FIRED IS THE LESS DANGEROUS ONE.
      Both need their own fixture and their own verification; fixing only the
      side that was observed would leave the worse half in place.**

      1. *False POSITIVE, observed.* Rule 3c: `defines_init_machinery` reports
         an immutable CREATE2 contract as proxy-deployed, disabling exclusion
         3c.3, and 3c fires on a contract that can never be upgraded. Measured
         on Uniswap v3-core `76a9ffa6ebc4` (`UniswapV3Pair`), whose emitted
         detail even asserts "on a proxy-deployed contract" - which is false.
      2. *False NEGATIVE, NOT observed, and the more dangerous.* Rule 10:
         `has_init_guard` classifies a writer carrying a mutex as
         one-shot-guarded, exclusion 10.1 matches, and the rule goes SILENT on
         a gate variable whose only protection is a reentrancy mutex - which is
         not initialization protection at all. A miss produces no artifact and
         is indistinguishable from a clean result. Rule 3b's exclusion 3b.4 has
         the same exposure. This direction requires a POSITIVE fixture (gate
         variable, unguarded writer carrying only a mutex, must FIRE), not just
         the 3c negative.

- [ ] **RC-EXTRACT1 — Rule 4 fires when arithmetic is EXTRACTED into a helper.**
      The de-inlining direction of the RC-INLINE family, on a third rule.
      Measured on Aave v2 `20bbae88d399`
      (`UniswapLiquiditySwapAdapter.executeOperation`): `amounts[i].add(...)`
      moved from line 82 of the caller to line 187 of a new `_swapLiquidity`
      helper, so the caller kept its raw loop counter and lost its visible
      SafeMath. Fix direction: evaluate Rule 4 over `reachable(fn)`, as rules
      2a/2b now do via `_cfg.after_call_writes_resolved`. The hard fixture is a
      commit that extracts a helper AND genuinely drops SafeMath inside it,
      which must still fire.

- [ ] **RC-NEWCALL1 — Rule 2b fires when a function gains its FIRST external
      call.** `state_writes_after_calls` returns the empty set by construction
      when there are no call nodes, so every write after the newly-added call
      reads as moved. Measured on v3-periphery `a796106e098c`
      (`NonfungiblePositionManager.permit`, EIP-1271 support added). Fix
      direction: require `fn_b` to have had at least one external call before
      comparing sets - the shape of Rule 10's T2 precondition. Needs both
      directions: no-call-at-N-1 gaining one (quiet), and a genuine reorder
      where both commits already had calls (must still fire).

- [ ] **RC-NEWVAR1 — Rule 2b fires on a state variable introduced at N.** A
      variable absent at N-1 cannot be in the N-1 set, so any write to it is
      unconditionally "moved". Measured on v3-periphery `0239382f49b3`
      (`Quoter.amountOutCached`, transient storage). Fix direction: restrict
      `moved` to variables present in `contract_b.state_variables`.

- [ ] **RC-RENAME2 — a parameter rename reads as a removed require (Rule 6).**
      THE RENAME MECHANISM THIS PROJECT PREDICTED AND HAD NEVER OBSERVED. The
      RC-5 retirement note said it "remains empirically unobserved ... a future
      real-repo hit is a NEW finding under a new label". This is that hit, on
      Rule 6. Measured on v3-periphery `f3ab2f1aa21a`
      (`decreaseLiquidity`: `amount` -> `liquidity`, `require(amount > 0)` ->
      `require(liquidity > 0)`, check intact). Fix direction: match a guard by
      its POSITION in the signature and the shape of its comparison, not by
      identifier. The hard fixture is a genuinely removed require whose
      parameter was ALSO renamed in the same commit - that must still fire, and
      any fix must be measured against it. Rules 2b/4/5 remain
      plausible-and-unobserved for the same reason as before and must not be
      claimed as affected without their own evidence.

- [ ] **Contract-level findings need deduplication by (contract, variable).**
      The same 3c result was emitted twice on v3-core, attributed to
      `UniswapV3Factory.sol` and `UniswapV3Pair.sol`, because `UniswapV3Pair`
      is reachable from both compiled units and each file is genuinely in the
      commit's changed set, so DESIGN-L2's `accept_finding` accepts both.

- [ ] **HIST-L1 dependency reconstruction is now the BINDING coverage
      constraint.** B3/B4 closed the compiler axis completely (auto-install
      fetched 0.5.15, 0.5.16, 0.6.6, 0.6.11, 0.8.3, 0.8.4, 0.6.12 on demand
      across the Step 5 targets). Measured coverage now tracks repo AGE, not
      pinned compilers: v3-periphery 98.7%, v3-core 84.3%, Aave 6.7%, 88mph 0%,
      Compound 0 pairs analysed. Compound v2 is environment-INFEASIBLE on this
      box - `error:0308010C:digital envelope routines::unsupported`, the Node
      17+/OpenSSL 3 break against its old toolchain - and needs a pinned older
      Node in the container before it can be scanned at all.

## Open after Rule 10 (Section A, 2026-08-16)

- [ ] **WALK-L7 invariant test — assert `set(RULE_ORDER) == set(RULES)`.** Rule
      10 was registered, fixture-tested at precision 1.00, and silently absent
      from the product because `src/scan.py`'s `RULE_ORDER` did not list it.
      Every gate was green while the rule did nothing. Nothing stops the next
      rule repeating this exactly. One assertion; deliberately not written in
      the doc pass, because tests get added on purpose, not in passing.
- [ ] **R10-M1 residual — `rule3b.py:98` uses `contract.constructor`.** Same
      accessor Rule 10 had to abandon: it does not cross implicitly-invoked base
      constructors, so a `_disableInitializers()` call in a BASE constructor is
      invisible. Failure direction is safe (false negative), and the path is
      unfixtured anyway — `rule3b.py` records that trigger 2 has no fixture.
      Fixing it means building that missing fixture FIRST.
- [ ] **R10-M2 residual — `has_init_guard` fails toward a FALSE POSITIVE for
      Rule 10.** The same helper limitation is a safe false negative for Rule 3b
      but unsafe for Rule 10, where an unseen init guard makes a writer look
      unguarded and satisfies T3. Not reachable with OZ 4/5 (both read their
      flags directly at the guard node), but it is the direction a future OZ
      refactor would break. Watch on the next OZ major.
- [x] **Rule 10 exclusion 10.7 — value-holding state variables. DONE
      2026-08-17.** Trigger now ranges over gate_vars U value_vars; a value
      variable is one a NATIVE value move (Transfer/Send/LowLevelCall with a
      call value) sends to, determined structurally via data dependency, never
      by name. Locked by `fixtures-r10v/` (1 positive, 4 negatives, 1.00/1.00).
      STILL OPEN, deliberately narrower: ERC20 `transfer(recipient, amount)`
      recipients do NOT qualify, so ERC20 treasury migrations are still missed.
      Widening needs its own fixture-first pass. Original item follows.
- [ ] ~~**Rule 10 exclusion 10.7 — value-holding state variables.** v1 keys only
      on gate variables, so a migration exposing an unguarded writer to a fee
      recipient or treasury address stays quiet even though it can move funds.
      Stated in RULES.md §10.7 rather than left silent. Widening needs its own
      fixture set: "holds value" has no structural definition as crisp as "read
      by a msg.sender-dependent guard".
- [ ] **Rule 10 has one real-world data point.** It is the least-tested rule in
      the set: 6 fixtures plus a single 88mph pair. Any future real-repo scan
      must treat rule 10 fires with more suspicion than the mature rules', and
      classify them as a first-class category.

## Open after the 25-pair stress run (Section 1b, 2026-08-15)

- [ ] **HIST-L2 — provision the per-commit compiler.** `solc-select install`
      on demand during env reconstruction, cached like the dependency install,
      falling back to the file's own pragma when the framework config declares
      no pin. Must report a per-pair skip reason on failure, never a compile
      error 200 lines later. See LIMITATIONS.md §HIST-L2. **This is the single
      highest-value open item for trajectory coverage**: it cost 57 of 76 file
      comparisons on the stress run.
- [ ] **Pre-flight compiler report.** Before analysing anything, print which
      solc versions the walk will need and which are missing. Would have turned
      a 69-minute run into a 5-second answer.
- [ ] **HIST-L3 — Yarn Berry install path.** `--ignore-scripts` is rejected by
      yarn 2+. Use `YARN_ENABLE_SCRIPTS=0` in the environment, NOT simply drop
      the flag: the flag exists to satisfy CHARTER rule 5, and dropping it
      trades a skipped pair for arbitrary code execution.
      ~~**Downgraded in urgency, not closed.** With HIST-L5 fixed, the FIRST
      yarn command (`yarn install --immutable --mode=skip-build`, which IS
      Berry syntax and does skip build scripts) now succeeds, so the broken
      fallback is no longer reached on Berry repos. It is still wrong and still
      the only thing standing between a yarn-1 repo and an install, so it stays
      open — but it is no longer blocking Reserve.~~
      **RETRACTED 2026-08-17 — PRIORITY RAISED BACK UP.** The B4 stress re-run
      contradicts the "no longer reached" claim directly: 2 of 25 pairs
      (`feab683c..6fed5516`, `55f24458..aab30189`) skipped with
      `env-reconstruction-failed (dep-missing)`, and the attached detail is
      `Unknown Syntax Error: Unsupported option name ("--ignore-scripts")` —
      i.e. the fallback WAS reached, so the first command did not succeed.
      **And the root cause is now UNKNOWN, not merely unfixed.** That message
      is the SECOND command's error; the retry loop discarded whatever made the
      Berry command fail. This is METHODOLOGY Face A verbatim — *an error
      surfaced through a fallback describes the fallback* — and it is blocking
      the diagnosis, not just the fix. Order of work is therefore forced: the
      open item "retry loops must report the FIRST failure, not just the last"
      must land BEFORE HIST-L3 can be diagnosed at all. Do not attempt a
      HIST-L3 fix against the `--ignore-scripts` symptom; it is not known to be
      the cause.
- [x] **HIST-L5 — remove our own node_modules junction before installing.**
      DONE. `_unlink_node_modules` runs before any installer and refuses to
      touch a real directory. This was the ROOT CAUSE beneath HIST-L4: an
      installer cannot populate a reparse point, so the second install for any
      dependency set failed, left a partial tree, and that tree got cached and
      trusted. See LIMITATIONS.md §HIST-L5.
- [x] **HIST-L4 — cache hits require a verified-complete marker.** DONE, and
      the first attempt at this fix was destructive (rmtree'd unmarked entries)
      and is retracted in LIMITATIONS.md §HIST-L4. Verification now reads and
      never deletes.
- [x] **Section 1b re-run after HIST-L2. DONE 2026-08-17.** Coverage
      **60/72 = 83.3%** (was 5/72 = 6.9%), `files_skipped` 57 → **0**. The
      `findings: 0` that could not be cited is now `findings: 1`, and that one
      fire is classified: RC-INLINE1, a Rule 2b false positive, not a Reserve
      issue. The remaining 12 errored files are all HIST-L1 dependency
      reconstruction, none of them compiler provisioning.
- [ ] **Section 1c performance — now answerable, and the answer is bad.** The
      B4 re-run took **46191s (12.8h) for 25 pairs / 72 file comparisons**,
      against 4150s before, because ~93% of comparisons went from failing fast
      to genuinely compiling and running ten rules. Full-history walks at
      current per-file compile cost (~640s avg observed this run) are
      impractical beyond small/targeted commit samples. Any future E2-E4
      real-protocol scan should default to a bounded, deliberately-selected
      commit sample (as B4 did with 25 pairs), not an attempt at full history,
      unless parallelization or incremental caching across runs is built first.
      Still not split into env-install / Slither-compile / rule-execution;
      do that before proposing any specific optimisation.

## SECTION C — open-item sweep, 2026-08-16

Every item accumulated this session, either closed or explicitly deferred with
a reason. Nothing dropped silently.

### Closed this pass

- [x] **HIST-L3 — Yarn Berry / lifecycle scripts.** FIXED (97f84db). The
      guarantee now lives in the ENVIRONMENT (`INSTALL_ENV`:
      `YARN_ENABLE_SCRIPTS=0`, `npm_config_ignore_scripts=true`) instead of a
      version-specific CLI flag that Berry ignores. Measured:
      `yarn config get enableScripts` returns `true` normally and `false` under
      the overlay — i.e. CHARTER rule 5 had been resting on which command won a
      retry race. Gap stated rather than hidden: a FRESH install through the new
      environment was not exercised, because every Reserve lockfile tried
      already had a cache entry.
- [x] **METHODOLOGY section — rewritten as ONE lesson** (`a self-consistent
      story is not evidence`) with two faces: an error arriving through a
      fallback describes the fallback (instances 1–3), and a check that reads
      correctly is unverified until something adversarial hits it (instance 4,
      the `\b` hole in the hallucination gate). Previously four disjointed
      incident reports with a stale "of the three" and a broken code span.
- [x] **Containerization.** Dockerfile + .dockerignore, built and smoke-tested
      locally: engine (`scorer.py` PASS inside the image), scan of a mounted
      repo, and an agent-generated verified dossier. Two container-only defects
      found and fixed in the process (solc-select installing to the wrong HOME;
      git `safe.directory` on mounted repos).

### Deferred, with reasons

- [ ] **HIST-L2 — per-commit solc provisioning. STILL DEFERRED.** The pre-flight
      check (960eeca) is the interim mitigation and it is a REPORTING and SPEED
      improvement, **not a coverage improvement**. Honest numbers from the
      25-pair stress run, stated without the "0 fires" framing: **23/25 commit
      pairs reached analysis (92%), but only 5 of 72 FILE COMPARISONS completed
      — 6.9%.** 57 of 76 were exact pragma pins (`0.8.19`, `0.8.17`) with no
      matching compiler installed. After the pre-flight those are reported as
      `never attempted — solc X not installed` instead of nine misleading rule
      errors each, and the run is far faster, but **the same 93% remains
      unanalysed**. Any claim about that workload must cite 6.9%, not 92%.
- [ ] **Cloud Run deployment. DEFERRED, NOT CANCELLED.** Needs a Google Cloud
      project and credentials not available on this machine. The image is built
      and locally verified end to end, so deployment is a `gcloud run deploy`
      away rather than a from-scratch task. README and AGENT-DESIGN both say
      "containerized and locally verified, Cloud Run deployment pending".
- [ ] **WALK-L6 — make the read-only guarantee literal.** Clone the target once
      into scratch and worktree off the clone. Claim already corrected in
      README and `src/scan.py`; the code fix changes a core path and deserves
      its own measurement, so it is not being done under deadline.
- [x] **RC-RENAME1 — CLOSED (`f8c8a24`), no longer deferred.** Shipped as Rule
      10, not as a patch to Rule 3b, exactly as this item required. The
      "fires on every proxy migration ever made" risk this entry predicted was
      real and showed up in a different place than expected: Rule 10 co-fired on
      both Rule 3b positives until exclusion 10.8 drew the rule boundary
      (Rule 3b owns "the guard left the function"; Rule 10 owns "the
      responsibility left the guarded function"). Caught by the 14-set sweep,
      not by reasoning.

### Confirmed, no action needed

- [x] **RC-AST1 fixture-first ordering.** Still recorded as unprovable
      ("Strict temporal ordering remains unprovable and is recorded as
      unprovable"), and the retroactive pre-fix measurement (precision 0.67 →
      1.00) is what stands in for it. Checked: RC-AST1 is not referenced in
      README, SUBMISSION-NOTES or AGENT-DESIGN at all, so there is no
      submission-facing copy to have drifted into a stronger claim.
- [x] **guard.sh scope — STILL THE RIGHT CALL, restated for a larger codebase.**
      Protected: 14 fixture sets + `scorer.py` (271 files). Deliberately
      outside: `walker.py`, `src/scan.py`, `src/verdict.py`, `src/history.py`,
      the rules, and all of `agent/`. The guard exists to make ONE failure mode
      detectable — ground truth or the thing that measures against it being
      edited to make a result look better. Source code is reviewed by diff at
      every commit; hashing it would fire on every legitimate change and train
      the human to run `freeze` reflexively, which would erode the signal for
      fixtures too. The one genuinely new candidate is `agent/verify.py`, since
      a weakened gate is silently harmful in the same way a weakened fixture is
      — but that is covered by adversarial tests that fail loudly if the gate
      stops rejecting, which is the better mechanism for code.

### Step 5 sampling honesty — what these numbers are NOT

- [ ] **Re-scan with larger samples before citing any target's fire count.**
      Two measured facts make every Step 5 number provisional:
      1. **The 3-pair pilots did not predict the full runs.** 88mph piloted at
         0.0% coverage and ran at 31.7%; Aave piloted at 48.6s/comparison and
         ran at 634.0s/comparison, a 13x miss that turned a projected ~48min
         into 8.6 hours. Pilot-then-scale was the right discipline and a 3-pair
         pilot is too small to size from - both are true.
      2. **The samples are a fraction of history.** 12 evenly-spaced pairs over
         849 Aave commits is ~1.4%; 16 completed comparisons cannot support any
         statement about Aave's fire rate. Same for 88mph at 12/263.
      A zero, or a one, from these runs is an ABSENCE OF EVIDENCE, not evidence
      of absence - the HIST-L2 lesson restated for sample size instead of
      coverage.
- [ ] **Rule 10 was never exercised on its own known true positive.** 88mph
      `a4c48d61` (the RC-RENAME1 case) was not in the evenly-spaced 12-pair
      sample, so 88mph's `FINDINGS=0` says nothing about rule 10's behaviour on
      that repo. A targeted re-run including that pair is the honest way to
      claim anything about rule 10 on 88mph.
