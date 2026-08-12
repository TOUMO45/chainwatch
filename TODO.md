# Deferred (documented in LIMITATIONS.md, not yet fixed)

- [ ] 3a-L2 — widen Rule 3a trigger from "constraint removed" to "caller set
      widened." Needs fixture: onlyOwner → require(msg.sender == mutablePublicVar).
      Real regression shape, currently invisible.
- [ ] X-L1 — implement verdict.py three-state model (DISCARDED/CANDIDATE/CONFIRMED).
      Convert 3a.1 and 2.10 from silent discard to CANDIDATE.
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
- [ ] HIST-L1 residual — repo-root-relative imports (`contracts/interfaces/…`)
      fail under bare solc because only Hardhat resolves them implicitly from the
      project root. 3 of 46 file comparisons on Reserve. Fix: emit
      `<dir>/=<root>/<dir>/` remaps for top-level source dirs in `derive_remaps`.
- [ ] Rule 3c cannot run in trajectory mode at all — 42/42 errors on the Reserve
      window. `_storage.storage_layouts` builds paths relative to THIS repo's
      root, so it cannot address a scratch worktree. Make the layout extractor
      take the project root as a parameter.
- [ ] HIST-L1 residual — `dep-gone-from-registry` was never exercised (the tested
      window is 2 months old). Older history will hit unpublished/yanked
      transitive deps; measure on a multi-year window before claiming "any repo".