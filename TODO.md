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