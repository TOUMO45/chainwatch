# HANDOFF — resume point for a fresh session

**Last commit: `81511bf`** · `./guard.sh check` → **INTEGRITY OK** · tree clean
· 22 fixture sets, 339 guard-protected files · full suite **87 passed**.

Read `CHARTER.md` first (it is the contract), then this file.

---

## State: verified green

Every number below is from a command whose raw output was read, not a summary.

```
./guard.sh check                     INTEGRITY OK
python -m pytest tests/ -q           87 passed    (FULL suite, no subset)
22 fixture sets                      all PASS, counts identical to baseline
```

**Run the FULL suite, never a subset.** This project has now been bitten twice
by skipping part of it: Section A missed Rule 10's null evidence because
`test_verdict.py` was skipped, and Step 4 caught a real-world failure the
22-set fixture sweep could not see. `tests/test_realworld_reserve.py` takes
~4 minutes and is the one that matters most.

---

## Closed in the last session

Four false-positive/negative classes, each fixture-locked and live-verified on
the real commit that surfaced it:

| class | rule | fix | fixtures |
|---|---|---|---|
| **RC-MUTEX1** | 3c + 10/3b | a set/clear mutex is not a one-shot init guard | `fixtures-rmutex/` |
| **RC-NEWCALL1** | 2b | `has_external_call(fn_b)` precondition | `fixtures-r2b-baseline/` |
| **RC-NEWVAR1** | 2b | `moved` restricted to variables present at N-1 | `fixtures-r2b-baseline/` |
| **RC-RENAME2** | 6 | guarded parameters keyed by POSITION, not name | `fixtures-r6-rename/` |

Plus **ERC20 value detection** for Rule 10 (`fixtures-r10e/`), closing the
native-only limit in `RULES.md §10.7`.

**RC-MUTEX1 is worth reading before touching `_shared.is_oneshot_init_guard`.**
The obvious fix — "the gated flag is written to exactly ONE constant" — is
WRONG and the frozen fixtures caught it: OZ's `reinitializer(n)` writes
`_initialized = version` from a PARAMETER, so its only constant-written gated
flag is `_initializing`, which is set/clear exactly like a mutex. The shipped
test needs BOTH conditions, each paying for a different past finding:
(a) some gated flag is written to a constant — `3b-L-ratelimit`;
(b) some gated flag is NOT set/clear — `RC-MUTEX1`.

---

## What remains

### Step 5 — HIST-L1 dependency-axis diagnosis

The compiler axis is closed (auto-install fetched `0.5.15`, `0.5.16`, `0.6.6`,
`0.6.11`, `0.6.12`, `0.8.3`, `0.8.4` on demand). **Dependency reconstruction is
now the binding constraint**, and coverage tracks repo AGE:

```
v3-periphery   98.7%   (77/78 files)
v3-core        84.3%   (43/51)
aave-v2        32.7%   (16/49)
88mph          31.7%   (32/101)
compound-v2    0 pairs analysed — INFEASIBLE
```

Numbers are exact, not rounded toward 100.

1. **Diagnose before fixing**, the way HIST-L2 was diagnosed: read the actual
   error strings in `.e2-full-*.json` → `coverage.rule_errors`. Do not guess.
   Expect a mix of dead npm packages (unfixable — report as such), version
   resolution bugs, and unhandled import styles.
2. **Compound v2 is `error:0308010C:digital envelope routines::unsupported`** —
   the Node 17+/OpenSSL 3 break against its old toolchain. A pinned older Node
   in the container is the legitimate route. **Do NOT force it by disabling
   checksum verification or sandboxing** — that trades a real safety control
   for coverage, which this project does not do.
3. Re-measure and report the honest percentage. "60%" is 60%, not "much
   improved". Enumerate what stays uncoverable and why.

### Step 6 — final real-world validation pass

Re-run bounded samples against the improved engine, classify every fire with
git-diff rigor, expect a possible sixth defect class. **Finding one is success,
not failure.**

---

## Two traps this session hit — read before scanning

**WALK-L8: a scan mutates shared per-repo worktree state.** An ERC20 re-check
over 2906 Reserve commits left `.walker-worktrees/<repo-hash>/` with
`node_modules` built for a newer dependency set, and the next analysis of
`f43202a3..e27227b2` failed every file. That surfaced as
`test_realworld_reserve.py` reporting *"the known TRUE POSITIVE did not fire"* —
which reads as a detection regression and is not one. **Check `files_ok=0`
before reading any real-world failure as a detection change.** `rm -rf` the
repo's worktree directory to reset.

**Pilots do not predict full runs.** 88mph piloted at 0.0% coverage and ran at
31.7%; Aave piloted at 48.6s/comparison and ran at 634.0s — a 13× miss that
turned a projected 48 minutes into 8.6 hours. Pilot-then-scale is still right;
a 3-pair pilot is still too small to size from. Both are true.

---

## Known limits, stated plainly

- **SafeERC20 wrapper transfers are invisible to Rule 10.** `safeTransfer`
  compiles to a `LibraryCall`, not a `HighLevelCall`. Reserve uses that pattern
  throughout, so its 0 findings on the widened rule is *consistent with the
  gap*, not reassurance about it.
- **Rule 10 has one real-world data point.** It remains the least battle-tested
  rule; treat its fires with more suspicion than the mature rules'.
- **Pre-2020 repos with dead npm dependencies are partially uncoverable.** That
  is an environment constraint, not a detection gap, and no amount of
  Chainwatch code fixes it.
- **RC-EXTRACT1 is documented and NOT fixed** (Rule 4 fires when arithmetic is
  extracted into a helper). It is the next-highest-value fix. See
  `LIMITATIONS.md §RC-EXTRACT1`.

`TODO.md` carries the full open list; `LIMITATIONS.md` carries every defect
class with mechanism/evidence/scope/fix-direction. **METHODOLOGY rule 5** in
`LIMITATIONS.md` tabulates all six instances of the vacuous-empty-set family —
read it before adding any rule that compares two sets across commits.
