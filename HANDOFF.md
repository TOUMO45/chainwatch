# HANDOFF — resume point for a fresh session

**Last commit: `c3fb4e8`** · `./guard.sh check` → **INTEGRITY OK** · full suite
**150 passed** · `fixtures-sizing/` now frozen into the guard baseline.

Read `CHARTER.md` first (it is the contract), then this file.

---

## State: verified green

Every number below is from a command whose raw output was read, not a summary.

```
./guard.sh check                     INTEGRITY OK  (346 files hashed)
python -m pytest tests/ -q           150 passed    (FULL suite, no subset)
```

**Run the FULL suite, never a subset** (`tests/test_realworld_reserve.py` is
~4 min and matters most). The suite takes ~8–10 min end to end.

---

## Shipped this arc (newest first)

| Commit | What |
|---|---|
| `c3fb4e8` | Submission packaging: README architecture diagram + spin-up + live URL; `SUBMISSION-DRAFT.md` (description, third-party/license disclosure, answers) |
| `e84a512` / `a46967e` | **COMP-L2**: Foundry env reconstruction — `lib/` auto-remapping + remapping-aware, dep-scoped skip gate (`src/history.py`, `tests/test_foundry_remap.py`) |
| `ed5e2d3` | Deployment to Cloud Run; `yarn`/`pnpm@9` added to image; `GEMINI_API_KEY` via Secret Manager |
| `0c72626` | Frontend redesign (forensic-terminal; four-channel verdict clarity; reduced-motion) — `webapp/static/*` |
| `0270fff` | Sizing (G5/G6): measured ranges, refusal-to-fudge, checkout-failed emit fix |

## Live deployment (kept up through judging, per the owner)

- **URL:** <https://chainwatch-898260334135.us-central1.run.app> · project
  `chainwatch-ee1d1` / `us-central1` · `2 vCPU / 4 GiB`, timeout `3600s`,
  min/max `0/2`, `GEMINI_API_KEY` via `chainwatch-gemini-key:latest`.
- **Teardown when done:** `gcloud run services delete chainwatch --region us-central1`.
- Known Cloud Run trait: in-memory job store + scale-to-zero means a scan longer
  than one held-open connection can be lost when the instance recycles. Bounded
  depth (≈`limit 10`) completes and persists; deep scans would need
  `--no-cpu-throttling --min-instances 1` (ends scale-to-zero → real cost).

## The Foundry ceiling (COMP-L2 — read before "improving" coverage)

The env fix took 1inch/cross-chain-swap from **0/10 pairs (false `dep-missing`
skips) → 10/10 reconstructed**, but its files still fail to **compile**: deeply
nested submodules (`limit-order-settlement` → its own `lib/` for `@1inch/st1inch`,
`@1inch/delegating`) each resolve imports in **their own** remapping context, and
bare solc holds **one flat** remapping set — flattening is fundamentally lossy
(the doubled-`contracts/` path). The tool that resolves this correctly is
`forge`, which **CHARTER rule 3 forbids installing** (WALK-L9 RCE class). So full
Foundry compile success for deeply-nested repos is a **charter-bounded ceiling**,
not a patchable bug. Do not chase it by loosening rules; installing `forge` is a
human decision with a real security tradeoff.

## Open (submission-readiness — needs the human)

- **Repo has NO git remote** — not on GitHub yet. Push, then make public or grant
  `testing@devpost.com` / `cloudhackathons@google.com` access. See `SUBMISSION-DRAFT.md §3`.
- Demo video not recorded (`DEMO-SCRIPT.md` drafted); Devpost form not submitted.
- `SUBMISSION-DRAFT.md` is a DRAFT for the owner to review/trim before pasting.
- Deadline: **2026-08-31 17:00 PT**.

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
