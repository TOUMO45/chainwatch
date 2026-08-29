# HANDOFF — resume point for a fresh session

**Last commit: `d7d6db4`** ("Deep Hunt: the signature-SCOPE oracle").
**NOT YET PUSHED** — `git status -sb` shows `ahead 21`. Git Credential Manager
has no cached token on this host: `git push` and even
`git credential-manager get` HANG until timeout, and there is no `gh` CLI and
no `GH_TOKEN`/`GITHUB_TOKEN`. A human must run `git push origin master`, or
supply a PAT. Do not burn time retrying it.

## CHAINWATCH 2.0 — the DEEP HUNT engine (2026-08-29). Read NEXTGEN.md's last section.

A THIRD pipeline beside the regression engine and the Twin, answering the
question neither can: *can the protocol as it stands be driven into a violating
state, whether or not any commit introduced it?* Additive, flag-gated
(`CHAINWATCH_DEEPHUNT=1`, `chainwatch.py --deep-hunt`), imported by nothing on
the classic path. 11 phases, `src/nextgen/deephunt/`, one commit per phase
(`3ef4535` → `c806c45`), then two more:

- **`53baa37`** made the DVBench harness actually runnable. Three real fixes:
  (1) the benchmark repo does not commit `.cache/etherscan/`, so a fresh
  checkout had ZERO source — added a keyless **Sourcify** fallback (71/90 cases
  fetched in 39s); (2) big multi-file bundles thrashed every entry file across
  ~20 solc versions — now ≤4 ranked entries with the verified compiler pinned,
  taking 300–620s cases under 40s; (3) a blinded reproducer's NOT_REPRODUCED
  was FAILing the gate for value/oracle objectives, where an isolated
  `new Target()` test proves nothing — now PENDING, recovering 3 false-REJECTs.
- **`d7d6db4`** added the **signature-SCOPE oracle** (below).

### The result that matters: a real bug, found blind

Swept six real repos (Web3Bugs contests 18/20/38/39/105/125). On contest 38 —
**Ambire, code4rena 2021-10** — Deep Hunt independently reported
`QuickAccManager.send` / `sendTransfer` / `sendTxns`, party `identity`. That is
finding **H-03, "Signature replay attacks for different identities (nonce on
wrong party)" — confirmed AND patched by the Ambire team** (Web3Bugs label
S2-3). Nothing pointed the engine at the contract, function, or bug class.

The oracle (`invariants.cat_signature_scope`): a nonce stops replay against the
SAME party; it does nothing across DIFFERENT parties unless the digest binds
that party. It fires only when a signature is genuinely verified, the nonce is
keyed on a caller-supplied PARAMETER (never `msg.sender`), and that parameter
is absent from the `abi.encode*` preimage once the `nonce[...]` index is
stripped. `FunctionModel.source` was added so an oracle can read an EXPRESSION
rather than a fact Slither summarises.

**Precision is the load-bearing claim, so it is tested.** OpenZeppelin 5
`ERC20Permit.permit` — the most deployed signature-consuming function in DeFi —
is modelled, writes a nonce, and is NOT flagged; the test asserts it was
modelled first so the silence cannot be vacuous. Wide sweep over 9 compiled
units: **3 fires, all 3 on the known-vulnerable contract, ZERO false positives.**

### Numbers (measured, in-repo artifacts)

- `.dvbench-run.json` — full blind DVBench run, 90 cases: 72 run, 38/72
  compiled, **micro recall 0.247 (24/97)**, **0 CONFIRMED, 0 false positives**.
- `.sigscope-sweep.json` — the signature-scope sweep over all 102 Web3Bugs
  contests (written by `$TEMP/bigsweep.py`; re-runnable).
- 118 deephunt tests green; full suite 720 passed / 3 skipped; `guard.sh` OK.

### Where the next gain is — NOT more oracles

**Compile rate is the ceiling.** 38/72 on DVBench, and roughly half of Web3Bugs
contests need `node_modules` that are not vendored. An uncompiled bundle
contributes exactly zero recall, so dependency reconstruction for a bare
Etherscan/hardhat tree is worth more than any new detector. The classic engine
already solves this per-commit in `src/history.py` (`detect_env`/`install`) —
wiring that into `deephunt/protocolmodel._compile_tree` is the obvious next
move.

Second: fork grounding is chain-gated. `.env` has only an ETH-mainnet Alchemy
URL, so only 31/90 DVBench cases could ever be execution-grounded. The harness
now resolves per-chain RPCs (`bench_dvbench.rpc_for_chain`, reading
`BSC_RPC_URL`/`BASE_RPC_URL`/…), so adding endpoints lifts this with no code
change. A bare eth-mainnet URL is deliberately NOT reused for other chains.

### Checkouts (gitignored)

`realworld-test/dvbench` (the DVBench repo + a Sourcify-populated
`.cache/etherscan/`) and `realworld-test/web3bugs` (493 labelled code4rena bugs
across 102 contests, with full source trees). Both are what the tests
`skipif`-guard on.

---

## PRIOR ARC Counterfactual Protocol Twin — ALL THREE COMMITS DONE (2026-08-28)

The user asked to build a **Counterfactual Protocol Twin** (a trace-driven
complement to the NEXTGEN pipeline) per a 10-phase architecture, in three
commits. Commit 1/3 (Phases 1-2 + the Anvil fork lifecycle) was already done
when this arc started. **This session finished commits 2/3 (Phases 3-5) and
3/3 (Phases 6-10 + the orchestrator), tested everything — including a real,
live end-to-end run against real WETH mainnet data through an actual WSL
Anvil fork, twice — found and fixed one real bug the test suite itself
caught, and wired the CLI.**

**The full spec and the phase-by-phase implementation notes are in
`NEXTGEN.md` → "Counterfactual Protocol Twin" (bottom of the file).**
Short version of what shipped this session:

- `twin/boundaries.py` (Phase 3) — nine independent boundary miners
  (authorization, conservation, accounting, replay-protection, state-machine,
  oracle-freshness, governance, collateral, withdrawal), each conservative:
  every one needs a concrete, repeated behavioural pattern before it reports
  anything, and `ORACLE_FRESHNESS` never advances past INFERRED since
  staleness itself is not observable from a call trace alone.
- `twin/diverge.py` (Phase 4) — cross-version behavioural comparison, wired
  automatically off `Collection.upgrades` (a second `collect()` call over the
  pre-upgrade window when an implementation change was observed).
- `twin/mutate.py` (Phase 5) — all ten mutation kinds generate real
  `{from,to,value,data}` calls; two are honestly-documented approximations
  (`CALLBACK_INSERT` has no contract-deploy step to stage a real callback;
  `PERMISSION_CHANGE`/`CROSS_CONTRACT_VARIATION` can only touch what a local
  fork exposes without an ABI) rather than silently overclaiming.
  `ORACLE_STATE` is genuinely real, not an approximation: a forked oracle's
  own `updatedAt` does not advance with the fork's local clock.
- `twin/replay.py` (Phase 6) + Phase 8 `minimize_calls` (the same
  delta-debugging algorithm as `execground/sequences.minimize`, reimplemented
  for a `Mutation`'s real RPC calls rather than generated Foundry-test
  source — see the module docstring for why they aren't literally the same
  function).
- `twin/checks.py` (Phase 7) — six conservative violation checks, each
  needing a concrete signal (a boundary-crossing success, a net ETH gain/loss)
  never "this merely differs from baseline".
- `twin/twin.py` — `CounterfactualTwin(address, rpc_url, from_block,
  to_block).run() -> TwinResult`, wiring all ten phases. Phase 9 calls BOTH
  `deployment.run` (can reach PASS — the Twin always has a live address) and
  `provenance.run` (always honestly INCOMPLETE — the Twin never reads a git
  commit, so it structurally cannot claim a commit-level bytecode match).
  Phase 10: Skeptic sweep + a genuinely independent blinded reproducer (fresh
  fork, re-derives the violation without seeing the Hunter-side reasoning).
  Verdict rule stated directly in `twin.py` (not routed through
  `nextgen/state.classify`, which is built around gates the Twin structurally
  can't produce) — CONFIRMED only if a violation reproduced on the fork AND
  the vulnerable implementation is still live AND the Skeptic can't disprove
  it AND independent reproduction agrees; each of those failing independently
  is REJECTED; anything else (most often: nothing found in budget) is
  UNKNOWN. `chainwatch.py --twin <address> --blocks lo:hi` added.

**The one real bug this arc found, in its own test suite, not from a user
report**: `ReplayResult.executed` was computed from a trace-entry COUNT, which
a submission failure (an exception from `send_tx` itself, distinct from an
on-chain revert) satisfied just as well as a real success — so a call that
never actually ran could read as "executed". Caught by
`tests/test_nextgen_twin_replay.py::test_replay_records_send_failure_without_raising`
on its first run against the real toolchain. Fixed by tracking submission
success explicitly. Full writeup: `LIMITATIONS.md` → `TWIN-L1`.

**Gates, raw, final:**
```
python -m pytest tests/test_nextgen_twin_*.py -q     92 passed  (692.5s,
                                                       all 9 Twin test files,
                                                       commits 1-3, run alone)
python -m pytest tests/ -q                            679 passed, 3 skipped,
                                                       0 failed  (1823.17s /
                                                       30m23s, the WHOLE
                                                       project: classic +
                                                       NEXTGEN + Twin)
bash guard.sh check                                    INTEGRITY OK
```
Two transient failures were observed during one intermediate run (a stale
`chainwatch-nextgen/mirror/...` temp git cache corrupted by 3 concurrent
heavy background test processes sharing it, and one flaky Anvil-fork-block
timing assertion under that same resource contention) - both vanished on a
clean, uncontended re-run and are NOT a code issue; see this arc's own
commit messages and `LIMITATIONS.md` → `TWIN-L1` for the one REAL bug this
arc did find (in its own test suite, on the first run against the real
toolchain) and fixed.

**Environment notes for the new chat:**
- Foundry is in WSL (`kali-linux`, `/home/kali/.foundry/bin`) — see the
  `foundry-in-wsl` memory. `anvil --version` works; `AnvilFork` handles the
  Alchemy probe issue.
- `RPC_URL` in `.env` is an Alchemy free endpoint: `eth_*` + `eth_getLogs` +
  `alchemy_getAssetTransfers` work; `debug_*` / `trace_*` return HTTP 400
  (that's why enrichment re-executes on a local anvil).
- Windows C: drive runs low on space; if a run hits `ENOSPC`, clear
  `%TEMP%\chainwatch-*` and (in WSL) `~/.foundry/cache/rpc/*` + `/tmp/cw-*`.
- Kill stray forks between runs: `wsl -d kali-linux -- bash -c 'pkill -f
  "cw-anvil|cw-rpcshim"'`.

---

## PRIOR ARC (2026-08-28) — NEXTGEN Tier 1: real-repo scanning. Commits `db23265`, `a6a1c68`.

Made `nextgen/pipeline.py` work on REAL GitHub repos: `src/nextgen/repo.py`
`RepoContext` reuses the classic per-commit worktree + dep reconstruction so a
next-gen analysis compiles a historical commit with imports resolved.
`pipeline.run_from_repo(...)` + `chainwatch.py --nextgen FILE:CONTRACT:FUNCTION`
(one `--pairs prev:cur`, optional `--address`). **Verified end to end: 88mph
`NFT.init` @ `a4c48d61` with addr `0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634`
→ `CHAINWATCH CONFIRMED FINDING`** (regression commit + dependency-resolved
invariant regression + `EOA→NFT.init` unprivileged path + byte-identical
on-chain bytecode provenance + `target_live` YES + read-only eth_call
reproduction for the pre-0.6 pragma); reserve `ActFacet.revenueOverview` @
`e27227b2` → `NOT A FINDING`. `a6a1c68` fixed a global-state pollution
(`RepoContext` now restores `_shared`/`_storage`/`$SOLC_VERSION` on `close()`).
Full `pytest tests/` after this arc: 587 passed / 3 skipped.

## PRIOR ARC (2026-08-28) — NEXTGEN: the execution-grounded proof engine.

The user asked to upgrade Chainwatch from a regression scanner into an
"execution-grounded security research and proof engine" per a 27-section spec.
**All 27 sections are implemented**, additively, under `src/nextgen/`, behind
the `CHAINWATCH_NEXTGEN` flag. The classic pipeline (`src/scan.py`,
`src/verdict.py`, `src/rules/`, `fixtures*/`, `guard.sh`) is untouched — nothing
on that path imports `src/nextgen/`.

**Roadmap + per-phase acceptance checks: `NEXTGEN.md`.** Three decisions the
user made up front (recorded there and in a `CHARTER.md` amendment): (1) the
fuzz/symbolic/PoC anti-goals are narrowed **for the next-gen pipeline only** to
local-fork execution — no broadcast tx, no weaponised artifact, no
auto-disclosure; (2) Foundry approved (it is in WSL — see below); a symbolic
solver stays deferred, §6 uses a Python constraint sketch; (3) the new
machinery is additive, `verdict.py` frozen, a next-gen CONFIRMED must clear the
classic gate first and then a stricter evidence chain.

**Commits (all local):** `d92e02f` P0 substrate · `0d92b52` P1-2 Time Machine +
invariants · `ffa7fa1` P3a attack graph · `3b37036` P3b provenance/deployment/
compensating · `896fb9a` P4 adversarial/benchmark/report · `85e788c` P5a
Foundry adapter + reproducer + economics · `a200539` P5b+6 sequences/hybrid/
regfuzz + composability + `pipeline.py`.

**Gates, raw:**
```
python -m pytest tests/ -q        581 passed, 3 skipped in 1154.44s (0:19:14)
                                  (baseline 509/3 at the P3 boundary; +72 new
                                   test_nextgen_* tests, 0 failures; 3 skips
                                   unchanged. Slither- AND WSL-Foundry-gated
                                   nextgen tests all RAN here, none skipped.)
bash guard.sh check               INTEGRITY OK
```

**Execution grounding is real.** `forge`/`anvil` 1.8.0 live in **WSL**
(`kali-linux`, `/home/kali/.foundry/bin`), NOT on the Windows PATH.
`src/nextgen/execground/foundry.py` shells to them via
`wsl.exe -d kali-linux --exec /bin/bash <script>` (path-mangling disabled, PATH
set explicitly, files written via base64, all subprocess I/O
`utf-8`/`errors=replace`). Verified end to end: a generated minimal Foundry
test for an unguarded `setOwner` printed `[PASS] test_invariant_is_violated()
(gas: 37579)` → REPRODUCED; an `onlyOwner`-guarded one → NOT_REPRODUCED. With
no `forge` reachable every execground entry point returns PENDING and the
`reproducer` gate never PASSES (same discipline as `liveness.py` without an RPC).

**Entry point:** `src/nextgen/pipeline.py::run(PipelineInputs) -> PipelineResult`
runs every phase's analyzer in evidence order (each wrapped, degrades to
PENDING), then `state.classify` → verdict, `proofscore.score` → the §16 tally,
`report.render` → the §23 report with the §18 evidence-graph appendix.

**Deferred by decision, not omission:** a symbolic solver (halmos); the
`unauthorized_upgrade` / `state_relation_violated` reproducer generators (they
return a clear "Phase 5b follow-up" reason); real corpus-backed dedup in the
pipeline (`not_duplicate` gate is set only from an explicit input for now).

---

## PRIOR ARC (2026-08-28) — `4712be8` professional security audit of Chainwatch itself.

**The user's mandate**: "act like [a] profe[ss]ional in web3 and bug hunter
in cryp[t]o and smart contract[s] [with] over 10 year[s'] experience, review
the whole project line [by] line and code by code and function by function
until you see the gap and weakness and fix it" — then granted an extended
unattended window ("I will go to sleep for 8 hours, you have all permission
and resource[s], do [y]our best") to keep going without further check-ins.

**This audit turned the lens around**: every prior arc hardened what
Chainwatch REPORTS about a target repository (coverage, attribution,
liveness). This one asked a different question — can a malicious TARGET
repository, or a malicious HTTP caller of the public web app, attack
Chainwatch's own hosting infrastructure? Three real, independently
exploitable findings, all fixed, all with new regression tests:

**SEC-L1 — a malicious target repository could read arbitrary files off the
host through a tracked git symlink.** A git blob at file mode `120000` is a
symlink; every rule and every compiler opens whatever it points to with no
sandbox of its own. `core.symlinks` defaults ON for the real Linux/Cloud Run
target (confirmed OFF and thus inert on this Windows dev machine — a real
measured platform difference, not glossed over). Fix: `history._strip_symlinks`
deletes every symlinked entry from a checkout before anything reads it
(deletion, not a containment check, so compile success/failure can't be used
as a file-existence oracle either). Applied at all 4 `scan.py` checkout call
sites, `anchor.py`'s, and `soldeer.py`'s independent git-dependency fetch.
Confirmed the sibling ZIP-extraction path (Soldeer registry packages) is
NOT vulnerable — Python's `zipfile.extractall()` never honors `S_IFLNK` mode
bits on any platform, verified directly rather than assumed.

**SEC-L2 — a remote caller could aim Chainwatch's own outbound RPC request
at internal network space (SSRF).** `webapp/server.py`'s public
`ScanRequest.rpc_url` reached `Web3.HTTPProvider(rpc_url)` with zero
validation anywhere in the chain — on Cloud Run, a live path to
`169.254.169.254`, the metadata endpoint that answers unauthenticated
requests carrying the running service account's own token. Fix:
`liveness._validate_rpc_url` — http(s)-only scheme, resolves the hostname
and rejects the request if ANY resolved address (not just the first — DNS
can return several) is private/loopback/link-local/reserved/multicast,
verified this also catches IPv4-mapped-IPv6 bypass attempts
(`::ffff:169.254.169.254`) since Python's `ipaddress` module classifies
those correctly. Scoped to only the explicitly-passed argument, never the
operator's own trusted `.env` default. Stated honestly: does not close DNS
rebinding (a TOCTOU gap between validation and web3.py's own request) —
that needs a pinned-connection transport, deliberately not bundled in.

**SEC-L3 — `prev`/`cur`/`rev` on the public diff/source endpoints were
usable as injected git options.** `GET /api/scan/{id}/diff?prev=&cur=` and
`GET /api/scan/{id}/source?rev=` passed those values as bare argv content
to `git diff`/`git show` with no `--` protecting them from being parsed as
options — `--output=<path>` alone turns either into an arbitrary-file-write
primitive, reachable pre-authentication, before any job lookup even runs.
Fix: `webapp.server._require_git_rev` requires `^[0-9a-fA-F]{4,40}$` (every
legitimate value these fields ever carry, confirmed against `app.js`, which
echoes `f.parent`/`f.commit` straight out of finding data `scan.py` itself
already emits as full SHAs) and 400s otherwise, checked before the job
lookup in both handlers.

**Checked and confirmed NOT vulnerable, not just assumed** (documented so a
future reader doesn't re-litigate the same question): `git clone`
argument-injection via the web form's `repo` field — blocked structurally,
not by validation added this session, because `_run_job` only calls
`clone_public` when `repo.startswith(CLONE_SCHEMES)` (`http(s)://`,
`git@`, `ssh://`, `git://`, `file://` — none start with `-`), so a
`-`-prefixed value falls through to the local-path branch instead of ever
reaching `git clone`. The Gemini-report and diff renderers in
`webapp/static/app.js` — read closely for stored XSS given an attacker
fully controls the source text an LLM might echo back; `mdToHtml()`
escapes `&`/`<`/`>` on every line BEFORE any markdown transform runs, and
`loadDiff()` wraps every line in `esc()`. `agent/store.py`'s own
`git diff` call, same unprotected-argv shape as SEC-L3's — but its
`parent`/`commit` values are never attacker-reachable text: they only ever
come from `Store.get(fid)`, sourced from `scan.py`'s own git walk, and a
git commit SHA is a hash output, structurally incapable of starting with
`-`. Left unchanged rather than "fixed" for a scenario that cannot happen
— matches this project's own stated engineering discipline.

**Gates, all read from raw output, not summarised:**

```
python -m pytest tests/ -q     346 passed, 3 skipped, 0 failed (1053.87s / 17m34s)
./guard.sh check                INTEGRITY OK
```

(326 passed, 3 skipped before this arc's new tests were added — the +20 is
the new SEC-L1/L2/L3 coverage. The 3 skips are unchanged: platform-gated
tests that need a real POSIX host, same as before this arc.)

New test files this arc: `tests/test_symlink_strip.py` (7),
`tests/test_rpc_ssrf_guard.py` (9), `tests/test_diff_source_arg_injection.py`
(15). Full writeups with evidence: `LIMITATIONS.md` — `SEC-L1`, `SEC-L2`,
`SEC-L3`.

---

## NEWEST ARC (2026-08-27) — the coverage work. Read this first.

Three fixes, in dependency order, each measured before and after on real
repositories. Full detail in LIMITATIONS.md (`COV-ACCT1 / COV-ACCT2`, `DEP-1`).

**1. COV-ACCT1 — coverage was scored per FILE but earned per RULE.** One
boolean spanned ~10 rule invocations, so a single failing rule discarded the
credit for the other nine. **2. COV-ACCT2 — "this compiler has no such
option" was recorded as "this rule failed".** Rule 3c needs
`solc --combined-json storage-layout`, which does not exist below ~0.6.x.
Together these made 88mph report `0/43 (0.0%)` when 387/430 rule invocations
had actually succeeded and produced its real rule-10 finding. Fixed with
`RuleUnsupported` + per-invocation counters + three file buckets
(ok / partial / lost), rendered in both the CLI and the web UI.

**3. DEP-1 — a repository's own `remappings.txt` silently defeated
`absolute=True`.** Its relative targets are appended last (so an explicit
entry wins) and therefore overrode the absolute remappings the walker
derives; with `Slither()` invoked without a cwd, solc then resolved
`node_modules/...` against Chainwatch's own root. Every import failed as
"not found" on a dependency tree that was installed correctly all along.

| repository | before | after |
|---|---|---|
| `1inch/swap-vm` | 0/1160 invocations (0.0%) | **80/80 (100%)** |
| `1inch/aqua` | 11/38 files (28.9%) | **40/40 (100%)** |
| `88mph` | 0/43 files (0.0%) | **6/6 (100%)** + 6 correctly excluded |

**Two things worth carrying forward as method, not trivia:**

- **A written claim was wrong and is corrected in place.** An earlier note in
  this session said "~15% coverage". That came from the broken counter; the
  same data reads 32.7%, and after DEP-1 the affected repos read 100%. The
  bug understated the tool, which is why it survived — it never tripped the
  zero-FP alarm. Coverage is what this project tells a reader to consult
  before believing a quiet result, so a broken counter corrupts every
  judgement built on it.
- **The full suite caught a real bug in the COV-ACCT2 fix itself, failing in
  the dangerous direction.** The first attempt keyed "unsupported" off a flag
  rejection alone — but `solc_candidates` returns every installed compiler
  merely ranked, NOT pragma-filtered, so a 0.5.x candidate rejects the flag
  for any file including a broken one. That excused genuine syntax errors and
  inflated coverage. Now classified three ways (flag rejection / version
  mismatch / real error) and unsupported requires a flag rejection with no
  real error anywhere. Guard test names the hazard explicitly.

New tests: `tests/test_coverage_accounting.py` (9), `tests/test_remap_absolutize.py`
(8). **Gates, all read from raw output, not summarised:**

```
python -m pytest tests/ -q     227 passed, 0 failed, exit 0  (804s)
./guard.sh check               INTEGRITY OK
```

(The preceding run — DEP-1 in, COV-ACCT2 correction not yet — was `1 failed,
225 passed`, that one failure being exactly the dangerous-direction bug
described above. It is fixed and the failure is gone.)

Remediation map (all remaining weaknesses, ranked, with evidence):
<https://claude.ai/code/artifact/04315294-0c84-49d9-be64-8691c1787f42>

---

## STOP — read this before anything else in this file

**This is a NEW session on top of the one that produced everything from
"Five things shipped today" onward below** (that summary is now one arc
behind — kept intact further down as real history, not deleted). This new
session's own work is summarized here; the full detail is in TODO.md's
newest entry (top of the file), RULES.md's `CAPABILITY 14` and `CAPABILITY
12 addendum` sections, and LIMITATIONS.md's new `Capability 14` section.

**The user asked for**: a genuinely new, high-value capability for the live
web app — a real proof-of-concept for a finding, Gemini given "a realer
role" (active reordering of findings, not just report-drafting), maximum
coverage, zero false positives, never stop. Also asked me to review a
supplied `index.txt` UI mockup.

1. **Capability 14 (`src/exploit_proof.py`) — read-only exploitability
   proof.** The user's PoC request collided directly with an existing,
   deliberate CHARTER anti-goal ("never generate exploit code, calldata, or
   working PoC transactions, even in the LLM layer"). Per CHARTER.md's own
   line 4, stopped and asked rather than resolving it myself; the user chose
   the narrowest of three offered scopes. Built: for a CONFIRMED, LIVE
   finding on rules 1, 3a, 3b or 10 (the only rule classes where "an
   unprivileged `eth_call` succeeds" IS the vulnerability), one real
   read-only `eth_call` proving the exact regressed function is callable
   right now — never a transaction, never handed to a user as runnable
   exploit material. **9/9 unit tests pass.** Reused capability 13's own
   `probe()`/calldata-building unchanged.
2. **Real live verification, not just unit tests — CONFIRMED, with a
   genuinely new result.** Called `exploit_proof.prove()` directly against
   real mainnet RPC with the real 88mph `init(address,string,string)`
   signature against `0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634` (the
   shared implementation behind the 88mph NFT clones this project already
   established as LIVE): **`OPEN`** — genuinely new evidence nobody had
   checked before (earlier sessions verified bytecode liveness, never
   attempted the call). Etherscan corroborates: zero transactions in that
   address's history, ever. **Scope caveat, stated plainly, not chased
   further**: this checked the shared implementation, not one of the three
   actual value-bearing CLONE contracts — their exact addresses aren't in
   any file this repo carries (dynamically created by a Factory, no static
   deployment manifest) and would need an `eth_getLogs` lookup. See
   LIMITATIONS.md `§14-L1` for the full mechanism and fix direction.
3. **Capability 12's ranking tool — built once, never wired to a caller,
   now is.** `rank_findings`/`verify_ranking` existed with zero code path
   that ever invoked them. Added `save_ranking`, a dedicated ranking
   instruction, `agent/runner.generate_ranking`, and
   `POST`/`GET /api/scan/{id}/rank`. **Verified against the REAL Gemini
   API**, not mocked — two synthetic CONFIRMED findings, the agent called
   `rank_findings` → `verify_ranking` → `save_ranking` in order, correctly
   ranked the LIVE+exploit-proof-OPEN finding above the liveness-UNKNOWN
   one, citing only real fields. Transcript and saved ranking JSON are real,
   in `reports/`.
4. **`index.txt` reviewed and rejected as given, reasons stated to the
   user**: it listed Mythril/Echidna/Foundry as "Active" (this project runs
   none of them; CHARTER explicitly rules out competing with them; Foundry
   specifically cannot even be installed here per WALK-L9) and hardcoded a
   fake "CONFIRMED reentrancy in Uniswap's real SwapRouter" as a canned demo
   line regardless of what any scan finds. Its genuinely good part (dark
   violet/cyan glass aesthetic, glow, motion) was carried onto the REAL
   SSE-wired UI instead of replacing it.
5. **Full webapp wired end-to-end and smoke-tested for real**: new
   checkboxes (capability 13/14), exploit-proof badge + drawer section,
   exposure-probe panel, "Rank CONFIRMED findings" button + ordered list.
   Booted the local dev server, confirmed 0 console errors, then ran a REAL
   scan through the actual HTTP API (`POST /api/scan` with
   `check_exposure`/`check_exploit_proof: true`) against 88mph, confirmed
   the same CANDIDATE result round-trips correctly through pydantic →
   `ScanOptions` → `scan()` → the rendered findings table.
6. **Full test suite, capability-14 baseline — CONFIRMED.**
   `python -m pytest tests/ -q`: **202 passed, 0 failed.** `./guard.sh
   check` → **INTEGRITY OK**.
7. **Redeployed to Cloud Run — CONFIRMED live.** Human explicitly approved
   (`AskUserQuestion`, "Yes, redeploy now") after the 202-pass confirmation
   above. `gcloud run deploy chainwatch --source . --region us-central1
   --project chainwatch-ee1d1 --set-secrets=GEMINI_API_KEY=chainwatch-gemini-key:latest
   --min-instances 0 --max-instances 1 --cpu 2 --memory 4Gi --timeout 3600`:
   **revision `chainwatch-00006-spp`, serving 100% of traffic.** Verified
   live, not just "deploy exited 0": opened the real URL in a FRESH browser
   tab (a reused tab showed stale 404s from old SSE reconnects to
   since-expired job ids — a red herring, not a deploy problem) — 0 console
   errors, every request 200, the capability 13/14 checkboxes render.
   `curl .../api/agent` → `{"available":true,"model":"gemini-3.5-flash-lite",
   "rpm_budget":12}` — Gemini (and therefore the new ranking endpoint) is
   live in production. `/healthz` still 404s at the edge — the SAME
   pre-existing, already-diagnosed Google-routing quirk from an earlier
   session (not new, not a real health problem; the container's own
   healthcheck passes before Cloud Run ever routes traffic to it).
8. **SCAN-L2 (after the deploy above landed)**: the user, looking at a live
   CANDIDATE finding in the deployed UI, asked for a targeted second pass
   at exactly the missing evidence field - not a blind retry loop. Built
   `scan._renamed_path_at_head`: when a file is missing at HEAD, check
   whether it MOVED (real git evidence: rename pairing, then an unambiguous
   same-basename fallback) before giving up as undetermined. Also fixed a
   second bug it exposed - `_shared.accept_finding`'s attribution guard
   still checked the OLD path in `changed_files` after a rename was
   followed, silently suppressing the fire. **Applied to the real 88mph
   finding**: `reachability` went from a bare "not established" to a real,
   specific, verified answer - the regression was repaired at the true
   `v3` HEAD (`f4886f318d07`), not the stale `master` branch an earlier
   investigation's citation pointed at. See TODO.md's "SCAN-L2" entry and
   LIMITATIONS.md's `14-L2` for the full mechanism and why this closes a
   DIFFERENT gap than §14-L1 (the still-open clone-address lookup) rather
   than the same one.
9. **Full test suite, INCLUDING SCAN-L2's 8 new rename-following tests —
   CONFIRMED.** `python -m pytest tests/ -q`: **210 passed, 0 failed, exit
   0, 781.99s (13m01s)** — exactly 202 + 8 (`tests/test_head_rename.py`),
   confirmed clean, no regressions. `./guard.sh check` → **INTEGRITY OK**,
   re-confirmed fresh as the last check before this line was written.
10. **SCAN-L2 redeployed** — the user approved a second deploy; SCAN-L2 is
    now live too (`gcloud run deploy` again, same flags): **revision
    `chainwatch-00007-9xj`, serving 100% of traffic.**
11. **Full 10-rule deep audit, on explicit request.** Read every shipped
    rule (`src/rules/rule1.py` through `rule10.py`, ~2,850 lines total) end
    to end against RULES.md's own documented spec, plus a fresh,
    comprehensive fixture sweep: `scorer.py` run individually against
    every one of the 26 `fixtures*` directories (not just the default
    `fixtures/`), not from memory. **Result: 24/24 real scorer-compatible
    sets PASS, 0 FP, 0 FN anywhere** — the two "failures" in the raw log
    (`fixtures-foundry`, `fixtures-sizing`) are non-scorer support
    fixtures for unrelated features (no `manifest.json` by design, not a
    bug). Raw sweep output preserved this session at
    `$TEMP/scratchpad/all_fixtures.txt` if a fresh session wants to
    re-inspect it, though it will not survive past this session's scratch
    directory — re-run the same loop to reproduce.
12. **One real gap found — empirically verified UNSAFE to fix blindly, so
    it wasn't.** RULES.md's Rule 1 spec requires a Slither-detector
    cross-check (`suicidal`/`arbitrary-send`/`unprotected-upgrade`) before
    CONFIRMED; `rule1.py` never implements it (zero references anywhere in
    `src/`). Tested the literal spec against the project's own real,
    trusted Rule 1 fixture before writing any code: all three detectors
    produced **zero findings** on it — they are scoped to selfdestruct/
    ETH-sends/upgrades specifically and do not overlap Rule 1's actual
    domain (ordinary state-setters losing access control). Implementing it
    as written would silently downgrade nearly every real Rule 1 finding
    to CANDIDATE. **Not fixed — needs a human decision** on what RULES.md
    actually meant; three concrete resolution paths written up in
    LIMITATIONS.md's new Rule 1 entry, along with the exact Slither API
    (`register_detector`/`run_detectors`) confirmed to work, so a future
    fix doesn't need to rediscover it.
13. **Research re-verified with real substance, not just headline
    confirmation** — full content fetched (not summaries) for EF's
    "Triage is the Product" and ARQ (arXiv 2608.20637). Both independently
    validate this project's existing six-evidence-field architecture and
    the CANDIDATE-deepening work (SCAN-L2) as being aligned with actual
    frontier practice, not just internally consistent. ARQ's
    execution-grounded rule-refinement technique is named as a genuine,
    concrete future direction ("Capability 15" candidate) — not built,
    deliberately: a new capability needs its own scoping conversation.

**Nothing outstanding from this arc except the two items already named
above (§14-L1's clone address, and the Rule 1 spec-ambiguity needing a
human call) — everything else asked for this session is done, verified,
and live.**

**What remains, highest value first:**
- **SCAN-L2 is built, tested (8/8), and verified against the real 88mph
  repo, but NOT deployed** — the live Cloud Run service (`chainwatch-00006-spp`)
  predates it. A second, cheap redeploy would ship it; not done
  automatically because a deploy is an "ask first" action, not a default.
- **LIMITATIONS.md §14-L1**: find one of the 88mph NFT clone addresses
  (yaLINK/CRV:STETH/CRV:RENWBTC 88mph pools) via the Factory's
  (`0x95816Fa25D54061086d4f4aD9a48FDBe9068E541`) `eth_getLogs`
  `CreateClone(address)` events, then re-run `--check-exploit-proof`
  against it to get a full-pipeline CONFIRMED-with-exploit-proof
  demonstration. The mechanism is proven (capability 14 already returned a
  real `OPEN` against the shared implementation directly); only this
  specific historical address lookup remains, and it has now failed twice
  on real infrastructure limits (Alchemy free tier: 10-block `eth_getLogs`
  cap; `cloudflare-eth.com`: an 800-block cap hit a rate-limit-shaped
  `-32603` on the corrected retry) — worth trying a paid/keyed RPC
  provider rather than a third free-tier attempt.
- **Ranking not yet exercised against a REAL scan's 2+ CONFIRMED findings**
  end-to-end through the web UI's own button (only proven via the real
  Gemini API against synthetic records, and via the underlying
  tools/runner directly) — needs a real scan that produces 2+ CONFIRMED
  findings, which no target scanned this session did (88mph caps at
  CANDIDATE for the reason above, even after SCAN-L2).

---

## Prior session's arc (still real, still unread-committed, kept as history)

**Five things shipped that session, in order:** (1) a real CONFIRMED finding
proving the tool works end to end, (2) a NEW capability (live one-shot-
exposure probe), built off research into what 2026's actual attacker
methodology looks like, closing a gap the tool had ZERO coverage for, (3) a
real rule extension (Rule 3a's second trigger, `caller-set-widened`) closing
a gap RULES.md itself had already named but never implemented, (4) a second,
independent real-world reproduction of an already-known bug (3x-L1) that
turned out to still be live on the project's own highest-priority rule
family (3a/3b/3c) despite being fixed everywhere else — found live on a
fresh 2026 target (Kinto), fixed the same session, (5) **WALK-L11**: a real
crash, on real content, found scanning `1inch/swap-vm` locally — 12
subprocess call sites decoding output with the OS locale instead of UTF-8,
crashing on ordinary emoji/international commit content. Fixed and now
fully reconfirmed (full suite green, real crash repro complete without
dying — see items 1–2 above). Read all five sections below before touching
`scan.py`, `verdict.py`, `history.py`, `src/exposure.py`,
`src/rules/rule3a.py`, `src/rules/_shared.py`'s test-path matchers, or any
`subprocess.run` call again.

**Also this session, not yet written up anywhere else:** the deployed
Cloud Run service's `max-instances` was dropped from `2` to `1`
(`chainwatch-00005-9tq`) after a real reproduced bug — two replicas with
no shared job state meant a client reconnecting mid-scan could 404 against
the *other* replica within moments of starting. Confirmed fixed. Attempted
a live UI scan of `1inch/solidity-utils` (311 commits) through the deployed
webapp — the job was lost server-side (same in-memory-state class of issue,
`min-instances:0` still means an idle gap can drop state; not chased
further since it's the same known limitation, not a new bug). Checked
again just before this handoff was written: the deployed page shows a
fresh "No scan yet" — the job is genuinely gone, not paused.
`1inch/solidity-utils` is cloned locally
(`realworld-test/1inch-solidity-utils`, 311 `.sol`-touching commits) but
**was never scanned locally** — next real step if this thread continues.

**Headline: CHARTER success criterion 6 is now genuinely met, by the shipped
tool itself, not by manual reconstruction of its logic.** A real CONFIRMED
finding (88mph `NFT.init()`, all six evidence fields, byte-exact liveness
proof against real mainnet RPC) — where PHASE 6's own prior entry had
concluded the criterion was structurally unsatisfiable — now comes out of the
**unmodified `scan()` pipeline itself**: `[done] findings=1 confirmed=1
candidates=0`. See "CHARTER criterion 6 satisfied" below before anything
else.

Read `CHARTER.md` first (it is the contract), then this file.

---

## State: verified green

Every number below is from a command whose raw output was read, not a summary.

```
./guard.sh check                     INTEGRITY OK
python -m pytest tests/ -q           193 passed, 0 failed    (FULL suite, no subset, 893.45s)
```

Every scorer-compatible fixture set (24 directories now — the two new ones
from the prior session, `fixtures-r4-extract` and `fixtures-r10-safeerc20`,
already counted — 2 of them needing `--remaps oz5`) re-run individually after
every change this session: all PASS, 0 FP anywhere.

**Run the FULL suite, never a subset** (`tests/test_realworld_reserve.py` is
~4 min and matters most). The suite takes ~8–9 min end to end.

---

## CHARTER criterion 6 satisfied: real CONFIRMED finding, 88mph NFT.init(), still live today

Full evidence chain, mechanism, and all three code fixes that unlocked it are
in **TODO.md's "Session 2026-08-26 (continued)"** entry and
**LIMITATIONS.md §11-L1/§11-L2/§11-L3** — read those before touching
`verdict.py`, `scan.py`'s liveness path, or `history.py`'s install/link code
again. Short version: an EIP-1167 clone's implementation is immutable, so
"the source was fixed" and "the deployed code is still vulnerable" can both
be true at once, with no responsible-disclosure conflict, if (as verified
here) the specific instances hold no funds.

Three fixes, found in sequence, each necessary before the next became
visible:
1. **§11-L1** — `verdict.py` gained `update_survival()`; `scan.py`'s
   `_attach_liveness` gained an immutable-clone fallback (recompile from the
   regression commit, not HEAD, for a structurally-confirmed EIP-1167 clone
   target) plus a real optimizer-runs fix.
2. **§11-L2** — fixing §11-L1 exposed that Rule 10's OWN compile was silently
   failing for an unrelated reason: a dangling NTFS junction (a stale
   dependency-cache link whose target had been cleared) that neither
   `_link_dir` nor `_unlink_node_modules` could detect, because both used
   `.exists()`/`.is_symlink()`, which report **False** for a junction whose
   target is gone — `os.path.lexists()` does not have this blind spot. Fixed
   in `src/history.py`, locked by `tests/test_install_link.py`.
3. **§11-L3** — fixing §11-L2 let the pair itself compile, which then exposed
   that the liveness fallback's OWN compile (`_runtime_bytecode`) has *never*
   pinned a compiler version — it trusted whatever solc-select's ambient
   global version happened to be, which by that point in a run is whatever
   the rule-compile path last left it at for a completely different file.
   Fixed by setting `SOLC_VERSION` the same way `_shared._compile_attempt`
   already does, just previously only in that one function.

**Verified with the real, unmodified pipeline, not a workaround**:
`scan()` with `explicit_pairs=[('5f52a2ead702...', 'a4c48d61661a...')]` and
the real mainnet `--address`, no stubbing: `"verdict": "CONFIRMED"`,
`"downgrade_reasons": []`, `"liveness": "LIVE"`. This is what
`chainwatch.py`'s CLI does internally too (the explicit-pairs form only skips
re-walking unrelated history, which is why it was used for the check — a
`--limit`-bounded full walk back to 2021 was not).

---

## Capability 13 and Rule 3a's second trigger — two real additions, not just fixes

**Capability 13 (`src/exposure.py`)** — a live one-shot-exposure probe,
motivated by real research into the current (2026) attacker landscape
(published as an artifact, "Chainwatch 2026"): automated scanners hunt
freshly-deployed-but-uninitialized proxies and race legitimate deployers to
seize them (one cited study: 183 cases, 56% still exploitable long-term).
Rule 3b only ever asked "was the guard removed"; this asks "has the window
been claimed yet" — a live, present-tense question, deliberately kept OUT of
the CONFIRMED/CANDIDATE verdict model. `--check-exposure` on the CLI. 12
tests, including calldata construction verified against the real 88mph
signature and candidate identification verified against a real compiled
fixture. **Live validation attempt** (Kinto's `$K` token, a real named 2025
CPIMP campaign victim) surfaced something real and serious enough that it was
deliberately stopped short rather than pursued further — see TODO.md's
"hunted for a second real finding" entry before touching that thread again.

**Rule 3a's second trigger, `caller-set-widened`** — closes 3a-L2, a gap
RULES.md's own trigger text already named ("the caller set widened") that the
shipped implementation only partially covered (it caught the constraint
disappearing, not the constraint surviving while what it checks against
becomes attacker-controllable). Built by composing two already-trusted
pieces — Rule 10's own `_classify` for unguarded-writer detection, the
existing msg.sender-dependency helpers — rather than new heuristics, which is
why it scored 1.00/1.00 on the first real run. Surfaced a second, genuinely
pre-existing (not new) gap in the process: `_authorizeUpgrade` findings have
never been able to reach CONFIRMED, from either trigger, because UUPS's
`_authorizeUpgrade` is `internal` by design and the reachability model has no
notion of "internal but reachable through an inherited external entry point".
Both gaps are now named findings (LIMITATIONS.md §3a-L2/§3a-L4), not silent
holes. Full writeup: TODO.md "3a-L2 closed" entry.

---

## Uncommitted this session (2026-08-25 → 2026-08-26) — nothing has been committed

Per the operating instructions for this session, no commit was made without
the human's explicit go-ahead, even though `CHARTER.md` rule 6 says "commit
after every green gate." `git status --short`, re-checked fresh at the point
this file was written (now includes the WALK-L11/Capability-13/3x-L1 arc on
top of the earlier list):

```
 M HANDOFF.md
 M LIMITATIONS.md
 M RULES.md
 M TODO.md
 M agent/runner.py
 M agent/store.py
 M agent/templates.py
 M agent/tools.py
 M chainwatch.py
 M src/history.py
 M src/rules/_shared.py
 M src/rules/_storage.py
 M src/rules/rule10.py
 M src/rules/rule3a.py
 M src/rules/rule3b.py
 M src/rules/rule3c.py
 M src/rules/rule4.py
 M src/scan.py
 M src/verdict.py
 M tests/test_verdict.py
 M webapp/server.py
 M webapp/static/app.js
 M webapp/static/index.html
 M webapp/static/style.css
?? .claude/
?? fixtures-r10-safeerc20/
?? fixtures-r3a-widen/
?? fixtures-r4-extract/
?? realworld-test/1inch-aqua/
?? realworld-test/1inch-solidity-utils/
?? realworld-test/1inch-swap-vm/
?? realworld-test/88mph-vuln-worktree/
?? realworld-test/kinto-core-src/
?? src/exploit_proof.py
?? src/exposure.py
?? tests/test_dedupe.py
?? tests/test_exploit_proof.py
?? tests/test_exposure.py
?? tests/test_git_encoding.py
?? tests/test_install_link.py
?? tests/test_retry_diagnostics.py
?? tests/test_rule_registry.py
```

(`agent/*.py` and `webapp/static/*` are the new-this-session additions on
top of the prior list: capability 14, capability 12's ranking wiring, and
the `index.txt`-inspired visual pass.)

`.guard-hashes` was re-frozen (`./guard.sh freeze`) to include all new
fixture sets across the arc — that file is itself untracked-by-git-status
here only because it is gitignored, but it changed on disk and matters for
`guard.sh check` to stay green on the next machine (reconfirmed
**INTEGRITY OK** as the very last check before this handoff was written).

The `realworld-test/*` clones and `.claude/` are scratch/tooling directories,
not deliverables — safe to leave, safe to delete, not meant to be committed.

---

## Shipped this arc (eight real fixes + two live end-to-end proofs, all fixture/test-locked)

| Finding | What | Locked by |
|---|---|---|
| **WALK-L7** | Invariant test: `set(RULES) == set(RULE_ORDER) == set(RULE_TITLES)`, so a rule silently registered-but-unscheduled (Rule 10's old failure mode) fails loudly | `tests/test_rule_registry.py` |
| **RC-DEDUP1** | `scan.py` stamped every finding's `file` with whichever file the walker happened to be compiling, not the file that actually declares the fired contract — on Uniswap v3-core this produced the SAME finding twice under two different filenames. Fixed attribution (`_repo_relative`) + added dedup (`_dedupe`), called once after the full walk, before liveness | `tests/test_dedupe.py` (12 cases) |
| **RC-EXTRACT1** | Rule 4 was blind to a checked-arithmetic call EXTRACTED into a new helper rather than removed outright (the documented Aave v2 case — see correction below). Now evaluates `reachable(fn)` like rules 2a/2b already do | `fixtures-r4-extract/` (P4x-01, N4x-01, N4x-02) |
| **Rule 10 SafeERC20 widening** | `safeTransfer`/`safeTransferFrom` (Reserve's pattern throughout) compile to a `LibraryCall`, invisible to the old ERC20 destination check. Measured the real Slither IR shape (`using X for Y` receiver rides as `arguments[0]`) before writing the fix | `fixtures-r10-safeerc20/` (P10se-01, N10se-01, N10se-02) |
| **Retry-loop diagnostics** | `_shared._compile_attempt` / `_storage.storage_layouts` reported only the LAST fallback candidate's error, hiding the real cause (METHODOLOGY Face A — three prior wrong diagnoses). Now reports both first (ambient) and last attempts. **Confirmed still costing real coverage TODAY** on `1inch/farming`, a repo no prior session had touched | `tests/test_retry_diagnostics.py` |
| **RC-VERDICT1** | Rule 4's `safemath-removed` and `unchecked-block-added` triggers, plus Rule 3b's `disableInitializers-removed` and Rule 3c's OZ5 ERC-7201 trigger, could **never reach CONFIRMED**, at all, regardless of liveness — evidence-key mismatches between each rule's `emit()` and `verdict.py`'s `PRE_POST`. Fixed via `PRE_POST_BY_TRIGGER`, keyed on each rule's own trigger/mode evidence field | `tests/test_verdict.py` (5 tests) |
| **Rule 3b reachability fix** | Even after RC-VERDICT1, the `disableInitializers-removed` trigger STILL couldn't reach CONFIRMED — it fires on a contract, not a function, and had no `visibility_after`/`writes_state_after`. Fixed via `_contract_initializer()`, which resolves the contract's own critical-config initializer (the real exposed surface) and reports ITS facts | `tests/test_verdict.py` (2 tests) |
| **RC-VERDICT2** | **Found live, scanning the real 88mph exploit** (see below): Rule 10 — the rule literally built to catch this exact $6.5M Immunefi case — could never reach CONFIRMED for ANY finding, ever. Its one `emit()` call never set `writes_state_after` at all. Fixed: `bool(fn_a.all_state_variables_written())` | `tests/test_verdict.py` (2 tests, one is a regression guard against the key silently disappearing again) |

**Two live end-to-end proofs, with real Gemini-generated dossiers shipped as
files:**
1. **Reserve Protocol** — anchored the real historical pair
   (`f43202a3c5b2..e27227b2919b`), ran with the real mainnet `ActFacet`
   address and `--generate-reports` in one command. Reproduced the documented
   CANDIDATE (Rule 5), checked liveness against the real RPC (`UNKNOWN`,
   correctly attributed to a compiler-settings mismatch, not guessed),
   Gemini drafted and mechanically re-verified `ActFacet_195a6ed78d6c.md`.
2. **88mph** — anchored the real, publicly-disclosed `NFT.init()` exploit
   commit, ran the same way with 88mph's real EIP-1167 clone address. THIS is
   what surfaced RC-VERDICT2 above. Liveness came back `UNKNOWN` here too —
   diagnosed as a methodology artifact (an anchor pinned exactly at the
   regression commit makes "HEAD" trivially equal to the regression itself,
   not the repo's true current HEAD; the real HEAD's `NFT.sol` has since been
   rewritten twice, including a full solc version upgrade) rather than a tool
   bug, and NOT chased further (would cost a ~159-pair real walk for a data
   point this session didn't need).

**RC-VERDICT1/2 are the ones worth reading before touching `verdict.py` or
any rule's `emit()` again.** A rule can be correctly registered in `PRE_POST`
at the rule-id level and still be broken — either because it fires from more
than one trigger shape and only one populates the registered keys
(RC-VERDICT1), or because its ONE emit site simply never set a required key
at all (RC-VERDICT2, found on a single-emit-site rule the multi-emit-site
audit couldn't have caught). The existing guard test only checked rule-id
presence. `PRE_POST_BY_TRIGGER` is the fix; nothing enforces that *every*
trigger shape of *every* multi-emit rule stays consistent going forward
except manual audit (done once, this session, for rule2a/2b/3b/3c/4 — the
multi-emit-site rules — plus rule10, found only by scanning real code, not
by that audit).

**One correction recorded, not quietly edited.** TODO.md previously cited
Aave v2 `20bbae88d399` as a real-world case RC-EXTRACT1's fix should catch.
Anchored a worktree at that exact commit and re-ran chainwatch against it:
**0 findings, 3/3 files compiled OK, 0 rule errors.** Reading the actual diff
shows why that is CORRECT: the extracted helper (`_swapLiquidity`) still
calls SafeMath's `.add()`/`.sub()` — the checked call relocated, it did not
disappear. That citation is retracted as a demonstrated positive; the fix
itself remains correct, proven by the synthetic `fixtures-r4-extract` pair.

---

## Live-scanned this session — no NEW real finding, but real signal

Scanned all 8 explicitly requested `1inch/*` repos plus several self-selected
real targets (compound-v2, aave-v2 anchor commit, limit-order-protocol,
token-plugins, farming), hunting for a genuinely new CONFIRMED/CANDIDATE
finding. **None surfaced.** What the hunt actually produced:

- Both Solana repos (`solana-fusion`, `solana-crosschain-protocol`) correctly
  reported "no Solidity files tracked" — `MULTICHAIN-SCOPE.md`'s existing
  scope boundary working as designed, not a gap.
- `cross-chain-swap` / `delegating` hit the pre-existing, already-diagnosed
  Foundry nested-remapping ceiling (COMP-L2) — charter-bounded, not chased.
- **COMP-L3 (NEW finding, documented in LIMITATIONS.md):** `1inch/farming`
  hit a genuine `Stack too deep` compile failure needing `--via-ir`, on code
  no prior session had seen. Not fixed — a real semantic build-config change,
  correctly deferred rather than rushed.
- `1inch/fusion-protocol`'s own HEAD environment failed to reconstruct
  (`dep-missing`) — not diagnosed further.
- `1inch/limit-order-protocol`'s dependency install itself timed out at
  ~25 minutes with no cache hit — genuinely slow/unreliable on this box, not
  diagnosed further.
- `v3-core`, `reserve-protocol`, `token-plugins`, and part of `farming`
  compiled clean with 0 findings. `token-plugins` has a real historical
  reentrancy-FIX commit sequence that Chainwatch correctly stayed silent on
  — it detects controls REMOVED, not ADDED; a pre-existing bug being patched
  is out of scope by charter, not a miss.

The retry-diagnostics and RC-VERDICT1 fixes above were both found *during*
this hunt, from reading real `rule_errors` and reasoning about what a real
CONFIRMED finding would require — not from the original plan.

---

## The Foundry ceiling (COMP-L2 — read before "improving" coverage)

Unchanged from last arc. Deeply nested submodules (`limit-order-settlement` →
its own `lib/` for `@1inch/st1inch`, `@1inch/delegating`) each resolve imports
in **their own** remapping context; bare solc holds **one flat** remapping
set. The tool that resolves this correctly is `forge`, which **CHARTER rule 3
forbids installing** (WALK-L9 RCE class). Charter-bounded ceiling, not a
patchable bug. Reconfirmed this session against the actual `1inch/cross-
chain-swap` and `1inch/delegating` repos, not just the old citation.

---

## Live deployment (kept up through judging, per the owner)

- **URL:** <https://chainwatch-898260334135.us-central1.run.app> · project
  `chainwatch-ee1d1` / `us-central1` · `2 vCPU / 4 GiB`, timeout `3600s`,
  min/max `0/1` (max dropped from 2 → 1 THIS session, see below),
  `GEMINI_API_KEY` via `chainwatch-gemini-key:latest`.
- **Teardown when done:** `gcloud run services delete chainwatch --region us-central1`.
- **`max-instances` fixed 2 → 1 this session** (`chainwatch-00005-9tq`):
  two replicas with independent in-memory `JOBS` dicts meant a client
  reconnecting to `/api/scan/<id>/events` or `/cancel` moments after
  starting a scan could 404 against the wrong replica — reproduced live on
  `1inch/swap-vm`. `webapp/server.py` already documents single-scan-at-a-
  time as the design; `max-instances:1` just makes Cloud Run's scaling
  match that design instead of silently violating it.
- **`min-instances:0` NOT changed** — a real, separate, still-open issue:
  scale-to-zero after an idle gap (~25 min observed) drops all job state,
  independent of the replica-count bug above. Fixing it means
  `min-instances:1`, which is a **recurring cost**, not a code fix —
  deliberately left for the human to decide, not changed unilaterally.
  Reproduced twice this session, most recently on a live
  `1inch/solidity-utils` UI scan attempt (job gone; confirmed via the
  deployed page showing a fresh "No scan yet" state).
- **UPDATE, new session, same day**: the image WAS rebuilt and redeployed —
  see the STOP box item 7 above for the exact command and verification.
  Current live revision is `chainwatch-00006-spp`, carrying everything
  through capability 14 and the ranking wiring. This paragraph's "not
  rebuilt" was accurate for the PRIOR session only.

## Open (submission-readiness — needs the human)

- **Repo has NO git remote** — not on GitHub yet. Push, then make public or
  grant `testing@devpost.com` / `cloudhackathons@google.com` access. See
  `SUBMISSION-DRAFT.md §3`.
- Demo video not recorded; Devpost form not submitted.
- **Deadline: 2026-08-31 17:00 PT — 6 days out as of this session.**
- **This session's changes are uncommitted.** Review the diff, then commit
  (or ask for a commit) before anything else touches these files.

---

## What remains (highest value first)

1. **`1inch/swap-vm`'s 152/155 lost file comparisons** — new this session,
   real and measured, NOT yet diagnosed. See STOP box item 3 above for the
   exact numbers and the raw report path. Highest-value next step: read the
   actual per-file errors (the JSON's `rule_errors`/skip reasons, not just
   the summary count) before guessing at a cause.
2. **`1inch/solidity-utils` never scanned** — cloned locally
   (`realworld-test/1inch-solidity-utils`, 311 `.sol`-touching commits),
   the live Cloud Run attempt lost its job state (known `min-instances:0`
   limitation, not a new bug). Run it locally instead:
   `python chainwatch.py --repo realworld-test/1inch-solidity-utils --limit 40`
   (or higher — 311 commits total).
3. **Rule 3b's `disableInitializers-removed` trigger still cannot reach
   CONFIRMED**, for a reason separate from (and found while fixing)
   RC-VERDICT1 — see TODO.md's dedicated entry. Needs a fixture-first pass
   (this trigger has never fired under any fixture) before attempting either
   candidate fix direction.
4. **COMP-L3 (`--via-ir` support)** — real coverage loss, measured live,
   fix direction documented in LIMITATIONS.md, not attempted (real
   build-config change, needs its own fixture).
5. **Rule 3c compiler floor** (`--combined-json storage-layout` unsupported
   below ~solc 0.6.x) — the retry-diagnostics fix makes the SYMPTOM legible;
   the underlying "report UNSUPPORTED not ERROR" fix still needs a new
   outcome type threaded through `_run_rule`/`Coverage`/report renderers — a
   real schema change, deliberately not rushed this session.
6. Everything else in the pre-existing backlog is unchanged — see TODO.md's
   "Session 2026-08-25" section at the top for this arc's full detail, and
   everything below it for what was already open before this session.

`TODO.md` carries the full open list; `LIMITATIONS.md` carries every defect
class with mechanism/evidence/scope/fix-direction, including the new COMP-L3
entry and the corrected RC-DEDUP1 note under RC-MUTEX1's "secondary
observation". **METHODOLOGY** in `LIMITATIONS.md` — read it before diagnosing
any retry-loop or "empty set" symptom; this session's retry-diagnostics fix
is a direct application of Face A, and RC-EXTRACT1's correction is a fresh
instance of the "empty set" table's entry #6.
