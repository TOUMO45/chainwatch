# Deferred (documented in LIMITATIONS.md, not yet fixed)

## Session 2026-08-28 (continued) — Counterfactual Protocol Twin, commits 2/3 + 3/3 finished

Told to finish the Twin (a trace-driven complement to NEXTGEN: reason from
real on-chain behaviour, not git history/source), test it, improve it, then
test how it works together with the rest of the project - no check-ins.

**Commits 2/3 (Phases 3-5) and 3/3 (Phases 6-10 + orchestrator) both done.**
Full architecture and phase notes: `NEXTGEN.md`. Nine boundary miners
(Phase 3), cross-version divergence wired automatically off observed
implementation upgrades (Phase 4), all ten mutation kinds generating real
`{from,to,value,data}` calls with two honestly-documented approximations
(Phase 5), real Anvil-fork replay + delta-debug minimisation (Phase 6/8),
six conservative violation checks (Phase 7), and the orchestrator wiring
Phase 9 (`deployment.run` + `provenance.run` - the latter deliberately
always INCOMPLETE for the Twin, since it never reads a git commit) and
Phase 10 (Skeptic sweep + a genuinely blind fresh-fork reproducer) into a
verdict rule stated directly in `twin.py`.

**One real bug, caught by the test suite itself, not a user report**:
`ReplayResult.executed` read `True` for a call whose `send_tx` outright
raised (a submission failure), because a failed call still appended one
trace entry, satisfying the buggy `len(traces) == len(calls)` check.
`tests/test_nextgen_twin_replay.py::test_replay_records_send_failure_without_raising`
failed on its first run against the real WSL/Anvil toolchain - fixed by
tracking submission success explicitly rather than inferring it from a
count. Full writeup: `LIMITATIONS.md` -> `TWIN-L1`.

**Verified real, not just unit-tested**: a full `CounterfactualTwin.run()`
end-to-end against real WETH mainnet data through an actual WSL Anvil fork
- collection, enrichment, boundary mining, mutation generation, multi-fork
replay, minimisation, and Phase 9/10 validation, all for real - completed to
a valid verdict TWICE (once at a wide 400-block window inside a full suite
run, once narrowed to 20 blocks standalone after the TWIN-L1 fix).
`chainwatch.py --twin <address> --blocks lo:hi` wired.

New tests: `tests/test_nextgen_twin_{boundaries,diverge,mutate,replay,checks,twin}.py`
(75 pure + 2 real Anvil-fork integration tests, one of the two run twice at
different window sizes). Combined Twin suite (all 9 files, commits 1-3):
**92 passed, 0 failed**. Whole-project suite: **679 passed, 3 skipped, 0
failed** (1823s). Committed as `c009873` (2/3) and `0430fbb` (3/3).

## Session 2026-08-28 — professional security audit: 3 real findings against Chainwatch's OWN infrastructure, all closed

Different question from every prior session: not "does the tool detect a
regression correctly", but "can a malicious target repository, or a
malicious caller of the public web app, attack Chainwatch itself". Found
and fixed three (LIMITATIONS.md `SEC-L1`/`SEC-L2`/`SEC-L3`); checked and
confirmed three adjacent classes were NOT vulnerable rather than assuming so
(`git clone` argument injection via the web form's `repo` field — blocked
structurally by the existing `CLONE_SCHEMES` prefix gate; stored XSS in the
Gemini-report/diff renderers — `mdToHtml()`/`esc()` already escape correctly;
`agent/store.py`'s own unprotected-argv `git diff` call — its `commit`/
`parent` values are hash outputs, never attacker-reachable text, so nothing
to fix).

**SEC-L1**: a tracked git symlink in a malicious target repo could read
arbitrary host files through the exact paths every rule and compiler already
opens with no sandbox — inert on this Windows dev box (`core.symlinks=false`,
measured directly) but real on the Linux/Cloud Run production target. Fixed
by deleting every symlinked entry immediately after checkout, at all 5 real
checkout call sites.

**SEC-L2**: `webapp/server.py`'s public `rpc_url` field reached
`Web3.HTTPProvider` with zero validation — a live SSRF path to
`169.254.169.254`, the cloud metadata endpoint, on the real Cloud Run
deployment. Fixed with a scheme + resolved-address validator at the shared
`liveness._w3()` choke point every caller already routes through.
**Left open, stated honestly, not silently unfixed**: this is
validate-then-use, not pinned-connection, so it does not defend against DNS
rebinding (a domain resolving to a public IP at check time and a private one
moments later at request time) — closing that needs a custom transport
adapter pinning the already-validated IP; real, separate work, deliberately
not bundled into this fix.

**SEC-L3**: `prev`/`cur`/`rev` on the public diff/source endpoints reached
`git diff`/`git show` as unprotected argv content — `--output=<path>` alone
is an arbitrary-file-write primitive, reachable pre-authentication. Fixed
with a strict hex-SHA shape check on all three, matching what these fields
are ever legitimately populated with.

New tests: `tests/test_symlink_strip.py` (7), `tests/test_rpc_ssrf_guard.py`
(9), `tests/test_diff_source_arg_injection.py` (15). Full suite and
`guard.sh check` both run clean before commit — see HANDOFF.md's newest arc
for the exact gate output.

## Session 2026-08-27 (continued) — DEP-3, MONO-L1's third measured cause, and 3b-CONF closed

Told to act on my own judgement as the domain expert, no further check-ins.
Worked the map's remaining items in priority order: Soldeer support
(unblocks a real, growing 2026 Foundry package-manager class), Balancer's
still-unverified MONO-L1 case, then Rule 3b's untested trigger.

**DEP-3 CLOSED (LIMITATIONS.md).** `src/soldeer.py` (Capability 18) resolves
both `[dependencies]` shapes (registry-hosted zip, git-pinned shallow fetch)
without executing `forge`/`soldeer` (CHARTER rule 3). Two real bugs found
only by testing end-to-end against `term-structure/termmax-contract-v2`, not
in isolation: a full `git clone` of `@chainlink-contracts`'s upstream
monorepo hung indefinitely (fixed to a shallow, rev-targeted fetch: 33.5s
measured, not minutes+); and even after every dependency resolved, every
pair still reported `dep-missing` because the pre-flight import scan had
never learned to exclude Soldeer's `dependencies/` directory, so a vendored
package's OWN transitive imports were counted as the target's missing ones.
Verified end to end: `0/12 (0.0%) -> 12/12 pairs (100%), 190/290 rule checks
(65.5%)`.

**MONO-L1's third measured cause (LIMITATIONS.md).** Balancer v3's own case
was flagged unverified last entry. Measured directly rather than left as an
assumption: a real, isolated `yarn install` ran to completion in 10m1s and
failed on a checksum mismatch for a git-fetched dependency
(`@zksync/contracts`) — a THIRD distinct root cause, on a third monorepo.
Three real cases measured, three different causes, and "large repository,
give it more time" was wrong every single time. Signature added to
`_REGISTRY_GONE`; verified via `H.install()` against the real checkout
(`cause: dep-gone-from-registry`).

**3b-CONF CLOSED (LIMITATIONS.md).** Rule 3b's `disableInitializers-removed`
trigger had never fired under any fixture since it was written. Read the
logic against RULES.md and Trigger 1's own already-proven real-OZ5 fixture
pattern; it needed zero code changes — only `fixtures-r3b-disableinit/`
(1 positive, 3 negatives, each isolating a different false-positive risk).
`precision 1.00, recall 1.00`. Full evidence chain confirmed to reach genuine
CONFIRMED-eligibility, not just "fires".

Suite 304 -> 319 passing (+15 tests: 5 dead-git-dependency, 17 Soldeer minus
2 network-gated by default). 26 fixture sets (25 -> 26, `fixtures-r3b-
disableinit` added), 0 FP; `guard.sh freeze` re-run to lock the new set in.

Still open: ANCHOR-1/BACKTEST-1/CORPUS-1 (already shipped earlier this
session, unaffected), RULE1-SPEC (needs the human decision already written
up in LIMITATIONS.md's Rule 1 section — three resolution paths, none of them
an engineering fact this session can settle by measurement alone).

## Session 2026-08-27 — the coverage arc: two accounting bugs and one total false negative, all measured before/after

The user asked for a map of every weakness and then "do it". The map
(published as an artifact) ranked P0 measurement integrity above P1 coverage,
on the argument that you cannot prioritise what you cannot measure. Executed
in that order; the argument held, and the P0 work is what made the P1 root
cause findable.

**COV-ACCT1 + COV-ACCT2 (LIMITATIONS.md).** Coverage was scored per file but
earned per rule, and an inapplicable rule was recorded as a failed one. 88mph
reported `0/43 (0.0%)` while 387/430 rule invocations had in fact succeeded.
Fixed via `_shared.RuleUnsupported`, a fourth `_run_rule` return value,
per-invocation counters, and three file buckets. CLI and web UI both render it.

**DEP-1 (LIMITATIONS.md).** The headline. A repo's own `remappings.txt` holds
checkout-relative targets and is appended last (so an explicit entry wins),
which overrode the absolute remappings `derive_remaps(absolute=True)` had just
derived. `Slither()` takes no cwd, so solc ran from Chainwatch's own root and
every import failed as "not found" — on a correctly installed dependency tree.
`1inch/swap-vm` 0/1160 → 80/80. `1inch/aqua` 28.9% → 100%.

**Method notes worth keeping:**

1. **Five hypotheses were eliminated by measurement before the real cause was
   accepted** — package not installed (it was), file missing (it existed), all
   8 imported files present in the installed version (they were), remap list
   broken (it compiled fine from the worktree cwd). The cause was only accepted
   after reproducing the sweep's error *byte-for-byte* by running the same
   remap list from Chainwatch's root. The map's own written guess (npm
   workspaces) was wrong, which is exactly why it said "instrument before
   fixing".
2. **The full suite caught a real bug in the COV-ACCT2 fix, failing in the
   dangerous direction.** `solc_candidates` returns every installed compiler
   merely ranked, not pragma-filtered, so keying "unsupported" off a flag
   rejection alone excused genuine syntax errors and inflated coverage. Now
   three-way classified; guard test added that names the hazard.
3. **A written claim from earlier in the session ("~15% coverage") was wrong
   and was corrected in place rather than quietly dropped.** It came from the
   broken counter.

Still open from the map, unchanged: ANCHOR-1 (deployment anchoring),
BACKTEST-1 (incident-anchored backtesting), CORPUS-1, DEP-2 (aave-v2 /
compound-v2 `dep-missing`), COMP-L3 (`--via-ir`), 3b-CONF / 3a-L4, RULE1-SPEC.

## Session 2026-08-26 (same session, continued) — full 10-rule deep audit, one real spec-vs-implementation gap found and NOT blindly fixed

Direct follow-up to the user's instruction: redeploy SCAN-L2, dig deeper into
external research for scanning ideas, then review every shipped rule
carefully and fix any real problem found.

**Redeployed SCAN-L2** to Cloud Run (`chainwatch-00007-9xj`, 100% traffic) -
the rename-following fix from the prior entry is now live.

**Research re-verified with real technical substance**, not just headline
confirmation - fetched full content, not summaries. EF's "Triage is the
Product": the actual pipeline is recon → hunting → gap-filling → validation,
every candidate needs an observable "Success" proof field (structurally the
same idea as this project's six required evidence fields - real external
validation the architecture is right), and their three recurring FP patterns
were checked against Chainwatch's own rules (see below). ARQ (arXiv
2608.20637): genuinely novel - synthesizes test programs, uses disagreement
between EXECUTION and a query's verdict as ground truth to auto-refine the
query, no labeled data needed, up to 119.8% more true positives at ≥98%
precision. Worth naming as a real future "Capability 15" direction (an
agent that generates boundary-condition Solidity variants per rule and
flags disagreement with real compiled/simulated behavior as CANDIDATE
fixtures for human review) - not built this session, deliberately: a new
capability needs its own scoping conversation, not a decision made
mid-audit.

**Full 10-rule audit, read end to end against RULES.md's own spec, plus a
fresh, comprehensive fixture-set sweep (`scorer.py` against all 26
scorer-compatible `fixtures*` directories individually, not just the
default `fixtures/`).** Nine rules check out clean: implementation matches
documented trigger/exclusions, `verdict.py`'s `PRE_POST`/`PRE_POST_BY_TRIGGER`
wiring is complete for every emit site, and every fixture-set score is
precision 1.00 with 0 FP (see HANDOFF.md for the exact sweep output).

**One real gap found, empirically verified as unsafe to implement literally
- documented, not blindly coded.** RULES.md's Rule 1 section requires
"Slither's own `suicidal`/`arbitrary-send`/`unprotected-upgrade` detectors
run at HEAD as a cross-check; disagreement → CANDIDATE, not CONFIRMED" -
`rule1.py` never implements this (confirmed: zero references to Slither's
detector API anywhere in `src/`). Before writing code, tested whether the
literal spec is even safe: ran the real detectors (`Slither.
register_detector`/`run_detectors()`, the same API Slither's own CLI uses)
against the project's own existing, precision-1.00 Rule 1 fixture
(`FeeManager.setFee` losing `onlyOwner`) - **all three detectors produced
zero findings.** They are narrowly scoped to selfdestruct, ETH-sends, and
upgrade functions specifically; Rule 1's actual domain (any state-setter
losing access control) does not overlap them at all. Implementing the spec
literally would downgrade essentially every real Rule 1 finding to
CANDIDATE, including the project's own trusted fixture - a severe, silent
recall collapse for zero precision benefit. **Not fixed - needs a human
decision on what RULES.md actually meant** (narrow the cross-check to only
apply when a finding's subject overlaps these detectors' domain, swap in
genuinely-overlapping detectors, or drop the requirement as an
aspiration that never matched Slither's actual stock coverage). Full
mechanism, evidence, and three concrete resolution options in
LIMITATIONS.md's new "Rule 1 — RULES.md's own Slither-detector cross-check
requirement is unimplementable as written" entry.

## Session 2026-08-26 (same session, continued) — SCAN-L2: `_head_survival` treated "moved" the same as "deleted," discarding a real, checkable fact

Direct follow-up to the user's own instruction after seeing a CANDIDATE
finding in the live UI: don't blindly retry, but DO run a clever, targeted
second pass at exactly the missing evidence field, and report whether it
settles the question either way.

**The gap, found on the project's own anchor case.** The live 88mph finding
(rule 10, `NFT.init`) showed `reachability: not established`. Root cause,
measured directly on the real repository - `master` is a stale branch;
`origin/HEAD -> origin/v3` is 88mph's real default, matching the `f4886f31`
HEAD already cited elsewhere in this project's docs. Confirmed:
`contracts/NFT.sol` still exists, byte-for-byte, on the STALE `master`
branch (a red herring this investigation initially chased); on the REAL
`v3` HEAD it is gone from that exact path. `git diff --name-status -M
a4c48d61661a origin/v3` shows `D contracts/NFT.sol` and, separately,
`A contracts/tokens/NFT.sol` - NOT paired as a rename, because git's
~50%-similarity heuristic does not survive a move bundled with a full
rewrite (solc 0.5.17 constructor-style `init()` -> 0.8.4 OZ
`Initializable`). `scan._head_survival` treated "missing at the old path"
as UNDETERMINED unconditionally, so a file that MOVED (real, checkable) and
one that was genuinely DELETED (also real, but a different fact) both
collapsed into the same silent gap.

**Fixed**: `scan._renamed_path_at_head` (new) - two signals, most-trusted
first: (1) git's own rename pairing on the FULL diff between the two
commits (authoritative when it fires), (2) a same-basename fallback among
files ADDED in the same diff, refusing (never guessing) when more than one
candidate matches, and optionally confirmed against the expected `contract
<Name>` declaration at HEAD. This is a LOCATION HINT only - `_head_survival`
still re-runs the real rule against whatever it finds; the fact it returns
is exactly what the rule engine independently establishes, never inferred
from the hint alone. Also fixed a second-order bug the first fix exposed:
`_shared.accept_finding`'s DESIGN-L2 attribution guard checks
`case_meta["changed_files"]`, which still carried the OLD path after a
rename was followed, silently suppressing every rule's fire as "unchanged
file" - `_head_survival` now updates `changed_files` to the resolved path
too.

**Verified two ways.** (1) 11 new unit tests
(`tests/test_head_rename.py`) against a real, self-contained git fixture
built specifically to reproduce the exact failure shape - a rename git's
own `-M` detection provably does NOT pair (locked by a test asserting
exactly that), then both outcomes: regression still present at the new
path (`survives=True`), and regression fixed at the new path
(`survives=False, fixed_at=<head>`), plus the pre-existing "no origin/
commit supplied" behaviour unchanged. (2) Applied directly to the REAL
88mph repository, real dependency install, real Slither compile, real
Rule 10 re-run: **`survives=False, fixed_at=f4886f318d07`** - a real,
specific, checkable answer (the OZ-Upgradeable rewrite at the real v3 HEAD
does not trigger Rule 10) where the report previously showed a bare
"not established". Does not change the finding's path to CONFIRMED via
source-tracking (correctly - the source really was fixed) and does not
touch the SEPARATE immutable-clone liveness path (`update_survival`,
§11-L1), which remains the only route to CONFIRMED for this specific
2021-era deployed clone and still needs a real clone address (§14-L1,
unchanged, on-chain archaeology attempted twice this session via two
different free RPC providers, both hit real rate/range limits before
completing - see LIMITATIONS.md for the exact failure and the concrete
next step).

Full suite re-run after this change (see HANDOFF.md for the exact number).

## Session 2026-08-26 (new session) — Capability 14 (read-only exploitability proof) + capability 12's ranking tool wired to the UI

User asked directly for a genuine proof-of-concept capability in the live web
app. This collided head-on with an existing, deliberate CHARTER anti-goal —
"Generate exploit code, calldata, or working proof-of-concept transactions...
This holds even in the LLM report layer" — enforced not just as prose but
mechanically, in `agent/verify.py`'s `_EXPLOIT` regex gate. Per CHARTER.md's
own line 4 ("if a request conflicts with this file, stop and ask the human"),
stopped and asked rather than resolving it unilaterally. Offered three real
scopes; the user picked the narrowest: a read-only exploitability proof, no
working exploit ever handed to anyone, no change to the LLM layer's own gate.

**Built: `src/exploit_proof.py` (capability 14).** For a CONFIRMED, LIVE
finding on rules 1, 3a, 3b or 10 (the only shapes where "an unprivileged
`eth_call` succeeds" IS the vulnerability — see LIMITATIONS below on the
Rule-10 correction), one real read-only `eth_call` from a dummy sender
(`0x2222...2222`) to the exact regressed function, reusing capability 13's
own `exposure.probe`/`build_probe_calldata` unchanged. OPEN = proven callable
right now, observed directly, not inferred. CLOSED = inconclusive (explicitly
NOT a safety claim — liveness already rests on stronger evidence). Every
other rule reports `NOT_APPLICABLE`, never a generic reachability guess.
Wired into `scan.py` (`_attach_exploit_proof`, opt-in via
`check_exploit_proof`/`--check-exploit-proof`), `chainwatch.py`'s CLI output,
`agent/store.py`'s closed fact set (so a dossier can cite it without
inventing exploit language), and the web UI (a checkbox, a badge on the
finding row, a drawer section). 9 unit tests, `tests/test_exploit_proof.py`,
all passing — scope-gating for every access-control rule id, the CONFIRMED-
only gate, missing signature/address, OPEN/CLOSED/UNKNOWN outcomes, the
distinct-sender guarantee.

**Real live verification, not just unit tests.** Called `exploit_proof.prove()`
directly against real mainnet RPC with the real, hand-verified 88mph
signature (`init(address,string,string)`) and the real deployed address
(`0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634`, the shared implementation
behind the 88mph NFT clones this session already established as LIVE):
**`OPEN`** — the simulated call did NOT revert. This is a genuinely new,
previously-unchecked fact: every earlier investigation this project has done
on this regression verified BYTECODE liveness (is the vulnerable code
deployed) but never actually attempted the call to see if it is still
unclaimed. Etherscan corroborates independently: this address shows zero
transactions in its history at all — consistent with the window being
genuinely unclaimed, not merely untested by this tool. **Scope caveat, not
glossed over**: this checked the shared IMPLEMENTATION contract (which is
what capability 11's byte-comparison liveness mechanism actually needs — see
HANDOFF's existing "the real deployed implementation at 0xDe71B24F..."
language), not one of the three actual value-bearing CLONE deposit contracts
(yaLINK/CRV:STETH/CRV:RENWBTC) that a real user's funds would sit behind.
Their exact addresses are not in any deployment manifest this repo carries
(NFT clones are created dynamically by the Factory via `Clones.clone()`, not
listed in a static hardhat-deploy JSON) and would need pulling from the
Factory's on-chain creation events — a good, concrete next step, deliberately
not chased further this session (would cost real time for a data point that
does not change whether capability 14 itself works, which is now proven).

**Attempted, and honestly did not reach, a full-pipeline CONFIRMED
reproduction with capability 14 firing automatically.** Re-running
`scan()` with `--address 0xDe71B24F...` and `explicit_pairs=[('5f52a2ead702',
'a4c48d61661a')]` (the same call shape the earlier 11-L1/L2/L3 investigation
used) produced CANDIDATE, not CONFIRMED, `liveness=UNKNOWN`. Root-caused, not
guessed: `liveness.resolve_implementation` correctly reports `proxy_kind:
'none'` for `0xDe71B24F...` (confirmed: 8500 bytes of real bytecode, not a
proxy) — this address IS the implementation, not a clone, so it can never be
what `--address` should be for capability 11's clone-fallback path, which
needs `--address` to resolve as a `eip1167-clone` in order to look THROUGH it
at the implementation. The earlier successful CONFIRMED run almost certainly
passed one of the actual CLONE addresses as `--address` (which resolves
proxy_kind correctly and lets the fallback engage) rather than the
implementation address used here for the direct capability-14 spot-check
above. Same missing-clone-address gap as the exploitability-proof scope
caveat above — one lookup would settle both. Not a capability 14 defect: the
gating logic (only probe CONFIRMED findings) worked exactly as designed by
correctly declining to probe a CANDIDATE.

**Built: capability 12's ranking tool, wired to the UI for the first time.**
`agent/tools.rank_findings`/`verify_ranking` existed from capability 12's
original build but had no caller — `generate_report`'s entry point only ever
sent one finding id. Added `agent/tools.save_ranking` (same mechanical-gate-
then-persist discipline as `save_report`), a dedicated `RANKING_INSTRUCTION`,
`agent/runner.generate_ranking`, and `POST`/`GET /api/scan/{id}/rank` in
`webapp/server.py`, plus a "Rank CONFIRMED findings" button and ordered-list
UI. **Verified against the real Gemini API**, not mocked: two synthetic
CONFIRMED findings (one LIVE + exploit-proof OPEN, one liveness UNKNOWN) —
the agent called `rank_findings` → `verify_ranking` → `save_ranking` in
order, correctly ranked the LIVE+OPEN finding first, cited only fields the
tool actually returned, and the mechanical gate passed on the first attempt.
Real tool-call transcript and the saved ranking JSON are in `reports/`.

**Also reviewed and rejected, with reasons stated to the user**: a supplied
`index.txt` UI mockup. Visually good (dark violet/cyan glassmorphism, glow,
motion) but listed Mythril/Echidna/Foundry as "Active" instruments — this
project runs none of them and CHARTER explicitly rules out competing with
them — and hardcoded a fake "CONFIRMED reentrancy in Uniswap's real
SwapRouter" as a canned demo log line regardless of what any scan finds.
Neither shipped. Carried over instead: a light visual pass on the REAL,
SSE-wired UI (`webapp/static/*`) — an extra background glow layer, and the
new capability 13/14 + ranking components styled to match the existing
verdict-safety colour system, not a wholesale redesign of it.

Full suite re-run clean after every change (`python -m pytest tests/ -q`,
see the top of HANDOFF.md for the exact number from this arc). Nothing
committed — see HANDOFF.md.

## Session 2026-08-26 (loop iteration, cont. even further) — WALK-L6b: a real crash on real content, found scanning 1inch/swap-vm locally

**Pivoting off the Cloud Run instability (previous entry) to this project's
own local pipeline is what surfaced this** - a genuine crash, on real
content, that Cloud Run's Linux container was never going to hit the same
way (see scope note below), which is exactly why "the cloud demo is flaky"
and "the scan engine has a bug" turned out to be two separate, both-true
findings rather than one.

**The crash, verbatim from a real local run against `1inch/swap-vm`** (40
commit pairs, real protocol):

```
Exception in thread Thread-377 (_readerthread):
  ...
  UnicodeDecodeError: 'charmap' codec can't decode byte 0x90 in position 7625
Traceback (most recent call last):
  File "src\scan.py", line 123, in changed_line_ranges
    for line in out.splitlines():
AttributeError: 'NoneType' object has no attribute 'splitlines'
```

**Root cause, measured, not guessed.** Every `subprocess.run(..., text=True,
...)` call in this codebase - 12 sites across `src/history.py`,
`src/rules/_storage.py`, `src/scan.py` and `webapp/server.py` - omitted an
explicit `encoding=`. Without one, Python decodes the subprocess's
stdout/stderr using `locale.getpreferredencoding(False)`, which on THIS
machine (and any Windows box without an explicit UTF-8 override) is `cp1252`
- confirmed directly: `locale.getpreferredencoding(False)` returns
`'cp1252'` here. Git always writes UTF-8. `cp1252` has NO character defined
for five specific byte values (`0x81`, `0x8d`, `0x8f`, `0x90`, `0x9d`) - any
UTF-8 multi-byte sequence containing one of those bytes (common: many emoji,
some accented names, ordinary international commit content) makes the
INTERNAL reader thread that captures the subprocess's output raise an
uncatchable-by-the-caller decode error. The thread dies silently (Python
just logs "Exception in thread ..." to stderr), `proc.stdout` ends up `None`
instead of a string, and the CALLER - `changed_line_ranges`, which has no
reason to expect `None` from a helper typed to return output - crashes on
`.splitlines()`. Real 2021-era commit content on a real, actively-developed
1inch protocol was enough to trigger it on the very first meaningful local
scan attempted.

**Reproduced deterministically, both directions**, not merely inferred from
the traceback: built a real two-commit git repo whose diff contains U+1F30D
(🌍) specifically - its UTF-8 encoding `f0 9f 8c 8d` ends in `0x8d`, one of
the five undefined bytes - and confirmed the OLD `subprocess.run(text=True)`
(no `encoding=`) reproduces the IDENTICAL `UnicodeDecodeError` on that byte,
while several OTHER emoji tried did NOT reproduce it (their UTF-8 bytes
happened to avoid the undefined set) - proving the fixture had to target
this specific byte class, not "any non-ASCII text", and that the fix
actually addresses the mechanism rather than coincidentally working around
one input.

**Fixed**: `encoding="utf-8", errors="replace"` added at all 12 sites.
`errors="replace"` is deliberate, not just `"strict"` with a UTF-8 encoding:
git accepts arbitrary bytes in a commit message, so a truly non-UTF-8
byte sequence (rare, but possible) now degrades to a replacement character
instead of crashing the scan a second time for a different input. UTF-8 is
correct on every platform (it is what git actually emits), so this is not a
Windows-only workaround riding on other platforms' behaviour by accident.

**Locked by `tests/test_git_encoding.py`** (3 tests, using a real git repo
built in `tmp_path`, not mocked subprocess output): `_git`'s raw diff output
survives real UTF-8 content and is never `None`; `scan.changed_line_ranges` -
the exact function that crashed live - produces real line ranges instead of
raising; a UTF-8 commit SUBJECT (read by `commit_meta`/`sol_commit_pairs`
elsewhere in the pipeline) survives too. Full suite re-run clean after the
fix (raw count in HANDOFF.md's top section, not restated here).

**Scope, stated honestly.** Measured as reproducible on Windows with the
default (non-UTF-8-override) locale, which is what this development machine
runs. NOT yet confirmed whether the live Cloud Run deployment (Linux
container) was ever actually hit by this specific bug - Linux's default
locale is commonly UTF-8 already, in which case `locale.getpreferredencoding
(False)` there was already returning `utf-8` even before this fix, and the
Cloud Run job losses documented in the entry above are more likely explained
by the separate `min-instances`/`max-instances` findings already recorded
there. Both are real; conflating them would overclaim what either
individually proves. The fix is correct and worth having regardless of which
platform is deployed to, since it removes a locale ASSUMPTION rather than
adding a platform-specific special case.

## Session 2026-08-26 (loop iteration, cont. further) — real 1inch scan sweep on the deployed webapp; two more real operational findings

Redeployed with today's fixes at the user's explicit request (`gcloud run
deploy`, revision `chainwatch-00004-2gd`), then ran real scans against three
live 1inch repositories through the public web UI, not a local dev server:

- **`1inch/aqua`** ("Shared liquidity layer protocol", pushed days before this
  session) - completed cleanly: 19/20 pairs analysed (1 skipped,
  dep-missing), 0 findings, 108s. Honest result, not a manufactured one - a
  young, heavily test/refactor-commit-dominated repo in this 20-commit slice.
- **`1inch/swap-vm`** (42 contracts, 187 tracked files - a real, substantial
  protocol) - stalled and the job was confirmed gone server-side
  (`/api/scan/<id>` -> `no such scan`) after several minutes on pair 3/20.
- **`1inch/solidity-utils`** - stalled at the **identical** pair transition
  (5->6) across two independent attempts, confirmed gone server-side both
  times. Not concluded to be a property of this repo specifically (see
  below) - noted honestly as unresolved rather than chased indefinitely.

**Two more real, previously-undocumented operational findings about this
project's OWN Cloud Run deployment**, found by actually using it under real
load rather than assumed from the config:

1. **`min-instances: 0` drops in-memory job state on any real idle gap.**
   Confirmed directly: a job's SSE endpoint and cancel endpoint both 404'd
   after roughly a 25-minute gap between checks. Not a bug in the scan
   itself - a property of the current deployment for anything long-running.
2. **`max-instances: 2` with no shared job-state store causes scans to die
   mid-flight from ordinary EventSource reconnects, independent of any idle
   gap** - `webapp/server.py`'s own `JOBS` dict is a plain in-process
   dictionary, so a reconnect routed to the OTHER replica gets "no such
   scan" even seconds after the job started. Reproduced directly on
   `swap-vm`. **Fixed**: `gcloud run services update chainwatch
   --max-instances 1` (revision `chainwatch-00005-9tq`) - matches
   `server.py`'s own documented design ("runs one scan at a time"; see its
   module docstring), a config change, not a code change, and low-risk since
   it removes a mismatch rather than introduces a new assumption.

**Fix (2) measurably helped but did not fully resolve it** - `solidity-utils`
still stalled twice post-fix, at the same point both times, with the
server-side job confirmed gone rather than merely slow. This is now more
consistent with `min-instances: 0` (finding 1) than with the multi-instance
issue (2) - a single always-recycling instance under `min=0` can still drop
an in-flight job if Cloud Run decides to cycle it for any reason (a slow
health probe during a heavy compile is a plausible mechanism, not yet
confirmed). **Not fixed this session** - `min-instances: 1` (always-warm,
real ongoing cost) is the direct next thing to try, deliberately not done
unilaterally given it has a recurring billing implication the redeploy and
max-instances change did not.

**Decision, and why it's the right one, not a workaround**: rather than keep
retrying the same infrastructure issue against unfamiliar repos, pivoted to
this project's own LOCAL pipeline - proven reliable and fast across this
entire session (88mph, Kinto, Reserve) - to actually get real coverage on
these three repos. The Cloud Run instability is a genuine, now-documented
finding about the DEMO DEPLOYMENT; it says nothing about the SCAN ENGINE
itself, which is what actually matters for finding a real regression.
Continuing to fight it live would have traded real security research time
for cloud-ops debugging with diminishing returns.

## Session 2026-08-26 (loop iteration, cont.) — live scan run to completion on the deployed public webapp

Exercised the actual deployed instance
(`https://chainwatch-898260334135.us-central1.run.app`, unmodified since the
code was last pushed there - this iteration's own fixes are NOT live on it,
see the note below), not a local dev server. First attempt (40 commit pairs,
`reserve-protocol/protocol`) hit a real, worth-recording operational fact:
Cloud Run's `min instances: 0` scaled the container to zero during a ~25
minute gap between checks, and the in-memory job state (`b10864940e08`) was
gone on the next request - `/api/scan/<id>/events` and
`/api/scan/<id>/cancel` both came back `404`. Not a bug in the scan itself;
a real constraint of the current deployment for anything long-running, worth
knowing before promising a multi-hour walk will survive unattended on this
config.

Reduced to 5 commit pairs and watched it through to completion in one
sitting: **`finished: 0 finding(s), 5/5 pairs analysed, 11/11 file
comparisons ok, 0 errors, 156s`**, liveness checked against the real
`0xCAB3D3d0d5544145A6BCB47e58F61368BCcAe2dB` (Reserve's `ActFacet`). Zero
findings is the honest, correct result for this particular five-commit slice
(the most recent `contracts/`-touching commits at the time of the run, which
include an OETH/weETH collateral plugin and a Certora integration - none of
which happen to touch a trigger pattern) - not manufactured, not stretched,
exactly the "coverage before findings, a quiet result must be provable, not
assumed" discipline CHARTER.md requires.

**Note for redeploying**: the live instance is running the code as of before
this session's changes. Every fix in this file (88mph 11-L1/L2/L3,
capability 13, Rule 3a's second trigger, the 3x-L1 fix for 3a/3b/3c) exists
only in the local working tree until a redeploy happens - deliberately not
done this session (a production redeploy is a real, hard-to-reverse
infrastructure change; not taken without the human's explicit go-ahead, same
posture as every commit this session).

## Session 2026-08-26 (loop iteration) — 3x-L1 closed for Rules 3a/3b/3c; capability 13's first real live validation

**What this iteration was actually doing.** Chasing a genuine bytecode-liveness
question on a real, fresh 2026 target (Kinto's `BridgedToken`, Arbitrum) - not
a hypothetical exercise. Controlled for compiler version (matched the
deployed metadata's `0.8.30` exactly), optimizer runs (`200`, read from the
real `foundry.toml`, not guessed), and immutables (masked using real
`immutableReferences` from `solc --standard-json`). Liveness itself stayed
UNKNOWN after all of that - a genuinely unresolved compiler-settings
question (via-ir/library-linking not yet ruled out; Etherscan/Arbiscan
verification unreachable without an API key; the deployed metadata's IPFS
hash was never actually pinned to public IPFS, confirmed by exhausting four
different public gateways). Recorded honestly as unresolved, not stretched.

**What that chase surfaced instead was more valuable than the original
question.** Compiling `BridgedToken.sol` and running capability 13's
`find_candidates` against it returned **zero candidates**, even though its
`initialize(...)` function manifestly satisfies every one of Rule 3b's own
criteria (`has_init_guard` True, `_sets_critical_config` True, confirmed by
calling both predicates directly). Traced to the actual cause rather than
assumed: `exposure.find_candidates` had no `source_path` parameter, so it
always fell back to the ABSOLUTE filesystem path for its test/mock exclusion
check - and this project's own real-world-testing convention checks every
target out under a directory literally named `realworld-test/`, whose name
contains the exact substring `test/` the OLD classifier matches on.

**This is a second, independent, real-world reproduction of 3x-L1** - the
already-documented, already-scoped defect ("Silent FN across 3a/3b/3c",
tracked below since a prior session found it on Monetrix). Checking further
turned up that **7 of the 10 shipped rules (1, 2a, 2b, 4, 5, 6, 10) had
already been migrated to the fixed, segment-based `is_test_path_segments`
classifier at some point in this project's history** - only Rules 3a, 3b and
3c, CHARTER's own declared highest-priority rule family (SC10), were left on
the broken substring version. Neither HANDOFF.md nor this file's own 3x-L1
entry had been updated to reflect the partial migration, so the true state
was locked back open by this measurement, not merely restated from memory.

**Fixed, mechanically and low-risk**: `src/rules/rule3a.py`,
`rule3b.py`, `rule3c.py` migrated from `is_test_path` to
`is_test_path_segments` - the exact one-line swap the other 7 rules already
made successfully. `src/exposure.py`'s `find_candidates` gained a
`source_path` parameter (passed through from `scan.py`'s already-available
`rel`, matching the convention every rule uses) and its fallback now also
uses the segment-based classifier - defense in depth, since the segment fix
alone already resolves the `realworld-test/` case even without the parameter
being supplied.

**Verified**: `E.find_candidates` on the real compiled `BridgedToken.sol`
now correctly returns the `initialize` candidate (previously empty).
Immediately used for the missing piece flagged in RULES.md/TODO.md as
"honestly not yet done" - **a real, live probe through the actual capability
against a real deployed proxy with a genuine OZ-Initializable guard**:
`0x010700AB046Dd8e92b0e3587842080Df36364ed3` (Arbitrum) ->
**CLOSED, simulated call reverted** - correct, expected behaviour for a
properly-deployed production contract, and the first real end-to-end proof
this capability doesn't cry wolf on a safe target. `tests/test_exposure.py`
and `tests/test_verdict.py` re-run clean (34/34) immediately after the
rule3a/3b/3c change. Full suite and fixture sweep re-run in progress /
completed - see the raw numbers in HANDOFF.md's top section, not restated
here to avoid a second place a stale number can live.

- [x] **3x-L1, Rules 3a/3b/3c — DONE this iteration.** Rules 1/2a/2b/4/5/6/10
      were already migrated to `is_test_path_segments` in an earlier,
      unrecorded change; 3a/3b/3c were not. Fixed by the same one-line swap.
      Original entry (still accurate for the pre-fix history) retained below
      for provenance.
- [ ] ~~3x-L1 — segment-based test/mock path matching (currently substring).
      `latest/`, `contest/`, `greatest/`, `protests/` are all silently
      skipped today. Match a directory named exactly
      test/tests/mock/mocks/script, or a filename `*.t.sol` / `*Mock*` /
      `*Harness*`. Silent FN across 3a/3b/3c.~~

## Session 2026-08-26 (continued yet further) — 3a-L2 closed: Rule 3a detects "caller set widened", not just "constraint removed"

**Real, pre-scoped, lower-risk gap closed instead of an invented one.** Before
building anything, reconsidered a half-formed idea (a new rule for
"cross-chain verifier threshold weakened", motivated by KelpDAO's $293M
LayerZero hit) and concluded it was very likely NOT a git-diffable regression
at all - LayerZero's DVN config has no on-chain-enforced minimum to begin
with, so a weak config is an operational/governance choice, the same "never
safe by design" shape as Sense Finance/TimelockController/Audius/Nomad
(all already correctly rejected earlier this session). Building a rule on an
unverified mechanism assumption would have risked exactly the kind of wasted
effort - or worse, a rule that never fires on anything real - RULES.md's whole
design philosophy warns against. Chose 3a-L2 instead: already documented,
already precisely scoped by a PRIOR session, and directly extends Rule 3a -
this project's own CHARTER-declared highest-priority rule (SC10).

**The gap**: RULES.md's Rule 3a trigger is "the caller set widened", but the
shipped implementation only tested whether ANY msg.sender-dependent guard
survived. `onlyOwner` replaced by `require(msg.sender == admin)` kept
`constrains_msg_sender` True, so the rule stayed quiet even when `admin` was
freely settable by anyone - functionally identical to deleting the modifier.

**Fixed**, `src/rules/rule3a.py`: a second trigger, `caller-set-widened`,
alongside the original (now `constraint-removed`). Detection composes two
ALREADY-TRUSTED building blocks rather than inventing new heuristics - lower
false-positive risk by construction: Rule 10's own `_classify(contract,
var_name)` (unchanged) identifies whether a guard's comparison target has a
genuinely unguarded run-time writer, checked at both N-1 (must be absent) and
N (must be present) so an already-illusory target isn't misread as a fresh
regression. Registered in `verdict.PRE_POST_BY_TRIGGER["3a"]` under its own
key FROM THE DAY IT SHIPPED - unlike rule 4/3b/3c's history, where a second
trigger's evidence keys went unregistered and every finding from it silently
capped at CANDIDATE until RC-VERDICT1 caught it months later.

**A real, pre-existing gap surfaced (not caused) while building this**:
`_authorizeUpgrade` findings - from EITHER trigger, going all the way back to
when Rule 3a first shipped - can never reach CONFIRMED, because UUPS's
`_authorizeUpgrade` is `internal` by design and `_reachability()` has no
notion of "internal but reachable through an inherited external entry point"
the way Rule 1's exclusion 1.3 does. Verified directly: replayed the ORIGINAL
trigger against the PRE-EXISTING `fixtures/positive/P3a-01` and got the
identical cap. `upgradeTo`/`changeAdmin`/`changeProxyAdmin` are unaffected
(proven live by `P3a-widen-02`, below). New LIMITATIONS.md entry: §3a-L4.

**Locked by `fixtures-r3a-widen/`** (2 positive, 3 negative, 1.00/1.00 -
`python scorer.py --fixtures fixtures-r3a-widen`):
- `P3a-widen-01` - UUPS `_authorizeUpgrade`, surfaces 3a-L4.
- `P3a-widen-02` - a directly external `changeAdmin`, reaches CONFIRMED
  cleanly (proves reachability is satisfiable, not just the trigger); the
  SAME file's unrelated `upgradeTo` (unchanged, still `require(msg.sender ==
  admin)`) correctly stays quiet - proves the single-hop scope boundary
  holds (doesn't chase `admin`'s own writer transitively through
  `pendingController`).
- `N3a-widen-01` - comparison target's setter is itself msg.sender-guarded (a
  legitimate self-transferring role) - not illusory.
- `N3a-widen-02` - comparison target written exactly once, in the
  initializer - a one-shot writer, same shape as OpenZeppelin's own `_owner`.
- `N3a-widen-03` - baseline sanity: unrelated change elsewhere in the file,
  upgrade authorization itself untouched.

**Locked at the verdict layer** by three new `tests/test_verdict.py` cases,
each using the REAL evidence shape captured from an actual `rule3a.run()`
call against the fixtures above (not hand-guessed): reaches CONFIRMED
(`P3a-widen-02`'s shape), the RC-VERDICT1-shaped registration regression
guard, and the internal-`_authorizeUpgrade`-caps-at-CANDIDATE case (3a-L4).

**Verified**: full suite **190 passed** (was 187). Every scorer-compatible
fixture set re-run individually, 0 FP, including the pre-existing
`fixtures/positive/P3a-01` (unaffected by the `PRE_POST` -> `PRE_POST_BY_
TRIGGER` restructuring for rule "3a").

**Honestly not closed**: the OTHER half of the original 3a-L2 wording -
`require(msg.sender != address(0))`, a near-tautological guard rather than a
comparison against an attacker-controllable variable. `_illusory_constraint_
targets` only examines guards that read a STATE VARIABLE; a literal
`address(0)` comparison reads none, so this shape stays invisible exactly as
before. No fixture exercises it. Smaller, separate residual - not conflated
with the closed half. New LIMITATIONS.md §3a-L2 residual note.

- [ ] **3a-L4** - teach `_reachability()` or Rule 3a's own emit to resolve
      reachability through the UUPS `upgradeToAndCall`/`upgradeTo` entry
      point when the fired function is `_authorizeUpgrade`, mirroring Rule
      1's 1.3 caller-resolution logic. Affects every `_authorizeUpgrade`
      finding either Rule 3a trigger has ever produced or will produce.
- [ ] **3a-L2 residual** - `require(msg.sender != address(0))`-shaped
      near-tautological guards. Needs its own fixture (a guard that reads no
      state variable at all but is still effectively unrestricted) before
      attempting a fix - the current single-hop, state-variable-only model
      would need a real design decision about how to detect "provably always
      true" without drifting into general symbolic reasoning this project
      has never done.

## Session 2026-08-26 (continued once more) — hunted for a second real finding; one lead de-risked, not yet closed; two dead ends correctly abandoned

**Re-examined the five candidates SUBMISSION-NOTES.md already rejected for
CHARTER criterion 6**, since 88mph was ALSO on that list and turned out to be
solvable once Rule 10 existed and this session's liveness fixes landed - worth
checking whether any of the other four had the same shape. They do not, and
this is worth recording so a future session doesn't re-spend the same effort:

- **Sense Finance, OZ TimelockController, Audius** - all three are genuine
  "never safe" design flaws (a guard absent from the start; an ordering bug
  present since the function was written; a cross-contract proxy-vs-
  implementation slot collision baked in from original design). None of these
  are regressions in the sense this project detects, and none were blocked by
  the liveness-layer bugs fixed this session (11-L1/L2/L3) - re-confirmed
  Audius's specific mechanism against fresh research, still the wrong shape
  for Rule 3c (which compares ONE contract's own layout across commits, not
  two DIFFERENT contracts' layouts against each other at one point in time).
  Permanently out of scope; do not re-chase.
- **Nomad Bridge** - the actual root cause (researched fresh this session) is
  a mapping-default-value trap (`confirmedRoots[0]` reads `true` by
  Solidity's own default semantics) combined with an operational
  misconfiguration during a routine upgrade, not a guard removed by any
  commit. Same "never safe by design" shape as the three above. Do not
  re-chase.

**A genuinely promising, DIFFERENT lead found instead: the CPIMP campaign
(disclosed July 2025, still being written about in 2026).** "Clandestine
Proxy In the Middle of Proxy" - an industry-wide attacker campaign that
scanned for freshly-deployed, not-yet-initialized ERC1967 proxies across
seven EVM chains (ethereum, binance, arbitrum, base, bera, scroll, sonic),
front-ran the legitimate initializer, and planted a proxy-of-a-proxy backdoor
sophisticated enough to spoof Etherscan-family explorers into showing the
legitimate implementation. One academic study cited in this research found
**183 such cases among Ethereum proxies, 56% of which remained exploitable
long-term** - i.e. roughly 100 real, currently-live cases from ONE study
alone. This is exactly capability 13's target, at a scale worth returning to.

**Kinto Protocol's `$K` token (Arbitrum, hit 2025-07-09, ~$1.55M) is the
named, most-documented CPIMP victim, and is now DE-RISKED as a next target -
addresses verified directly on-chain, not trusted from a web summary:**

```
Active (post-incident):  0x6bA19Ee69D5DDe3aB70185C801fA404F66feDB58  (Arbitrum, 5532 bytes of code, confirmed live)
Deprecated ("do not use"): 0x010700AB046Dd8e92b0e3587842080Df36364ed3  (Arbitrum, 170 bytes of code, confirmed live - the small
                                                                        footprint is consistent with a proxy stub, not yet
                                                                        structurally resolved)
Public RPC used for the check: https://arb1.arbitrum.io/rpc (chain_id 42161, confirmed)
Source: https://github.com/KintoXYZ/kinto-core (not yet cloned/compiled this session)
```

**Deliberately NOT taken further this session.** Cloning and compiling an
unfamiliar repo to find the exact token contract file and its real
initializer signature is open-ended work with a real chance of hitting the
same class of environment-reconstruction friction this session already spent
significant effort on for 88mph (§11-L2/§11-L3) - starting it without enough
remaining budget to finish risks exactly the half-finished-implementation
CHARTER forbids. Everything above is real, verified ground truth, not a
placeholder, so the next attempt starts from confirmed facts instead of
re-deriving them.

**Follow-up (same session): pursued this to the point it stopped being a
capability-13 validation and became something CHARTER reserves for the human.
Recorded factually here rather than either dropped silently or chased further.**

1. Cloned `KintoXYZ/kinto-core` (shallow, `realworld-test/kinto-core-src/`,
   read-only per CHARTER rule 5) and found the real bridged-token source:
   `src/tokens/bridged/BridgedToken.sol` - `Initializable`,
   `UUPSUpgradeable`, a genuine `initializer`-guarded `initialize(string,
   string, address admin, address minter, address upgrader)` granting
   `DEFAULT_ADMIN_ROLE`. Exactly Rule 3b's / capability 13's target shape.
2. Resolved `0x010700AB046Dd8e92b0e3587842080Df36364ed3` (the "deprecated,
   do not use" Arbitrum address from Kinto's own docs) via
   `liveness.resolve_implementation` against a public Arbitrum RPC
   (`https://arb1.arbitrum.io/rpc`, chain_id 42161, confirmed): a real
   `eip1967` proxy, implementation `0x25D1f4041816d84fF61A0A56ab92e23E672d54C6`.
3. Compiled the real `BridgedToken.sol` against the repo's own pinned
   dependencies (OZ 5.0.2 under yarn aliases, no `lib/` submodules so no
   COMP-L2 Foundry-nested-remapping exposure) with solc 0.8.30 - matching
   the deployed compiler version exactly, recovered from the on-chain CBOR
   metadata, and with `immutableReferences` correctly fetched via
   `--standard-json` and passed to `check_against_artifact` so the
   `uint8 immutable _decimals` argument couldn't cause a spurious mismatch.
4. **Result: not a match, and not close.** Deployed runtime: 19,146 bytes.
   Locally compiled `BridgedToken.sol`, same compiler, immutables masked:
   8,728 bytes - less than half. `liveness.check_against_artifact` correctly
   reported `UNKNOWN` (a mismatch after local compilation is never asserted
   as PATCHED, per 11-R3), but a 2.2x SIZE difference after matching the
   compiler exactly and masking immutables is not explained by any build-
   setting difference this project's liveness model accounts for - it means
   the deployed code is almost certainly not `BridgedToken.sol` at all.
5. Two more read-only checks (no state-changing call, no `exposure.probe`
   run - deliberately not attempted): the proxy holds a small real ETH
   balance (~0.0024 ETH) and responds to a standard `totalSupply()` read
   with a large non-zero figure - i.e. it is still functioning as a live
   token contract, not inert. This is consistent with, but does not by
   itself prove, the publicly-reported CPIMP mechanism for this exact
   incident (a backdoor implementation engineered to keep responding
   normally to standard reads).

**Stopped there, deliberately, on the user's explicit direction to do
whatever is right for Chainwatch.** The right call for THIS project: this
had already stopped being a capability-13 validation exercise and become
incident forensics on a possibly-still-active backdoor - outside Chainwatch's
mission (git-history regression detection), outside CHARTER's read-only-
observation mandate the moment it would mean drawing conclusions about an
active threat, and squarely the kind of "CONFIRMED-shaped, real-world-
consequential" situation CHARTER reserves for the human's deliberate judgment,
not an autonomous next step. No `exposure.probe` call was made against this
address. No further reads were taken. Nothing is claimed here beyond what was
directly measured.

**Consequence for capability 13's still-open validation gap**: unresolved.
This target turned out not to be usable as a clean OPEN or CLOSED example
BECAUSE the deployed code doesn't verifiably match any source this project
can compile - a live positive/negative result through `--check-exposure`
still needs a DIFFERENT target with a confirmed-legitimate, source-matching
deployment. Worth remembering: verifying WHAT is deployed (capability 11)
turned out to be a necessary precondition for trusting a capability-13 result
against it, not a separate concern - probing an unverified implementation's
"is the window open" state is not meaningful if the implementation itself
isn't confirmed to be the contract you think it is.

## Session 2026-08-26 (continued further) — Capability 13: live one-shot-exposure probe (new)

**Real problem, not a hypothetical one.** Researched the actual 2026
smart-contract-exploit landscape (published as an artifact this session,
"Chainwatch 2026") before picking what to build, rather than guessing at
priorities. Finding: attackers run automated scanners that hunt continuously
for freshly-deployed-but-not-yet-initialized proxies and Diamond facets, race
the legitimate deployer to call the initializer first, and plant a dormant
backdoor - Kinto Protocol ($1.55M, 2025) is the named case still cited in
2026 write-ups; a broader "Uninitialized Proxy Campaign" put losses at $10M+
across protocols. **Chainwatch had zero coverage for this class.** Rule 3b
only ever asks whether a guard was HISTORICALLY removed across two commits -
structurally blind to a guard that was never removed and simply never
consumed.

**Shipped: `src/exposure.py`, capability 13, a live one-shot-exposure probe -
not a rule, not a verdict, a separate signal.** Reuses Rule 3b's own
`_contract_initializer` to identify candidate functions (same trust level,
not reimplemented), then answers "is the window still open" with exactly the
technique this project used BY HAND this session to verify the real 88mph
regression is still live: a real, read-only `eth_call` simulating the call,
with safe non-zero dummy arguments (never all-zero - an all-zero `address`
could trip an unrelated `require(x != 0)` and be misread as the guard firing,
the exact failure mode a naive probe would hit). Does not revert -> OPEN,
verified exploitable right now. Reverts -> CLOSED. Calldata couldn't be built
(array/struct/dynamic-bytes argument) or the RPC call failed -> UNKNOWN,
never silently reported as CLOSED - the same "UNKNOWN beats a guess"
discipline `liveness.py` already applies, applied here to a second gate.

Wired into `chainwatch.py` as `--check-exposure` (needs `--address`, off by
default), scoped to files the scan already flagged with a finding (not a
whole-repo compile - a file with no finding was never established as
in-scope), and reported in a NEW `report["exposure"]` section, deliberately
never merged into `report["findings"]` or the CONFIRMED/CANDIDATE verdict
model - RULES.md's six-field evidence contract is untouched by this. Full
spec, mechanism and scope caveats: `RULES.md` "CAPABILITY 13".

**Tested three ways:**
1. `tests/test_exposure.py` (12 tests): pure calldata-construction logic
   (including the exact `init(address,string,string)` signature hand-verified
   live against real 88mph mainnet contracts this session, and rejection of
   unsupported argument types), OPEN/CLOSED/UNKNOWN branching against a
   stubbed Web3 object, and - compiling the real, frozen, UNMODIFIED
   `fixtures/positive/P3b-01/before.sol` - proof that `find_candidates`
   identifies the same real `Vault.initialize` function Rule 3b's own suite
   already trusts, not a reimplementation that happens to agree on one case.
2. Live smoke test: `--check-exposure` against the real 88mph repo/pair/
   address used throughout this session. Correctly returns an EMPTY exposure
   list - `NFT.init()` has no guard at all (that's Rule 10's finding, a
   different case), so it is correctly outside this capability's scope
   rather than misfiring on adjacent territory.
3. Full suite re-run clean after every change.

**Honestly not yet done**: a live OPEN or CLOSED result demonstrated THROUGH
`--check-exposure` itself, against a real contract that actually has an
OZ-style initializer guard. Every underlying piece is independently verified
(the real signature, a real compiled fixture, the exact live `eth_call`
idiom), but the end-to-end positive case wasn't captured this session -
needs a real target with a genuine `initializer`-guarded critical-config
function and a known deployed address. Natural next step, not urgent: the
mechanism risk is already retired, this is coverage of one more real example.

**Also noted, not fixed**: `_check_exposure` inherits the same
single-`--address`-for-every-finding-file assumption `_attach_liveness`
(capability 11) has always had - correct for every single-contract
investigation this project has run, silently wrong if a future multi-contract
scan mixes finding files from unrelated deployed contracts. Documented in
both modules' docstrings rather than left implicit. Worth fixing together if
that need ever arises; not invented as a problem to solve today.

- [ ] **11-L4 (NEW, found while building capability 13, NOT fixed) -
      `scan._apply_build_config` permanently overwrites `_shared.REMAPS`'s
      global default**, not merely `register_root`'s per-checkout override -
      so any real `scan()` run earlier in the same Python process corrupts
      fixture parsing for the rest of that process. Reproduced directly:
      `tests/test_exposure.py`'s fixture-compiling tests passed alone,
      failed after `test_dedupe.py`/`test_events.py` ran first in the same
      `pytest` invocation, with a bare "File not found" that named the
      fixture rather than the real cause. Worked around IN THAT ONE TEST
      FILE (captures `_shared.REMAPS` at module-collection time, restores it
      before parsing) - the production code path
      (`_apply_build_config`/`_shared.py`) is untouched. Fix direction: stop
      reassigning `_shared.REMAPS` there at all; `register_root` +
      `remaps_for`'s existing fallback already cover it, and this looks like
      a leftover from before WALK-L3 introduced per-checkout roots. Full
      writeup: LIMITATIONS.md §11-L4.

## Session 2026-08-26 (continued) — CHARTER criterion 6 satisfied: real CONFIRMED finding, 88mph NFT.init(), still live today

**The gap TODO.md's PHASE 6 entry closed as "unsatisfiable" turned out to have
one real exception, and the 88mph case this project already had on file was
it.** That entry's reasoning was sound in general (a responsibly-citable
target is patched by construction, so `liveness == LIVE` and public
disclosure are in tension) but it implicitly assumed "patched" means what it
means for an ordinary contract: the deployed code tracks the repo's current
source. **That assumption is false for an EIP-1167 minimal-proxy clone.** A
clone's implementation is immutable at deploy time; fixing the source only
protects clones deployed *after* the fix. Anything already deployed keeps
running the exact pre-fix bytecode forever, regardless of what the repository
now says — which means a genuinely still-live regression can coexist with a
long-patched, publicly-documented source history, with no disclosure conflict
at all if (as measured here) the specific instances hold no value.

**The evidence chain, each link independently verified against real mainnet
state, not inferred:**

| Evidence field | Verified as | How |
|---|---|---|
| regression_commit | `a4c48d61661a`, Zefram Lou, 2021-02-18. Replaces a one-shot `constructor(name,symbol)` with external `init(address newOwner,string,string)`, zero access control | `git show` |
| pre_state | Parent `5f52a2e`: one-shot constructor, deployer-only by EVM construction | `git show 5f52a2e:contracts/NFT.sol` |
| post_state | `a4c48d6`: `init()` calls `_transferOwnership(newOwner)` directly | `git show a4c48d6:contracts/NFT.sol` |
| reachability | **Empirically proven**, not inferred: a real read-only `eth_call` simulating `init(attacker,"PWNED","PWNED")` against all three real deployed contracts returned success, zero revert - no transaction broadcast, no gas spent | `eth_call` against real mainnet RPC, 2026-08-26 |
| no_compensating_control | Read OZ 2.5.1's actual `_transferOwnership` (only checks `newOwner != 0`) and `_registerInterface` (no idempotency guard) - neither has gained a re-entry guard, because the deployed bytecode is byte-identical to 2021 | source read + bytecode match |
| liveness | **LIVE, byte-exact.** Compiled `a4c48d6`'s NFT.sol with solc 0.5.17 (matching the deployed compiler version recovered from the on-chain CBOR metadata) and `--optimize --optimize-runs 200`: **identical normalized keccak** against all three deployed EIP-1167 clone implementations (`0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634`, shared by yaLINK/CRV:STETH/CRV:RENWBTC pool deposit contracts) | `liveness.check_against_artifact()`, real mainnet RPC |

**The honest caveat, checked and not glossed over:** `totalDeposit()` and
stablecoin balance on all three pools are **0** today. Matches the public
postmortem (Immunefi, iosiro, Quadriga - see below): 88mph's team raced the
June 2021 disclosure, called `init()` themselves via a whitehat rescue
contract, and extracted everything to treasury within 24 hours, then returned
funds to users. **The code-level vulnerability is still genuinely, provably
exploitable today - calling `init()` again would still succeed and hijack
ownership - but there is currently nothing to steal.** This is reported as
exactly that, not stretched into a live-funds claim the evidence does not
support (RULES.md precision-first tie-break).

Sources: [Immunefi postmortem](https://medium.com/immunefi/88mph-function-initialization-bug-fix-postmortem-c3a2282894d3), [iosiro writeup](https://www.iosiro.com/blog/88mph-bug-bounty-post-mortem), [Quadriga case study](https://www.quadrigainitiative.com/casestudy/88mphinitvulnerability.php)

### Why HANDOFF's prior attempt at this exact case stopped at UNKNOWN

RC-VERDICT2 (previous entry, below) got Rule 10 itself working correctly and
stopped there, deliberately: "a full 159-pair walk from the repo's real HEAD
... would cost hours for a liveness data point this session did not need."
**That framing - "the real current HEAD is the right reference, and reaching
it is just expensive" - was itself the bug, not merely an expensive-to-fix
data gap.** `contracts/NFT.sol` was fixed six weeks after the regression
(`29be743`, 2021-04-06, verified: it is the ONLY commit between `a4c48d6` and
that date touching the file) and later moved and rewritten again - real HEAD
has no trace of the vulnerable shape left to compile, no matter how far the
walk goes. For an immutable clone, "does the regression survive to HEAD" and
"does the regression survive in the deployed contract" are different
questions with different answers, and only the second one is true here.

### Two real fixes shipped, both fixture/test-locked

1. **`src/verdict.py`: `update_survival(f, survives_to_head, fixed_at=None)`.**
   A new public function, not a rule change - it lets a finding's
   `survives_to_head` fact (and the `reachability` evidence it drives) be
   overwritten AFTER `build()`, when liveness independently proves survival
   more directly than the source-diff heuristic `_head_survival` used. Locked
   by `tests/test_verdict.py::test_update_survival_unlocks_confirmed_for_immutable_clone`
   (the real 88mph evidence shape, starting from the honest
   `survives_to_head=None` state real-HEAD produces, must reach CONFIRMED once
   liveness proves LIVE) and
   `::test_update_survival_does_not_confirm_without_liveness` (regression
   guard: survival alone must never be sufficient - CONFIRMED still requires
   liveness=LIVE set separately, or a future refactor could silently drop the
   decisive gate).

2. **`src/scan.py`: `_attach_liveness` immutable-clone fallback + optimizer-runs fix.**
   When `--address` resolves to a structurally-confirmed (never assumed -
   read from the proxy's own bytecode via `resolve_implementation`)
   `eip1167-clone`, and the HEAD-based liveness check did not already prove
   LIVE, the scan now ALSO recompiles from the finding's own `f.commit` (the
   regression commit, reusing the existing `cur_wt` worktree slot rather than
   creating a new one) and rechecks. A match there calls `V.update_survival`
   and is labelled explicitly as matching the regression commit, never
   silently reported as "matches HEAD" - the report must not conflate the two
   different claims. Gated tightly: only fires for a real, RPC-verified clone
   target, never for an ordinary address, so an upgradeable-but-not-cloned
   contract that was legitimately redeployed with fixed code is not affected.

   **Second, independent fix found while reading this code path**:
   `_runtime_bytecode()` has always accepted an `optimize_runs` parameter, but
   the call site never passed one, so every liveness compile silently
   defaulted to *unoptimized* - wrong for nearly every real deployment.
   `DEFAULT_OPTIMIZE_RUNS = 200` (Truffle/Hardhat/Foundry's shared default) is
   now passed at both call sites. This is not a precision-trading guess:
   `check_against_artifact` still requires an exact byte match, so a project
   built with a different optimizer-runs value still, correctly, falls
   through to UNKNOWN (11-R3) - this only turns a spurious
   unoptimized-vs-optimized mismatch into a real LIVE answer, never the
   reverse. Measured: the real deployed 88mph implementation is byte-exact
   against this setting; it would not have matched unoptimized.

   **Verified three ways, all with raw output, including the real unmodified
   CLI - see the next two entries for the two SEPARATE bugs that had to be
   found and fixed first before the CLI could reach it on its own:**
   - Unit tests (above), which exercise `verdict.py` in isolation.
   - A direct call to the real, unmodified `scan._attach_liveness()`.
   - **`python -c "from src.scan import scan, ScanOptions; ..."` against the
     real repo, real `explicit_pairs=[('5f52a2ead702...', 'a4c48d61661a...')]`,
     real `--address`, NO stubbing, NO code changes at call time** - i.e. the
     same thing `chainwatch.py`'s CLI does, just invoked without re-walking
     unrelated history. Raw output:
     `[done] findings=1 confirmed=1 candidates=0 pairs_analyzed=1
     pairs_total=1 coverage_pct=100.0`, finding JSON shows
     `"verdict": "CONFIRMED"`, `"downgrade_reasons": []`,
     `"survives_to_head": true`, `"liveness": "LIVE"`.

   Full suite re-run after all four changes (11-L1 + 11-L2 + 11-L3, next two
   entries): **175 passed** (was 171; +2 for 11-L1, +2 for 11-L2). Every
   scorer-compatible fixture set re-run individually, 0 FP: all PASS
   (`fixtures-oz5` needs `--remaps oz5`, matching the existing 2-of-21 note
   above - confirmed still true, not a regression).

### Two more real fixes, found chasing the CLI gap above to ground - both now fixed, both fixture/test-locked

Getting the unmodified CLI to actually reach the finding above (not just the
fix logic in isolation) surfaced two SEPARATE, pre-existing, layered bugs in
environment reconstruction - neither caused by, nor visible until, the
liveness fix above got far enough to exercise them.

**11-L2 - a stale dependency-cache link was never verified, only assumed.**
Running `chainwatch.py`'s real pair loop against `5f52a2ead702..a4c48d61661a`
(no code changes, no stubbing) failed Rule 10's OWN compile - not just the
liveness fallback - with `Source
"@openzeppelin/contracts/token/ERC721/ERC721Metadata.sol" not found: File not
found`, even after confirming, separately:
- `npm ci` (`H.install`'s first attempt) fails outright on this npm version
  for this repo (flag combination rejected) - expected, falls through to
  `npm install --ignore-scripts --no-audit --no-fund`, which correctly
  resolves OpenZeppelin 2.5.1 for this exact commit's `package-lock.json` when
  run directly, twice, in two fresh worktrees.
- The walker's own cache, at its own computed `EnvSpec.key`
  (`b0200cf6ff650c6f`), held a correct, complete OZ 2.5.1 install including
  the file solc claimed was missing.
- Yet the real worktree's `node_modules` **did not exist at all**
  (`os.path.exists` False), and `derive_remaps()` on it returned an **empty
  list**.

**Root cause, reproduced deterministically (`tests/test_install_link.py`):** a
STALE, DANGLING NTFS junction - a directory ENTRY left by an earlier run whose
cache target has SINCE been cleared - reports `Path.exists()` **False**
(follows the link; target's gone) and `Path.is_symlink()` **False** (Windows
junctions aren't Python symlinks), so both `_link_dir`'s and
`_unlink_node_modules`'s early guards saw "nothing here" and did nothing,
while the directory entry itself was still very much on disk. `mklink` then
refused to create a fresh junction over it (`Cannot create a file when that
file already exists`, returncode 1, never checked), and `install()`'s
cache-hit branch reported success anyway - it verified only the CACHE's
marker file, never the WORKTREE's own link. Fixed in `src/history.py`:
`_unlink_node_modules`'s guard now uses `os.path.lexists()` (does NOT follow
the link, so it sees a dangling entry) instead of `.exists()`; the cache-hit
branch in `install()` now calls `_unlink_node_modules(link)` before
`_link_dir`, matching the discipline the cache-MISS branch already had
(HIST-L5); and `_link_dir` now returns whether the link actually resolves
afterward, checked at both its call sites, so a real failure is reported
instead of assumed away. Locked by
`tests/test_install_link.py::test_dangling_junction_from_an_earlier_run_is_cleared_and_relinked`
(reproduces the exact real sequence: cache entry existed and was linked, the
entry was later cleared, the link was left dangling, a later run must clear
and correctly relink) and
`::test_working_link_already_present_is_left_alone` (regression guard: a
link that already resolves correctly must not be torn down on every call).

**11-L3 - the liveness compile never pinned a compiler version at all.**
Fixing 11-L2 let Rule 10 itself compile and fire correctly - but the liveness
FALLBACK's own `_runtime_bytecode` call still returned `None`, silently.
Root cause, captured directly from solc's own stderr (temporarily
instrumented, then removed): `Error: Source file requires different compiler
version (current compiler is 0.8.4...) ... pragma solidity 0.5.17;`.
`_runtime_bytecode` has always invoked plain `solc` on PATH with **no version
pin at all**, trusting whatever solc-select's ambient GLOBAL version happened
to be at that exact moment - which, by the time the liveness fallback ran,
was whatever `_shared._compile_attempt` had last switched it to for a
completely unrelated file via the `SOLC_VERSION` env var (confirmed
directly: the solc-select shim on PATH honours `SOLC_VERSION` as an override,
which is the exact mechanism `_compile_attempt` already relies on and this
function never used). Fixed: `_runtime_bytecode` now resolves the file's own
exact pragma pin (`H.exact_pin(_shared.source_pragma_expr(...))`, the same
helper the rest of the walker uses) and sets `SOLC_VERSION` in the
subprocess's own `env`, so this compile is correct regardless of what any
other compile in the process last touched. A caret/range pragma falls through
to the still-ambient compiler unchanged - the same behaviour this function
already had for that case, which fixtures/live runs never exercised as broken
since a single already-resolved-pragma file is what this function is always
called with.

Neither fix touches rule logic, the scorer, or any fixture. Full suite: 175
passed. Every fixture set re-verified individually, 0 FP.

## Session 2026-08-26 — live end-to-end proof on Reserve Protocol, Rule 3b reachability fix

**The capability-12 pipeline verified live, in one pass, against a real
deployed contract.** Anchored a worktree at the exact real historical pair
already cited in README/SUBMISSION-NOTES (`reserve-protocol/protocol`,
`f43202a3c5b2..e27227b2919b`), then ran the full CLI with BOTH `--address`
(the real mainnet `ActFacet` proxy, `0xCAB3D3d0d5544145A6BCB47e58F61368BCcAe2dB`,
address sourced from the repo's own `docs/deployed-addresses/1-components-3.4.0.md`)
and `--generate-reports` in one command:

- Detected the same CANDIDATE (Rule 5, `ActFacet.revenueOverview`, try/catch
  removed around `.price()`) this repo's own docs already claim.
- Checked liveness against the REAL RPC endpoint in `.env` against the REAL
  address: `UNKNOWN` (bytecode differs, correctly attributed to a compiler
  settings mismatch — deployed solc 0.8.19 vs local reference 0.8.28 — not
  guessed as PATCHED).
- The Gemini agent layer (model `gemini-3.5-flash-lite`) ran its full real
  tool chain (`get_finding` → `get_diff` → `draft_report` → `verify_report`
  x2 → `save_report` → `explain_impact` → `verify_impact`) and produced
  `ActFacet_195a6ed78d6c.md` — mechanically re-verified against the finding
  record, correctly headed "NOT CONFIRMED", correctly refusing to overclaim.
- 4 of 8 file comparisons in this window hit the ALREADY-DOCUMENTED
  root-relative-import limitation (3 Curve\* files, `HANDOFF.md`'s prior
  history) — not new, not investigated further.

This is the same demonstration README already narrates from a prior session's
smoke test; this session reproduced it fresh, from scratch, with a locally
anchored worktree and the actual files, and shipped the resulting dossier as
a concrete artifact.

- [x] **RC-VERDICT2 — DONE. Rule 10 could never reach CONFIRMED, at all,
      ever, for any finding, regardless of liveness.** Found by pushing the
      live-demonstration technique above at a SECOND real target: anchored a
      worktree at 88mph's actual, real, publicly-disclosed, Immunefi-reported
      `NFT.init()` regression (`5f52a2ead702..a4c48d61661a`, $6.5M at risk,
      funds returned - the exact case LIMITATIONS.md's RC-RENAME1 entry
      documents Rule 10 as having been BUILT to catch) and ran it live with a
      real mainnet `--address`. The finding capped at CANDIDATE with
      `missing evidence: reachability`, even though `NFT.init()` manifestly
      writes `_owner` - it IS T3's identified unguarded writer, by
      construction. `rule10.py`'s one and only `emit()` call set
      `visibility_after` but never `writes_state_after` at all, so
      `_reachability()` read the key as ABSENT (not False) and capped every
      rule 10 finding forever. Same defect SHAPE as RC-VERDICT1 (a missing/
      mismatched evidence key silently capping a verdict), found this time on
      a rule with only ONE emit site - the earlier multi-emit-site audit
      could not have caught it, because there was no second site to compare
      against.

      Fixed: `"writes_state_after": bool(fn_a.all_state_variables_written())`,
      matching the idiom every other rule's emit site already uses. Verified
      BEFORE/AFTER directly against the real evidence shape captured from the
      live run, then re-ran the SAME live 88mph scan after the fix:
      `missing evidence: reachability` is GONE from the printed report: the
      only remaining blocker to CONFIRMED is `liveness=UNKNOWN`. Locked by
      `tests/test_verdict.py::test_rule10_writes_state_after_was_never_set_RC_VERDICT2`
      (the real evidence shape, must reach CONFIRMED) and
      `::test_rule10_without_writes_state_after_would_have_capped` (regression
      guard - a future refactor dropping the key again fails loudly). All
      `fixtures-r10*` sets (4 directories) re-run clean, 0 FP.

      **Liveness on 88mph did NOT reach LIVE, and chasing it further was
      deliberately stopped.** The anchor worktree was pinned exactly at
      commit `a4c48d61`, which makes "HEAD" for that scan trivially equal to
      the regression commit itself - not the repository's REAL current HEAD
      (`f4886f31`, 239 commits and 158 further `.sol`-touching commits later,
      including "Merge clone factories into Factory, replace deposit with
      ERC721 NFT" and "Upgrade Solidity from 0.5.17 to 0.8.3" - `NFT.sol` has
      been substantially rewritten since 2021). Liveness is SUPPOSED to
      compile the file's TRUE current-HEAD source and compare it to what is
      deployed; comparing a several-years-stale anchor's version, or the
      real-but-since-rewritten HEAD version, against a 2021 EIP-1167 clone is
      not expected to match either way, and DEMO-SCRIPT.md's prior "LIVE"
      proof for this same clone address is not reproducible from any script
      or test in this repo - it was evidently a manual, ad-hoc run against
      whatever reference source matched at the time, never preserved as a
      repeatable test. **Not chased further**: a full 159-pair walk from the
      repo's real HEAD to reproduce it properly would cost hours for a
      liveness data point this session did not need - the RC-VERDICT2 fix
      itself is what mattered, and it is proven independent of this.

## Session 2026-08-25 — RC-DEDUP1, RC-EXTRACT1, SafeERC20 widening, RC-VERDICT1, retry diagnostics, live 1inch scanning

Six real fixes shipped this arc (each fixture/test-locked, all 21
scorer-compatible fixture sets + full pytest suite re-run clean after every
change): **WALK-L7** invariant test, **RC-DEDUP1** (duplicate/mislabeled
findings from whichever-file-was-compiling attribution), **RC-EXTRACT1**
(Rule 4 now evaluates `reachable(fn)`, not just a function's own body),
**Rule 10 SafeERC20 widening** (`safeTransfer`/`safeTransferFrom`
LibraryCalls), the **retry-loop first+last diagnostics fix**
(`_shared._compile_attempt`, `_storage.storage_layouts`), and **RC-VERDICT1**
(two of Rule 4's three triggers could never reach CONFIRMED regardless of
evidence - see its own entry below) - see each item's own entry for detail.
See `tests/test_dedupe.py`, `tests/test_rule_registry.py`,
`tests/test_retry_diagnostics.py`, `tests/test_verdict.py`,
`fixtures-r4-extract/`, `fixtures-r10-safeerc20/`.

- [x] **RC-VERDICT1 — DONE. Two of Rule 4's three triggers could never reach
      CONFIRMED, at all, regardless of evidence.** `src/verdict.py`'s
      `PRE_POST["4"]` was a single `(pragma_before, pragma_after)` pair, but
      rule4.py fires from three structurally distinct triggers and only the
      pragma-lowered one ever emits those two keys - `_safemath_removed` and
      `_unchecked_added` (both real, both fixture-verified-firing:
      `fixtures-r4` P4-02 / P4-01) emit neither, so `_pre_post()` silently
      returned `(None, None)` for them. Reproduced directly: a Rule 4
      safemath-removed finding built with full liveness (LIVE) and HEAD
      survival still capped at CANDIDATE with
      `missing evidence: pre_state, post_state`. This is the exact defect
      class already fixed once for Rule 10 (see the code comment on
      `PRE_POST`'s former "10" entry) - one level deeper: the rule id WAS
      registered, but only one of its three live firing shapes matched what
      was registered, and the existing guard test
      (`test_every_shipped_rule_has_pre_post_and_exclusions`) only checked
      rule-id presence, not per-trigger-shape correctness.

      Fixed via `PRE_POST_BY_TRIGGER["4"]`, keyed on the `"trigger"` evidence
      field already present at every rule 4 emit site: `safemath-removed` now
      reads `(wrapper_calls_before, wrapper_calls_after)` (both keys already
      existed in that emit call); `unchecked-block-added` gained two new
      evidence keys, `checked_before: True, checked_after: False` (the exact
      fact that trigger's own precondition already establishes). `_pre_post()`
      consults the per-trigger map first, falling back to the flat `PRE_POST`
      dict for every other rule id, none of which have multiple trigger
      shapes today. Locked by
      `tests/test_verdict.py::test_rule4_every_trigger_shape_reaches_confirmed`
      (all three trigger shapes, full liveness, must reach CONFIRMED) and the
      updated `test_every_shipped_rule_has_pre_post_and_exclusions` (accepts
      either registration form).

      **Audited every OTHER multi-emit-site rule for the same gap** (any rule
      with >1 `emit()` call: rule2a x3, rule2b x2, rule3b x2, rule3c x2) by
      checking each site's evidence dict against its rule's registered
      PRE_POST keys. rule2a and rule2b: every site consistent, clean. **Two
      more real instances found and fixed the same way:**
      - Rule 3b's SECOND trigger (`disableInitializers-removed` - a
        constructor's `_disableInitializers()` call removed) had NO pre/post
        keys at all. Fixed: `disables_init_before/after` added to its
        `emit()`, registered in `PRE_POST_BY_TRIGGER["3b"]`. **STILL CANNOT
        REACH CONFIRMED for a SEPARATE reason, left open below** (see
        "Rule 3b's disableInitializers trigger" item).
      - Rule 3c's OZ 5 ERC-7201 namespaced-storage trigger (`mode:
        "erc7201-namespaced"`, the 3x-L3 unlock) also had none. Fixed:
        `collision_before/after` (coarser than the OZ 4 path's exact slot
        numbers, because `_namespaced_collision` only returns a bool -
        honest given the data available, not a shortcut). Rule 3c IS
        CONTRACT_LEVEL, so this one reaches CONFIRMED cleanly with full
        evidence, unlike 3b's.
      - `_pre_post()` also needed to check TWO different discriminator key
        names - rules 3b/4 use `"trigger"`, rule 3c uses `"mode"` - since
        neither was unified before this fix touched three rules at once.
      - Locked by `tests/test_verdict.py::test_rule3c_erc7201_trigger_reaches_confirmed`
        and `::test_rule3b_disableinitializers_trigger_has_pre_post_but_still_caps`
        (the latter deliberately asserts CANDIDATE, not CONFIRMED - see below).
      - Neither of the two newly-fixed trigger shapes has ever fired under a
        fixture or on real code; both are, in the code's own words, "no
        fixture exercises this clause yet". The fix corrects the verdict
        model for when they eventually do, not a fixture-verified live case
        the way rule 4's fix was.

- [x] **DONE — Rule 3b's `disableInitializers-removed` trigger can now reach
      CONFIRMED.** Went with fix direction (b): added `_contract_initializer()`
      to `rule3b.py`, which identifies the contract's own critical-config
      initializer (same `has_init_guard` + `_sets_critical_config` criteria
      Trigger 1 already uses) - the actual exposed surface when
      `_disableInitializers()` is removed, since nothing calls a constructor
      twice. Its `visibility`/state-write facts populate `visibility_after`/
      `writes_state_after`; attribution (file/line) stays on `contract_a`,
      unaffected. Fails safe: when no initializer is identifiable, those keys
      stay unset and the finding correctly caps at CANDIDATE rather than
      guessing. Locked by
      `tests/test_verdict.py::test_rule3b_disableinitializers_trigger_reaches_confirmed_via_resolved_initializer`
      and `::test_rule3b_disableinitializers_trigger_caps_when_no_initializer_identifiable`.
      **Still no RULE-level fixture** (proving `rule3b.py.run()` itself fires
      True on a real `_disableInitializers()`-removal diff) - only the
      verdict-model layer is tested here, same scope as the original
      RC-VERDICT1 fix. Building that fixture is separate, still-open work.

Live-scanned 8 requested 1inch repos plus a handful of self-selected targets
(compound-v2, aave-v2 anchor, limit-order-protocol, token-plugins, farming) in
search of a genuinely new real-world finding. **None found** - every fire
candidate either (a) was a true negative on inspection of the real diff (Aave
`20bbae88d399`, corrected above), (b) hit the pre-existing charter-bounded
Foundry ceiling (`1inch/cross-chain-swap`, `1inch/delegating` - COMP-L2), (c)
hit environment-reconstruction limits new to this session (`1inch/farming`'s
COMP-L3 above; `1inch/fusion-protocol`'s HEAD env unavailable;
`1inch/limit-order-protocol`'s dependency install itself timing out at ~25
minutes with no cache hit - never diagnosed further), or (d) genuinely
compiled clean with 0 findings (`v3-core`, `reserve-protocol`, `token-plugins`,
partial `farming`). One notable non-finding: `token-plugins` has a real
historical reentrancy-fix commit sequence (`48d0c29c6acc` "Fix reentrancy in
removeAllPlugins" onward) that Chainwatch correctly stayed silent on - it
detects controls REMOVED, not controls ADDED, so a pre-existing bug being
patched is out of scope by charter, not a miss. Both Solana repos requested
(`1inch/solana-fusion`, `1inch/solana-crosschain-protocol`) correctly reported
"no Solidity files tracked" per `MULTICHAIN-SCOPE.md`'s existing scope
boundary - not attempted further.

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
- [x] **3x-L1 — DONE for 3a/3b/3c** (see this file's top entry, "3x-L1 closed
      for Rules 3a/3b/3c"). Rules 1/2a/2b/4/5/6/10 had already migrated to
      `is_test_path_segments` at some earlier, unrecorded point; 3a/3b/3c were
      the last three, now fixed the same way. Reproduced live on a real 2026
      target (Kinto `BridgedToken`) before being fixed. Original wording
      retained below for provenance.
      ~~3x-L1 — segment-based test/mock path matching (currently substring).
      `latest/`, `contest/`, `greatest/`, `protests/` are all silently skipped
      today. Match a directory named exactly test/tests/mock/mocks/script, or a
      filename `*.t.sol` / `*Mock*` / `*Harness*`. Silent FN across 3a/3b/3c.~~
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

- [x] **DONE — retry loops now report BOTH the first and last attempt.**
      `_shared._compile_attempt` and `_storage.storage_layouts` each capture
      the ambient (first) attempt's exception/stderr before entering the
      fallback loop, and on exhaustion raise/report
      `first attempt (<ambient>): <error> | after N fallback(s), last attempt
      (<version>): <error>` instead of only the last candidate's message.
      Locked by `tests/test_retry_diagnostics.py` (3 cases, a genuinely
      unparseable file that exhausts every installed solc - no real repo
      needed, mirrors the fixture-first discipline for a diagnostic path
      rather than a rule). **Confirmed live and still costing real coverage
      on 2026-08-25**, before this fix, on `1inch/farming` (a fresh target,
      not a repo any prior session had touched): the SAME pair
      (`c320d35302cd..44d786872de5`) showed Rule 1 erroring with "current
      compiler is 0.8.19" (a last-candidate artifact) and Rule 3c erroring
      with `Invalid option to --combined-json: storage-layout` on
      `FarmingPool.sol`/`FarmingPlugin.sol`/`MultiFarmingPlugin.sol` - the
      exact 88mph compiler-floor symptom, reproduced on unrelated code a year
      later. All 21 scorer-compatible fixture sets plus the full pytest suite
      re-run clean after the fix. Original item follows.
- [ ] ~~**Retry loops must report the FIRST failure, not just the last.**
      `_shared._compile` and `_storage.storage_layouts` both keep only the last
      candidate's error, which has now produced three wrong diagnoses (see
      LIMITATIONS.md §METHODOLOGY). Retain and report both:
      `first attempt (<ambient>): <error>; after N fallbacks (<last>): <error>`.
      Cheap, and it would have prevented all three.~~
- [ ] **Rule 3c needs a compiler floor, reported as UNSUPPORTED not an error.**
      `--combined-json storage-layout` does not exist below roughly solc 0.6.x;
      on 0.5.17 the rule raises, and one raising rule marks the whole file
      errored in the coverage accounting even when the other eight produced
      verdicts (88mph: `files 0/1` despite 8 rules running). Detect the
      unsupported option and return a distinct not-applicable signal.

      **STILL OPEN, reconfirmed live (2026-08-25) on `1inch/farming`** - a
      fresh, unrelated target: `FarmingPool.sol`/`FarmingPlugin.sol`/
      `MultiFarmingPlugin.sol` all hit `Invalid option to --combined-json:
      storage-layout` on Rule 3c, costing those files' 3c coverage even though
      the other 9 rules ran fine on the same files. The retry-loop reporting
      fix (above) makes the SYMPTOM legible - the error now clearly says
      "unsupported option", not a misleading version string - but does not by
      itself change the file-level coverage accounting: a raised exception
      still marks the whole file `files_error` rather than "9/10 rules
      verdicted, 1 not applicable at this compiler version". Deliberately NOT
      attempted this session: a genuine "not-applicable" signal needs a new
      outcome type distinct from (True/False/"candidate"/error) threaded
      through `_run_rule`, `Coverage`, the CLI/web report renderers, and their
      tests - a real schema change, not a local fix, and not safe to rush.
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

- [x] **RC-MUTEX1 — DONE 2026-08-18, BOTH directions. Locked by `fixtures-rmutex/`
      (N3c-mutex-01 quiet, P3c-mutex-01 still fires, P10-mutex-01 fires where it
      was silent). Live: v3-core c67ae093edd9..76a9ffa6ebc4 now 0 findings. The
      naive one-constant form regressed fixtures/N3b-01 (reinitializer) and was
      corrected to a two-condition test. Original item follows.**
- [ ] ~~**RC-MUTEX1 — a set/clear reentrancy mutex satisfies
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

- [x] **RC-EXTRACT1 — DONE.** `_safemath_removed` (rule4.py) now evaluates
      reachability: for every entry function present in both commits, it sums
      checked-arithmetic library calls across `reachable(fn)` (itself, its
      modifiers, every internal helper it transitively calls) instead of
      scanning only the function's own body. A checked-call count that drops
      from >0 to 0, with plain arithmetic still reachable, fires - whether the
      checked call was removed outright or extracted into a brand-new helper.
      Attribution stays on the ENTRY function (never the resolved helper),
      matching rule2b's RC-INLINE2 convention, so file/line always come from
      one self-consistent object. Locked by `fixtures-r4-extract/`: P4x-01
      (SafeMath extracted into `_swapLiquidity` and dropped - fires), N4x-01
      (diff-identical extraction that KEEPS the SafeMath call one level deeper
      - stays quiet, the case that proves this isn't "any extraction fires"),
      N4x-02 (an unrelated new-at-N helper with its own plain arithmetic added
      *alongside* an unchanged, still-reachable SafeMath call - stays quiet,
      the case that proves reachable-set widening alone can't cause a false
      positive). All three fixture sets that exercise rule 4 (`fixtures-r4`,
      `fixtures-r4-extract`) plus every other frozen set re-run clean, 0 FP.

      **CORRECTION, checked against the real commit (2026-08-25).** The item
      below cites Aave v2 `20bbae88d399` as the real-world source. Re-run
      against that EXACT commit anchored via a worktree
      (`48b9a603a796..20bbae88d399`, `--rules 4`): **0 findings, 3/3 files
      compiled OK, 0 rule errors** - and reading the actual diff shows why
      that is CORRECT, not a miss. `_swapLiquidity` (the new helper
      `amounts[i].add(...)` moved into) still computes
      `amount.add(premium)` and `aTokenInitiatorBalance.sub(premium)` through
      SafeMath - the checked call relocated, it did not disappear. The
      original wording ("lost its visible SafeMath") described the caller's
      OWN body losing its arithmetic, which is true but is not the same claim
      as "lost its protection." This specific citation is retracted as a
      demonstrated positive; the FIX ITSELF remains correct and is proven by
      the synthetic `fixtures-r4-extract` pair, which models the shape where
      protection genuinely IS dropped during extraction. No real-world commit
      currently demonstrates RC-EXTRACT1 firing; one may still exist
      elsewhere and has not been searched for beyond this one citation.
      Original item follows.
- [ ] ~~**RC-EXTRACT1 — Rule 4 fires when arithmetic is EXTRACTED into a helper.**
      The de-inlining direction of the RC-INLINE family, on a third rule.
      Measured on Aave v2 `20bbae88d399`
      (`UniswapLiquiditySwapAdapter.executeOperation`): `amounts[i].add(...)`
      moved from line 82 of the caller to line 187 of a new `_swapLiquidity`
      helper, so the caller kept its raw loop counter and lost its visible
      SafeMath. Fix direction: evaluate Rule 4 over `reachable(fn)`, as rules
      2a/2b now do via `_cfg.after_call_writes_resolved`. The hard fixture is a
      commit that extracts a helper AND genuinely drops SafeMath inside it,
      which must still fire.~~

- [x] **RC-NEWCALL1 — DONE 2026-08-18.** `has_external_call(fn_b)` precondition;
      N2bn-01; live pair 0 findings. Original follows.
- [ ] ~~**RC-NEWCALL1 — Rule 2b fires when a function gains its FIRST external
      call.** `state_writes_after_calls` returns the empty set by construction
      when there are no call nodes, so every write after the newly-added call
      reads as moved. Measured on v3-periphery `a796106e098c`
      (`NonfungiblePositionManager.permit`, EIP-1271 support added). Fix
      direction: require `fn_b` to have had at least one external call before
      comparing sets - the shape of Rule 10's T2 precondition. Needs both
      directions: no-call-at-N-1 gaining one (quiet), and a genuine reorder
      where both commits already had calls (must still fire).

- [x] **RC-NEWVAR1 — DONE 2026-08-18.** `moved` restricted to variables present
      at N-1; N2bn-02; live pair 0 findings. Original follows.
- [ ] ~~**RC-NEWVAR1 — Rule 2b fires on a state variable introduced at N.** A
      variable absent at N-1 cannot be in the N-1 set, so any write to it is
      unconditionally "moved". Measured on v3-periphery `0239382f49b3`
      (`Quoter.amountOutCached`, transient storage). Fix direction: restrict
      `moved` to variables present in `contract_b.state_variables`.

- [x] **RC-RENAME2 — DONE 2026-08-18.** Rule 6 keys guarded parameters by
      POSITION, safe because _candidate_map matches on full_name (types, not
      names). fixtures-r6-rename 1.00/1.00; live pair 0 findings. Original
      follows.
- [ ] ~~**RC-RENAME2 — a parameter rename reads as a removed require (Rule 6).**
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

- [x] **RC-DEDUP1 — DONE.** Two compounding bugs, both in `src/scan.py`. (1)
      After a rule fired, the walker unconditionally stamped
      `f.file = rel` - the file the walker HAPPENED to be compiling - over the
      correctly-attributed absolute path `_shared.emit`/`V.build` had already
      set, so a contract reachable from more than one changed file's compiled
      unit got mislabelled to whichever file triggered that particular
      compile. Fixed via `_repo_relative()`, which resolves the true
      declaration path against the checkout roots and falls back to `rel`
      only when that fails. (2) With attribution correct, the SAME
      declaration discovered from two different compiled units still produced
      two Finding objects. Fixed via `_dedupe()`, called once after the full
      walk (before liveness, so an RPC call is never spent twice on one
      fact), collapsing by (rule_id, commit, contract, function, evidence
      variable, line, detail) - a key that never touches which file triggered
      the compile. Locked by `tests/test_dedupe.py` (12 cases, pure functions,
      no Slither needed): collapses the true duplicate, keeps distinct
      variables/commits/rules on the same contract, preserves first-seen
      order. Original item follows.
- [ ] ~~**Contract-level findings need deduplication by (contract, variable).**
      The same 3c result was emitted twice on v3-core, attributed to
      `UniswapV3Factory.sol` and `UniswapV3Pair.sol`, because `UniswapV3Pair`
      is reachable from both compiled units and each file is genuinely in the
      commit's changed set, so DESIGN-L2's `accept_finding` accepts both.~~

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

- [x] **WALK-L7 invariant test — DONE.** `tests/test_rule_registry.py` asserts
      `set(RULES) == set(RULE_ORDER) == set(RULE_TITLES)` in both directions
      (registered-but-unscheduled, scheduled-but-unregistered, and untitled).
      Currently all three agree (10 rule ids); the test exists so the next
      rule that repeats Rule 10's silent-absence shape fails loudly instead of
      shipping green. Original item follows.
- [ ] ~~**WALK-L7 invariant test — assert `set(RULE_ORDER) == set(RULES)`.** Rule
      10 was registered, fixture-tested at precision 1.00, and silently absent
      from the product because `src/scan.py`'s `RULE_ORDER` did not list it.
      Every gate was green while the rule did nothing. Nothing stops the next
      rule repeating this exactly. One assertion; deliberately not written in
      the doc pass, because tests get added on purpose, not in passing.~~
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

## Open after the Step 4 ERC20 widening (2026-08-18)

- [ ] **WALK-L8 — a scan MUTATES shared per-repo worktree state, so an unrelated
      scan can invalidate a later analysis of the same repository.** Found the
      hard way: an ERC20 live re-check sampling 6 pairs across 2906 Reserve
      commits left `.walker-worktrees/<repo-hash>/` with `node_modules`
      reconstructed for a much newer dependency set, and the NEXT analysis of
      `f43202a3..e27227b2` then failed every file with
      `Source "@reserve-protocol/trusted-fillers/..." not found`. That surfaced
      as `tests/test_realworld_reserve.py` failing with "the known TRUE POSITIVE
      did not fire", which reads like a detection regression and is not one -
      0 of 8 files compiled, so nothing could fire. Deleting the worktree
      restored 3/3.
      The scratch directory is keyed by repo path alone, so every scan of a repo
      shares one mutable env. Fix direction: key the worktree/dependency state
      by EnvSpec as well as repo, or reset it per run. Until then, a failing
      real-world test should be checked for `files_ok=0` BEFORE it is read as a
      detection change - the coverage line distinguishes the two, exactly as
      HIST-L2 said it would.
- [x] **DONE — Rule 10 SafeERC20 widening.** `rule10._value_vars` now matches
      `safeTransfer`/`safeTransferFrom` LibraryCalls via `_shared.
      SAFE_ERC20_DEST_POS`, measured (not assumed) against a real Slither
      parse: the `using X for Y` receiver rides as the LibraryCall's own
      `arguments[0]`, shifting every destination position by one relative to
      the raw `ERC20_RETURN_FNS` positions (`safeTransfer` -> 1,
      `safeTransferFrom` -> 2). Locked by `fixtures-r10-safeerc20/`: P10se-01
      (SafeERC20 treasury migration, diff-identical to P10e-01 - fires),
      N10se-01 (`safeApprove` is not in the position table at all, so it is
      never even considered - the SafeERC20-side N10e-01), N10se-02
      (`safeTransferFrom`'s SOURCE is argument 1 in the shifted scheme, not
      argument 0 - the shift-aware counterpart of N10e-02's position trap).
      Every other rule-10 and cross-rule fixture set re-run clean, 0 FP.
      Original item follows.
- [ ] ~~**Rule 10 residual: SafeERC20 wrapper transfers are still invisible.**
      `safeTransfer`/`safeTransferFrom` compile to a `LibraryCall`, not a
      `HighLevelCall`, so the ERC20 widening does not match them. Reserve uses
      that pattern throughout, which is why its live re-check returned 0
      findings and why that zero is consistent rather than reassuring. Widening
      to library calls needs its own fixtures.~~
