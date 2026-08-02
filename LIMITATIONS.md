# Chainwatch — Known Limitations

Findings, not commentary. Every item below is a case where a shipped rule is
known to give the wrong answer, recorded at the time it was discovered so it
survives the session that found it.

**Status:** as of Rules 3a, 3b and 3c shipping at precision 1.00 / recall 1.00
against the 10-case fixture set. Capability 11 (on-chain liveness) is not yet
built.

## How to read this file

Each item is tagged with the direction it fails in:

- **[FN risk]** — a real regression the tool stays silent on. Costs a finding.
- **[FP risk]** — a non-regression the tool would report. Costs credibility,
  which RULES.md names as the actual asset. These are the serious ones.

Per RULES.md's precision-first tie-break, the rules are deliberately biased
toward FN. Most of what follows is the price of that choice, knowingly paid.

---

## Rule 3c — Storage layout collision

Rule 3c decides two independent things: *did the layout change* (answered by a
real `solc --storage-layout` comparison, slot by slot) and *is this contract
behind a proxy* (exclusion 3c.3). The layout half is compiler-authoritative.
Every limitation below is in the proxy half.

The proxy determination uses two signals:

- **Signal A — self-declaration.** The contract carries one-shot initialization
  machinery (a modifier that gates on *and writes* a storage flag). A contract
  intended for proxy deployment cannot use a constructor for setup, because
  constructor code never runs against proxy storage, so it must be
  initializer-based.
- **Signal B — in-unit corroboration.** A factory constructs this contract and
  a proxy-shaped contract (fallback + delegatecall) in the same function.

### Signal A blind spots

| # | Limitation | Direction |
|---|---|---|
| 3c-L1 | **EIP-1167 minimal-proxy / clone targets.** A clone target holds persistent storage across redeployments of the pattern but need not inherit any OpenZeppelin upgradeable base. Signal A sees no init machinery and discards. | **[FN risk]** |
| 3c-L2 | **EIP-2535 Diamond facets.** Facets execute against the Diamond's storage via delegatecall and frequently carry no `Initializable`. Layout collisions between facets are real and invisible here. | **[FN risk]** |
| 3c-L3 | **Solady-style and hand-rolled implementations.** Non-OZ upgradeable bases may implement initialization without the read-and-write storage-flag shape Signal A keys on. | **[FN risk]** |
| 3c-L4 | **`Initializable`-inheriting but directly deployed contracts.** A contract may inherit OZ upgradeable bases out of habit, or be an abstract base whose concrete children are never proxied. Signal A passes it on **intent, not fact**, and a harmless layout change is reported. | **[FP risk]** |

### Signal B blind spots

| # | Limitation | Direction |
|---|---|---|
| 3c-L5 | **Proxies declared outside the compilation unit.** Signal B only sees contracts in the file/unit under analysis. A proxy declared in a Foundry/Hardhat deploy script, a `broadcast/` or `deployments/` JSON artifact, or an entirely separate repository is never observed. Signal B therefore contributes nothing on the majority of real repos, leaving Signal A load-bearing in practice. | **[FN risk]** |

### Structural blind spots

| # | Limitation | Direction |
|---|---|---|
| 3c-L6 | **ERC-7201 namespaced storage defeats sequential slot comparison.** State lives in structs at keccak-derived slots rather than sequential slots 0,1,2… There is nothing for a slot-by-slot comparator to compare, so the rule goes quiet regardless of what changed inside the namespaced struct. Silent, and **growing**: ERC-7201 is the default in OpenZeppelin 5.x, so coverage decays as repos migrate off 4.x. **CORRECTED (Phase 5b) — this entry understated the damage in two ways.** ERC-7201 defeats proxy **detection** one layer *earlier* than layout comparison, so Rule 3c never even reaches the comparator; and the same mechanism disables **Rule 3b**, which this entry never claimed. The real scope is in **3x-L3**, which supersedes this row for OZ 5.x projects. Treat a quiet 3c result on an OZ 5.x repo as *unmeasured*, not as *safe*. | **[FN risk]** |
| 3c-L7 | **OpenZeppelin dependency version bumps between commits.** If the OZ version itself changes across the two commits, inherited base-contract layouts shift wholesale and every downstream variable appears relocated. Sometimes this is a genuine hazard, but it surfaces as one enormous finding covering every variable rather than a targeted one, and it will fire on routine dependency-upgrade commits. | **[FP risk]** |

### The core caveat

**Signal A proves *intent* to be proxied, not the *fact* of it.** Source code
can only ever show that a contract was written to be deployed behind a proxy;
it cannot show that it actually is, nor which proxy holds which implementation
today. That gap is not closable by static analysis of a repository.

**Capability 11 (on-chain liveness) is what closes it.** Comparing deployed
bytecode at a real address against the implementation built from a given commit
replaces the inference "this looks proxy-shaped" with the observation "this
exact code is behind this exact proxy right now." This is a concrete reason the
charter names capability 11 the decisive gate: without it, 3c's key exclusion
rests on a declaration of intent rather than a deployment fact.

---

## Rule 3a — Upgrade authorization weakened

| # | Limitation | Direction |
|---|---|---|
| 3a-L1 | **Fixed target-function set.** The rule inspects `_authorizeUpgrade`, `upgradeTo`, `upgradeToAndCall`, `changeAdmin`, `changeProxyAdmin`. A protocol with a custom-named upgrade entry point is not examined at all. | **[FN risk]** |
| 3a-L2 | **Detects constraint → *no* constraint, not narrow → wide.** The trigger in RULES.md is that the caller set *widened*. The implementation tests whether any msg.sender-dependent guard survives. A genuine weakening that keeps some msg.sender check — `onlyOwner` replaced by a check against a mutable, publicly-settable address, or by `require(msg.sender != address(0))` — keeps the rule quiet. This is the widest gap in Rule 3a. | **[FN risk]** |
| 3a-L3 | **3a.1 is discarded silently rather than raised as CANDIDATE.** RULES.md specifies that a move to a timelock/multisig should reach a human as a CANDIDATE. The current harness has no CANDIDATE state (see cross-cutting below), so N3a-01-shaped changes vanish. The fixture's own review note — that a timelock set in an initializer stays `address(0)` on an already-deployed proxy and *locks* the upgrade path — is exactly the kind of nuance a human is supposed to see and currently would not. | **[FN risk]** |

---

## Rule 3b — Initializer re-callable

| # | Limitation | Direction |
|---|---|---|
| 3b-L1 | **Detects the diff pattern, not end-to-end callability.** Fixture P3b-01 is the documented instance: with the `initializer` modifier removed, its `initialize()` still calls `__Ownable_init()` / `__UUPSUpgradeable_init()`, which carry `onlyInitializing` (`require(_initializing)`), so the function always reverts and is un-callable rather than exploitable. The rule fires — correctly per the RULES.md trigger — but a finding of this shape is not by itself proof of exploitability. P3b-02 is the runtime-exploitable sibling kept alongside it precisely so this distinction stays visible. | **[FP risk]** |
| 3b-L2 | **Trigger 2 is unexercised.** The "constructor's `_disableInitializers()` was removed" clause is implemented and spec-faithful but no fixture covers it. It is unproven code: neither its firing nor its silence has been demonstrated. | **unproven, both directions** |
| 3b-L3 | **Shares the proxy determination with Rule 3c.** Exclusion 3b.4 discards only on proof the contract is never proxied, using the same Signal A. Every Signal A blind spot above (3c-L1 through 3c-L4) applies here too. | **[FN + FP risk]** |
| 3b-L4 | **Shallow caller analysis for 3b.3.** Whether an internal initializer's callers are themselves guarded is checked one level through the contract's own external functions. Deeper or cross-contract call paths are not resolved. | **[FP risk]** |

---

## Cross-rule — applies to 3a, 3b and 3c alike

Both items below were found in Phase 5, running the rules against the real
Monetrix contracts (`realworld-test/monetrix-src/`, a Code4rena project). They
are recorded because a real corpus surfaced them and a hand-built fixture set
did not.

### 3x-L1 — test/mock path exclusion is a substring match

**Type: FALSE NEGATIVE (silent).**

Every rule begins by discarding test/mock/script paths. The check is a plain
substring match of `test/`, `tests/`, `mock/`, `mocks/`, `script/`, `scripts/`
against the whole path. Any real project directory whose name merely *ends* in
one of those words is therefore skipped: the rule returns `False` having
examined nothing, and the output is indistinguishable from a genuine clean
result.

Verified against the shipped matcher:

| Path | Skipped? | |
|---|---|---|
| `latest/Vault.sol` | **yes** | false negative |
| `contest/Vault.sol` | **yes** | false negative |
| `greatest/Vault.sol` | **yes** | false negative |
| `protests/Vault.sol` | **yes** | false negative |
| `src/latest/Vault.sol` | **yes** | false negative — any depth |
| `attestations/Vault.sol` | no | markers require a trailing `/`, so this yields `testa`, not `test/` |
| `test-helpers/Vault.sol` | no | |

**How it was caught.** Phase 5's first run reported a clean "0 detections across
20 files" — with every rule returning in **0.0 seconds**, which is impossible
for a Slither parse plus a `solc --storage-layout` invocation. Our own harness
directory `realworld-test/` contains the substring `test/`, so all three rules
bailed out before examining a single contract. The run was a false PASS. Timing
was the only signal that anything was wrong; the verdicts themselves looked
correct.

A second exposure: when a caller does not supply `source_path`, the rules fall
back to the *filesystem* path. Any component of the absolute path — a user
directory named `latest`, a CI workspace named `contest` — can then silently
disable analysis for an entire run.

**Fix direction (deliberately not implemented yet):** match on path *segments*,
not substrings — a directory named exactly `test`, `tests`, `mock`, `mocks` or
`script`, or a filename matching `*.t.sol` / `*Mock*` / `*Harness*`. Tracked in
TODO.md.

### 3x-L2 — OZ major-version pre-screen was wrong

**Type: analysis-blocking / wrong assumption.**

The Monetrix corpus was screened as "OpenZeppelin 4.x" on the strength of its
storage style: it uses sequential storage rather than ERC-7201 namespacing.
That signal is **necessary but not sufficient**. The corpus in fact imports OZ
**5.x** paths — `PausableUpgradeable` and `ReentrancyGuard` live under `utils/`
in OZ 5, but under `security/` in the pinned 4.9.6. A project can use OZ 5
while keeping sequential storage in its own contracts, so storage style alone
cannot establish the dependency major version. **Import paths must be checked
too.**

**Consequence:** 4 of 20 files failed to compile under the pinned 4.9.6 and were
left entirely unmeasured — `MonetrixVault.sol`, `MonetrixAccountant.sol`,
`USDM.sol`, `sUSDM.sol`, with the raw error `Source
"@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol" not found`.
This includes **MonetrixVault, the largest and most complex contract in the
project — precisely where a false positive is most likely**. The Phase 5 result
is therefore "0 false positives on 16 of 20 files", not on 20. Silence on those
four files is *unmeasured*, not *clean*, and must not be reported as evidence of
precision. Tracked in TODO.md.

### 3x-L3 — Rules 3b and 3c cannot fire at all on OpenZeppelin 5.x

**Type: STRUCTURAL BLINDNESS (silent). Affects Rule 3b and Rule 3c.**
Supersedes 3c-L6 for OZ 5.x projects.

On any project using OpenZeppelin 5.x base contracts, **Rules 3b and 3c are
incapable of producing a finding** — not less accurate, incapable. Rule 3a is
unaffected.

**Mechanism.** OZ 5 moved the initialization flags `_initialized` /
`_initializing` out of declared state variables and into an **ERC-7201
namespaced struct**, reached through an assembly storage pointer at a constant
slot. Observed directly against OZ 5.7.0:

```
modifier Initializable.initializer()
   state vars WRITTEN : [] <-- EMPTY
   state vars READ    : ['INITIALIZABLE_STORAGE']
   is_oneshot_init_guard = False
```

Slither attributes **no declared state-variable write** to `initializer`,
`reinitializer`, or `onlyInitializing`, because the write goes through the
assembly pointer. `is_oneshot_init_guard()` requires the gate-on-and-write-the-
same-flag shape, so it returns False for all three. The failure then cascades:

1. `is_oneshot_init_guard` → False for every OZ 5 init modifier
2. → `defines_init_machinery()` (Signal A) → False for every contract
3. → Rule 3c exclusion **3c.3** discards every contract as "not behind a proxy"
4. → Rule 3b exclusion **3b.4** discards every contract on the same signal

Both rules therefore return quiet before examining anything of substance. The
storage-layout comparator in 3c is never reached, so this is *not* the
"nothing to compare" problem described in 3c-L6 — it fires one layer earlier
and is not confined to Rule 3c.

**Proven, not inferred.** Two synthetic OZ 5.7.0 regressions were built with
exactly the shapes of fixtures P3b-01 / P3b-02 and P3c-01 — the same shapes that
score **1.00 recall** under OZ 4.9.6:

```
Rule 3b  initializer modifier REMOVED from ownership-setting fn : QUIET  <-- MISSED
Rule 3c  storage var INSERTED mid-layout on UUPS proxy contract : QUIET  <-- MISSED
```

**How it was found.** Phase 5b, on the real Monetrix corpus. Monetrix is the
case that makes the scope unambiguous: it uses **sequential** storage in its own
contracts, so 3c's layout comparator would have worked correctly. It is the OZ 5
*base classes alone* that blind both rules. After recovering the 4 previously
uncompilable files under OZ 5.7.0, Rule 3c reported `proxied contracts: none` on
all four, where the same rule found `InsuranceFund(10)` and `MonetrixConfig(26)`
under OZ 4.9.6.

**Consequence for reporting.** The Phase 5b headline "0 false positives across
20/20 Monetrix files" is accurate but must never be quoted without this
qualifier: on the 4 files analyzed under OZ 5, **Rules 3b and 3c contributed no
signal at all**. Their silence there is structural, not evidence of precision.
Only Rule 3a's silence on those files is meaningful.

**Fix direction (not implemented):** teach Signal A to recognise ERC-7201 init
machinery structurally — a modifier that reads a constant namespace slot and
writes through an assembly storage pointer. Tracked in TODO.md; it is the single
unlock for OZ 5 support in both rules.

**STATUS UPDATE — both modes now built.** Signal A recognises ERC-7201 init
machinery, so Rule 3b fires on OZ 5 (P3b-oz5-01), and Rule 3c gained an
AST struct-offset comparator for namespaced structs (P3c-oz5-01), both scoring
precision 1.00 / recall 1.00 on `fixtures-oz5/` with the OZ 4 set unchanged at
1.00/1.00. One correction to the note above: fixing Signal A was the unlock for
Rule 3b only. Rule 3c needed a **second, independent** piece of work, because
`solc --storage-layout` reports an empty layout for namespaced contracts and so
the comparator had nothing to diff even once the proxy gate worked. The
remaining gaps in the OZ 5 path are 3c-oz5-L1 and 3c-oz5-L2 below.

### 3c-oz5-L1 — exclusion 3c.2 (`__gap` consumption) is not implemented on the OZ 5 path

**Type: FALSE POSITIVE risk. Rule 3c, OZ 5 mode only.**

The OZ 4 path forgives a reserved `__gap` that shrinks by exactly the space an
inserted variable consumes, because every pre-existing slot is preserved
(fixture N3c-02). The OZ 5 namespaced-struct comparator has **no equivalent
exclusion**: it compares member offsets only. Shrinking a `__gap` member inside
an ERC-7201 struct while adding a member before it is a safe, intentional
pattern, and it would currently be reported as a collision.

**Exposure is low but real.** ERC-7201 gives each contract its own storage
namespace, which is precisely the problem `__gap` existed to solve, so gap
members inside namespaced structs are uncommon. That is a reason to defer the
work, not a reason to consider the rule complete.

**Deliberately not implemented yet.** There is no OZ 5 gap fixture, and shipping
an untested exclusion is how a rule quietly acquires a false *negative* while
fixing a false positive. The order must be: build the fixture first, then
implement 3c.2 for the namespaced path against it — the same fixtures-first
discipline used for every rule so far. Tracked in TODO.md.

### 3c-oz5-L2 — hybrid contracts take the OZ 4 path only

**Type: FALSE NEGATIVE risk. Rule 3c.**

Mode selection is per contract and keyed on whether `solc --storage-layout`
returned anything: a non-empty layout takes the OZ 4 path, an empty one falls
through to the OZ 5 namespaced comparator. A contract holding **both** declared
state variables **and** an ERC-7201 namespaced struct therefore reports a
non-empty layout, takes the OZ 4 path, and its namespaced struct is never
compared. Changes inside that struct are missed silently.

This hybrid is unlikely — a project adopting namespaced storage normally moves
all of its state there — and it is recorded for completeness rather than as a
live concern. The fix is to run both comparators whenever a namespaced struct is
present, instead of treating the two modes as mutually exclusive. Tracked in
TODO.md.

### 3b-L-ratelimit — an init guard and a rate-limit guard are structurally identical

**Type: FALSE POSITIVE risk. Rule 3b, BOTH the OZ 4 and OZ 5 paths.**

Rule 3b identifies a one-shot initialization guard structurally: a guard that
**gates on a storage value it also writes**. That test is *necessary but not
sufficient*. A rate-limit guard has exactly the same shape:

```solidity
// MonetrixVault.keeperBridge - real code, Phase 5c full run
require(block.timestamp >= lastBridgeTimestamp + config.bridgeInterval(), "too early");
...
lastBridgeTimestamp = block.timestamp;   // reads and writes the same var
```

`keeperBridge` is an operational bridging function
(`onlyOperator, requireWired, whenNotPaused, whenOperatorNotPaused`), yet
`has_init_guard()` returns **True** for it, and because it also writes
`PausableStorageLocation` it is additionally counted as touching access-control
state — so Rule 3b classified it as *init-guarded and critical-config*.

**No false positive was produced**, because Phase 5c compares each contract to
itself and nothing changed. The exposure is on a real diff: if a commit removed
that rate-limit `require`, Rule 3b would report it as an **initializer
regression**. The finding would be mislabeled — wrong rule, wrong explanation,
and it would reach a triage team as an SC10 proxy-initialization issue when it is
actually a rate-limiting change. RULES.md names credibility with triage teams as
the actual asset, so a confidently mislabeled finding costs roughly what a false
positive costs.

**Root cause and the missing discriminator.** An initialization flag is *set once
and never reset*: after the guard passes, the value is written to a state that
can never satisfy the guard again. A rate-limit variable is *rewritten on every
successful call*, and the guard is designed to pass again later. The current test
does not distinguish "written once, monotonically closing the gate" from "written
every call, reopening the gate", and that distinction is exactly what separates
the two. Note this is not an OZ 5 regression — the OZ 4 declared-variable path
has always had it; the OZ 5 namespaced path inherited the same semantics
deliberately, to keep the two modes equivalent.

Fixing this needs a rate-limit **negative** fixture first, per the
fixtures-first discipline. Tracked in TODO.md.

### 3c-oz5-realworld-gap — the OZ 5 comparator has no real-world evidence

**Type: EVIDENCE GAP, not a defect.**

Rule 3c's OZ 5 namespaced-struct comparator is validated **only** by
`fixtures-oz5/`. No real-world code has ever exercised it.

Phase 5c ran all 20 Monetrix contracts under OZ 5.7.0 with 0 false positives,
and that result must not be read as evidence for the OZ 5 comparator. Every
Monetrix contract reported `mode=OZ4 declared-vars` — the project imports OZ 5
packages but declares its own state **sequentially**, so all 12 upgradeable
contracts took the OZ 4 `solc --storage-layout` path. Their only ERC-7201
structs are inherited from OpenZeppelin base contracts under `node_modules`,
which the comparator excludes by design (3c-L7). The namespaced code path was
therefore never entered, not even once, across the full run.

**What would close this:** a real protocol that uses ERC-7201 namespaced storage
in **its own** contracts, not merely via OZ 5 dependencies. Until then, treat
Rule 3c's OZ 5 mode as fixture-validated only — the same standard applied to
every other rule before real-world testing, and the reason charter criteria 6
and 7 remain unmet. Tracked in TODO.md.

---

## Capability 11 — On-chain liveness (the decisive gate)

Comparison method: **normalized runtime-bytecode identity**. Deployed runtime
code (`eth_getCode`, after resolving proxies) is compared against a reference,
with the CBOR metadata trailer split off and immutable ranges masked, then
keccak-hashed. Findings on each hard problem, all verified against mainnet:

| # | Problem | How it is handled, and what it costs |
|---|---|---|
| 11-F1 | **Runtime vs creation bytecode** | Solved, not papered over: we compare against `solc --bin-runtime`, the artifact that matches what `eth_getCode` returns. Consequence: creation bytecode is *not* recoverable from the chain at all, so constructor logic is outside what liveness can ever verify. |
| 11-F2 | **CBOR metadata trailer** | Stripped before hashing (last 2 bytes are the blob length). Verified on real data that the trailer format is not even stable within one contract's own lineage: Aave V3 Pool's current implementation carries a 10-byte trailer (compiler version only) while its original implementation carries 51 bytes including an ipfs source hash. Any byte-equality check would have reported PATCHED on two identical deployments. |
| 11-F3 | **Immutables** | Masked using solc's `immutableReferences` when a compiled artifact is available. **This is the main false-PATCHED source in bytecode-vs-bytecode mode**: there we have no artifact and therefore no immutable offsets, so two deployments with identical logic but different constructor-set immutables (a different oracle or treasury address) compare as PATCHED. See 11-R2. |
| 11-F4 | **Constructor arguments** | Structurally absent — they are appended to *creation* code, and we compare runtime code. Choosing runtime comparison eliminates this problem rather than mitigating it. |
| 11-F5 | **Proxy indirection** | `eth_getCode` on a proxy returns the *proxy's* code, so a naive check inspects the wrong contract and is blind to every Rule 3 finding. We resolve first: EIP-1967 slot, then beacon (via a read-only `implementation()` call), then EIP-1167 inline clone target, then the legacy zeppelinos slot. |

### Verified finding: the standard slot is not universal

USDC (`0xA0b8…eB48`), one of the largest contracts on mainnet, returns **zero**
at the EIP-1967 implementation slot. Its implementation lives at the pre-1967
zeppelinos slot `keccak256("org.zeppelinos.proxy.implementation")`, where it
resolves to `0x43506849…02dd`. A liveness check that assumes the EIP-1967 slot
would silently compare the *proxy's* code and could report either verdict
without ever touching the real implementation. This is why the resolver tries
four schemes and reports which one matched (`proxy_kind`).

### Error rates

| # | Risk | Direction |
|---|---|---|
| 11-R1 | **LIVE means "this executable code is running", not "this exact commit is deployed."** Metadata stripping and immutable masking are deliberate, and they make the mapping commit→normalized-hash many-to-one: two commits differing only in comments, NatSpec, or immutable values normalize identically. Liveness can confirm or deny that a commit's *code* is running; it cannot uniquely identify *which* commit produced it. | **[FP risk]** — bounded: a real logic fix always changes normalized code, so a genuinely patched contract cannot report LIVE. |
| 11-R2 | **False PATCHED from unmaskable immutables or library linking** in bytecode-vs-bytecode mode. Without an artifact there are no immutable offsets or library placeholder positions to mask, so configuration-only differences read as code differences. | **[FP risk]** (reports a regression as not-live / a mismatch that is not real) |
| 11-R3 | **Source-compiled mismatches are reported UNKNOWN, never PATCHED.** A local recompile cannot be distinguished from the original build unless optimizer runs, viaIR, evmVersion, and library links are all reproduced, and none of those are recoverable from deployed bytecode. Verified: comparing a locally compiled fixture against a live contract returns UNKNOWN citing `deployed solc 0.8.27 != reference solc 0.8.20`. The cost is **UNKNOWN inflation** — on real repos the source path will often refuse to conclude. That is the intended trade. | **[FN risk]**, deliberately chosen |
| 11-R4 | **Diamonds (EIP-2535) have no single implementation slot.** Resolution finds nothing, falls through to `proxy_kind="none"`, and compares the Diamond's own code — which is not where the facet logic lives. Silent, and it compounds 3c-L2. | **[FN risk]** |
| 11-R5 | **Archive-node dependency and provider limits.** Historical implementation reads need archive state. Observed on the configured provider: `eth_getLogs` over full history is rejected outright (HTTP 400), so upgrade history was reconstructed with historical `eth_getStorageAt` instead. A provider without archive access silently loses the ability to establish what *was* deployed. | **[FN risk]** |
| 11-R6 | **A verdict is a snapshot at one block on one chain.** The implementation can be upgraded immediately after the read, and the same source deployed to other chains may sit behind a different implementation. Report the block and chain_id with any finding; both are recorded in the evidence. | **[FP risk]** |

### Control status

Both directions are proven on real mainnet data (chain_id 1), not asserted:
positive control returns LIVE against the current implementation, negative
control returns PATCHED against the superseded original implementation of the
same proxy. Charter success criterion 5 is met for this contract. It has **not**
been exercised across a broad set of proxy styles — one EIP-1967 proxy, one
legacy-slot resolution, and no beacon or clone tested against live data.

---

## Cross-cutting

| # | Limitation | Direction |
|---|---|---|
| X-L1 | **No CANDIDATE state exists yet.** `src/verdict.py` is still empty; rules return a binary fire/quiet. Every exclusion RULES.md designates as "CANDIDATE, needs human read" (3a.1, and later 2.10 and 5.3) is currently a silent discard. The three-state model is specified but not implemented. | **[FN risk]** |
| X-L2 | **The fixture set is small and narrow.** Precision 1.00 across 10 hand-written single-file cases, all OpenZeppelin 4.9.6, all solc 0.8.20. This demonstrates the rules do what they were designed to do; it is **not** evidence of precision on real repositories. Charter success criteria 6 and 7 (a CONFIRMED finding on a real independent repo, and a real-world false positive root-caused and added as a permanent negative fixture) remain unmet. | **[FP risk]** |
| X-L3 | **Single-file analysis.** Every fixture is one self-contained file. Real repos spread contracts, bases, and proxies across directories and imports; multi-file resolution and per-commit `pragma`/solc-version switching via solc-select are not yet exercised by the history walker (`src/history.py` is empty). | **[FN risk]** |
