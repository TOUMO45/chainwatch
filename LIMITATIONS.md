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
| 3c-L6 | **ERC-7201 namespaced storage defeats sequential slot comparison entirely.** State lives in structs at keccak-derived slots rather than sequential slots 0,1,2… There is nothing for a slot-by-slot comparator to compare, so the rule goes quiet regardless of what changed inside the namespaced struct. This is a **silent** false negative — indistinguishable from a clean result. It is also **growing**: ERC-7201 is the default in OpenZeppelin 5.x, so coverage of this rule decays as repos migrate off 4.x. Treat a quiet 3c result on an OZ 5.x repo as *unmeasured*, not as *safe*. | **[FN risk]** |
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

## Cross-cutting

| # | Limitation | Direction |
|---|---|---|
| X-L1 | **No CANDIDATE state exists yet.** `src/verdict.py` is still empty; rules return a binary fire/quiet. Every exclusion RULES.md designates as "CANDIDATE, needs human read" (3a.1, and later 2.10 and 5.3) is currently a silent discard. The three-state model is specified but not implemented. | **[FN risk]** |
| X-L2 | **The fixture set is small and narrow.** Precision 1.00 across 10 hand-written single-file cases, all OpenZeppelin 4.9.6, all solc 0.8.20. This demonstrates the rules do what they were designed to do; it is **not** evidence of precision on real repositories. Charter success criteria 6 and 7 (a CONFIRMED finding on a real independent repo, and a real-world false positive root-caused and added as a permanent negative fixture) remain unmet. | **[FP risk]** |
| X-L3 | **Single-file analysis.** Every fixture is one self-contained file. Real repos spread contracts, bases, and proxies across directories and imports; multi-file resolution and per-commit `pragma`/solc-version switching via solc-select are not yet exercised by the history walker (`src/history.py` is empty). | **[FN risk]** |
