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

### RC-AST1 — Rule 3c false-positive from solc astId suffixes leaking into type-string equality

**Type: FALSE POSITIVE. Rule 3c. HIGH real-world exposure — any commit that
adds or removes a declaration anywhere in a changed .sol file can trigger this
on unrelated declarations. MEASURED on a real repository (Reserve, FP5).**

Rule 3c fires when the raw slot layout is unchanged. `rule3c.py:199` compares
storage entries with `same_type = entry_b["type"] == entry_a["type"]`, and
`entry["type"]` is the string solc emits in `--combined-json storage-layout`
— strings that embed solc's numeric astId as a suffix:
`t_contract(IMain)<astId>`, `t_struct(AddressSet)<astId>_storage`,
`t_mapping(t_contract(IERC20)<astId>,t_contract(IAsset)<astId>)`. AstIds
renumber whenever any declaration is added or removed anywhere in the file,
which is orthogonal to whether the referenced type's identity or the compared
variable's slot layout actually changed. A pure function-body refactor that
adds a few lines is enough to shift every subsequent declaration's astId and
make every affected type string compare unequal.

**Evidence, measured.** PHASE 5 walker run against `reserve-protocol/protocol`,
pair `cef2f655..7f65c030` (FP5, `contracts/p1/AssetRegistry.sol`), post-STEP-5
HEAD. Raw `solc --combined-json storage-layout` output for both sides,
13 entries each, all slots / offsets / labels / gap sizes identical:

```
[0]  _initialized     slot=0   offset=0  type=t_uint8
[1]  _initializing    slot=0   offset=1  type=t_bool
[2]  __gap            slot=1   offset=0  type=t_array(t_uint256)50_storage
[3]  __gap            slot=51  offset=0  type=t_array(t_uint256)50_storage
[4]  __gap            slot=101 offset=0  type=t_array(t_uint256)50_storage
[5]  main             slot=151 offset=0  type=t_contract(IMain)<astId>
[6]  __gap            slot=152 offset=0  type=t_array(t_uint256)49_storage
[7]  basketHandler    slot=201 offset=0  type=t_contract(IBasketHandler)<astId>
[8]  backingManager   slot=202 offset=0  type=t_contract(IBackingManager)<astId>
[9]  _erc20s          slot=203 offset=0  type=t_struct(AddressSet)<astId>_storage
[10] assets           slot=205 offset=0  type=t_mapping(t_contract(IERC20)<astId>,t_contract(IAsset)<astId>)
[11] lastRefresh      slot=206 offset=0  type=t_uint48
[12] __gap            slot=207 offset=0  type=t_array(t_uint256)46_storage
```

The only differences between prev and cur (5 entries): astId suffixes shift.
Same referenced interfaces / struct / mapping shape — the numeric label is
what changed, not the type. Rule 3c reports a fire despite zero real layout
change (source diff is function-body refactor: hoist `asset.erc20()` into a
local `erc20`, pass it as a new second arg to `_register` /
`_registerIgnoringCollisions`; adds ~11 lines to the file which shifts every
subsequent declaration's astId).

**Related but distinct from the existing astId-instability handling for
entry keying.** `_storage.py:172-174` (`keyed_entries` docstring) already
records the same principle:

> Positional keying is required because reserved gaps all share the label
> `__gap` across an inheritance chain, and astIds are not stable between
> commits (adding a declaration renumbers them), so astId cannot be used to
> match a variable to its counterpart.

That fix — positional (label, nth-occurrence) keys instead of astId keys —
covers ENTRY IDENTITY across commits. It does not extend to TYPE-STRING
COMPARISON at `rule3c.py:199`, which still leans on the raw solc string.
Same root cause (astIds shift on unrelated source edits), same class of
fix (canonicalize astIds out before comparing), different consumer never
updated to the same principle.

**Scope, honestly.**
- **Not Reserve-specific.** Any repository whose commits add or remove a
  declaration anywhere in a changed .sol file will renumber astIds on every
  subsequent declaration in that file. Real commits routinely change
  declaration counts; the class of commits that do NOT (pure whitespace,
  pure comment, or pure body-of-a-single-function edits with no local-var
  changes) is narrow.
- **Real-world exposure: HIGH.** Measured on the first real-repo trajectory
  slice ever run (Reserve, FP5). Almost every non-trivial commit is a
  candidate trigger.
- **Confined to Rule 3c** — Rules 1/2a/2b/3a/3b/4/5/6 do not consume solc's
  storage-layout type strings and are not affected.
- Does not depend on OZ 4 vs OZ 5 mode; the astId-in-type-string wire format
  is a solc-side detail present in both.

**Fix direction (not implemented — pending its own step and a fixture-first
prerequisite).** Two viable canonicalizations, either sufficient:

- **String-level:** regex-strip trailing `<digits>` inside `t_contract(...)`,
  `t_struct(...)`, `t_mapping(...)`, `t_array(...)`, and any nested position
  before comparing. Preserves the type CATEGORY and referenced NAME, drops
  the unstable numeric label. Cheapest, closest to the existing code shape.
- **Structural:** for each compared entry, resolve the type string back to
  its Slither declaration and compare `canonical_name` (which is stable
  across compilations by DESIGN-L1's own logic). Stronger, aligns with how
  Rules 2b/4/5 already handle cross-commit type identity, but a larger
  refactor.

Either fix must be **locked by a dedicated fixture** — a paired negative
(same-shape declarations, an unrelated declaration added or removed
elsewhere in the file so astIds shift, EXPECTED quiet) AND a paired
positive (a genuine type CHANGE, e.g. `IMain` → `IERC20`, that must still
fire after the fix). Fixture is a prerequisite: without both cases the fix
could pass by silencing the whole shape and hide real type-change
regressions. Tracked in TODO.md.

**RESOLVED 2026-08-15.** Implemented as the string-level canonicalisation:
`canonical_type()` in `_storage.py`, applied at both of `rule3c.py`'s
comparison sites (the OZ 4 entry loop and `_namespaced_collision`).
`slot_span` and the `types` map keep the RAW string, because the layout
JSON's `types` dict is keyed by it.

Locked by `fixtures-r3c-ast1/` (3 cases, 1.00/1.00):
- `N3c-ast1-01` — contract-typed state, unrelated interface added ahead of it
  so astIds shift, storage otherwise identical. Fires before the fix, quiet
  after.
- `P3c-ast1-01` — same shape, but `registry` genuinely changes identity
  `IRegistry` → `IOracle`. Fires before AND after: the strip removes the
  numeric label, never the type NAME.
- `P3c-ast1-02` — **over-strip guard.** An accessed fixed array grows
  `uint256[10]` → `uint256[20]` as the last storage variable, so the ONLY
  signal is `t_array(t_uint256)10_storage` → `...20_storage`, where the
  digits are the array LENGTH. A naive "strip all trailing digits" fix
  collapses these to equal and goes silent on a real storage-extent change.
  This is why the regex targets `t_contract` / `t_struct` / `t_enum` /
  `t_userDefinedValueType` identifiers only.

**Why the frozen 3c sets never caught it** — the same structural masking that
hid DESIGN-L2 behind single-file fixtures. Every pre-existing 3c fixture
declares only `uint256`/`address` state, whose layout type strings
(`t_uint256`, `t_address`) carry no astId at all; the only digits anywhere in
the frozen set are array lengths. No fixture had a contract-, struct-, or
enum-typed state variable, so no fixture could express the bug.

**Live confirmation.** Reserve pair `cef2f655..7f65c030` (FP5), which fired
Rule 3c before the fix, is quiet after it — all 9 rules quiet, zero errors.
Independently re-derived from the retained walker artifacts: `.walker-out.json`
(pre-fix) records `3c FIRED  cef2f655..7f65c030  contracts/p1/AssetRegistry.sol`,
and `.walker-out-v3.json` (post-fix, same four pairs) records no Rule 3c fire at
all. That also settles a question WALK-L2 raised: Rule 3c's solc invocation was
working on this file, so RC-AST1 is provably independent of any
compiler-invocation problem.

**RETROACTIVE FIXTURE VALIDATION (2026-08-15).** The project's standing rule is
fixtures before code, and for this finding that ordering could NOT be proven
after the fact: the fixture and the fix arrived in one uncommitted working tree
with no intermediate commits, and the code files' mtimes were later overwritten.
Rather than assert compliance, the discriminating property was measured
directly — `fixtures-r3c-ast1` was run against the **pre-fix** `_storage.py` and
`rule3c.py` (restored from `fa0d214`) in a throwaway `git worktree`:

```
PRE-FIX                                    POST-FIX (HEAD)
  [3c] N3c-ast1-01  got=FIRE  ** WRONG **    [3c] N3c-ast1-01  got=quiet  OK
  [3c] P3c-ast1-01  got=FIRE  OK             [3c] P3c-ast1-01  got=FIRE   OK
  [3c] P3c-ast1-02  got=FIRE  OK             [3c] P3c-ast1-02  got=FIRE   OK
  3c  TP 2  FP 1  precision 0.67  FAIL       3c  TP 2  FP 0  precision 1.00  OK
```

This establishes what actually matters about a locking fixture, which is not its
timestamp: the negative reproduces a genuine pre-existing false positive on the
unfixed code, and both positives fire on BOTH sides, so the fix cannot have
passed by blanket-silencing the contract-typed-state shape. Strict temporal
ordering remains unprovable and is recorded as unprovable.

---

## Rule 1 — SC01 access control

### 1-N1 — Rule 1 needs NO OZ 5-specific handling (design note, not a limitation)

Unlike Rules 3b and 3c (see [3x-L3](#3x-l3--rules-3b-and-3c-cannot-fire-at-all-on-openzeppelin-5x)), Rule 1 required **zero OZ 5-specific code**. There is no OZ 4/OZ 5 branch, no namespace-pointer handling, no per-version switch — the OZ 4 detection resolves OZ 5 `onlyOwner`/`onlyRole` unchanged.

**Reason.** Rule 1 detects a lost access constraint through `constrains_msg_sender`, which is data-dependency based and only needs the **`msg.sender` side** of an access check — and OZ 5 never namespaces that side. OZ 5's `_checkOwner` is `if (owner() != _msgSender()) revert …`: `owner()` reads `_owner` from the ERC-7201 `OwnableStorage` namespace, but `_msgSender()` is plain `msg.sender`, so the guard node is data-dependent on `msg.sender` regardless of where `owner()` reads from. `onlyRole` behaves the same way — `_checkRole(role, _msgSender())`.

**Why 3b differed.** Rule 3b had to identify **which** namespaced slot the one-shot init flag (`_initialized` / `_initializing`) occupied, in order to prove the modifier was a real init guard — that read *is* the namespaced value, which is why 3b needed the ERC-7201 pointer machinery. Rule 1 never inspects the owner/role storage read, only the `msg.sender` comparison, so the OZ 5 indirection is irrelevant to it.

**Verified, not asserted.** `fixtures-r1-oz5` (OZ 5.7.0: `OwnableUpgradeable`, `AccessControlUpgradeable`, UUPS v5, ERC-7201) scores Rule 1 **1.00/1.00** with no rule change — 2 positives fire, both negatives stay quiet (N1-oz5-02's `_authorizeUpgrade` regression is Rule 3a's, declared via `also_fires`), while OZ 4 (`fixtures-r1`) and all Rule 3 sets remain 1.00/1.00.

---

## Rule 2b — SC08 reentrancy, CEI ordering

### RC-ROLE — Rule 2b admin-gate discriminator misses role-based access control

**Type: FALSE POSITIVE. Rule 2b. MEASURED on a real repository (Reserve, FP6,
commit `92ff272f`). FIXED 2026-08-15; locked by `fixtures-r2b-role/`.**

Phase-3 STEP 4 suppressed a Rule 2b over-fire on admin-gated functions via
`_admin_gated_by_state_addr`, which recognised exactly one shape: a
`require`/`if` comparing `msg.sender` against an address held in a state
variable (`msg.sender == owner`). Real governance code very often expresses the
same gate as an **authority call** instead — `acl.hasRole(ROLE, msg.sender)`,
`authority.canCall(msg.sender, ...)` — which that discriminator cannot see. Such
a function is admin-only in fact and still fires.

**Evidence, measured.** Reserve `Upgrade4_2_0.castSpell`, pair
`6481e75d..92ff272f`, under post-STEP-5 HEAD:

```
castSpell(IRToken,Governance,address[])
  _admin_gated_by_state_addr  -> False        <- STEP-4 discriminator blind
  own_guard_state_reads       : [NEW_VERSION_HASH, PRIOR_VERSION_HASH, assets, supported]
  writes_after_calls          : [newGovs, supported]
  guard actually present      : require(main.hasRole(MAIN_OWNER_ROLE, msg.sender) && ...)
```

`moved = {supported}` intersects `own_guard_state_reads`, and the admin
suppression does not apply, so Rule 2b fires.

**Two things this exposed beyond the missing shape.**

1. **The fire is driven by variable CONSOLIDATION, not by a write moving.** At
   N-1 `supported` is only READ by the function while a sibling `cast` mapping
   carries the write; at N `cast` is deleted and `supported` absorbs its write.
   Rule 2b's `moved` set is "written-after-a-call at N, not at N-1", which this
   satisfies without any write physically crossing a call. Note also that the
   role check is *itself* an external call, so every subsequent write is
   "after a call" on both sides — a fixture that omits the consolidation cannot
   reproduce the fire at all.

2. **The STEP-4 fixture was infidelitous, and that is why a green gate shipped
   an unfixed case.** `fixtures-multi/R2B-SPELL-N` reproduced castSpell's SHAPE
   (admin-only, guard-read variable, write across a call) using the EQUALITY
   gate form and a physically-moved write. It therefore passed under a fix that
   never addressed the real function. A fixture that mirrors a real case must
   mirror the mechanism the rule keys on, not merely the situation.

**Fix (implemented).** `_admin_gated` in `rule2b.py` now accepts either form:
identity equality as before, or a guard consuming the bool verdict of a call
that takes `msg.sender` as an argument.

**The bool-return restriction is load-bearing, and was measured, not assumed.**
`balanceOf(msg.sender)` is also "a call taking msg.sender whose result reaches a
guard". Accepting it would classify an ordinary balance check as access control
and silence genuine re-entrancy:

| guard | without bool check | with bool check | required |
|---|---|---|---|
| `token.balanceOf(msg.sender) >= amt` → uint256 | True (wrong) | False | False |
| `acl.hasRole(ROLE, msg.sender)` → bool | True | True | True |

An authority predicate answers *whether this caller may act*; a value lookup
constrains *how much*. `fixtures-r2b-role/P2b-role-01` locks the distinction —
an anyone-callable `redeem()` whose cap guard reads a variable consolidated
across the hook call, which must keep firing.

**Scope.** Any repo whose access control is role-based rather than
single-owner-address — OpenZeppelin `AccessControl`, ds-auth, timelock/governor
patterns — i.e. most non-trivial protocols. Confined to Rule 2b's
direct-reentrancy verdict; the read-only (2.10) path was never gated on this.

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

## Rule 6 — SC05 input validation

Rule 6 fires when a parameter-dependent guard (require / revert / custom-error
whose condition is data-dependent on a function **parameter**, not on
`msg.sender`) is present at N-1 and absent at N on a function that still changes
state. It ships with the following coverage, all validated at precision 1.00 /
recall 1.00 on `fixtures-r6/` (9 cases):

**Implemented and proven by fixture:**

- **6.1** check moved into a modifier on the same function (N6-01) — the
  parameter stays guarded because the reachable set includes modifiers.
- **6.2** check enforced downstream in an always-called function, on the same
  value, before any state change (N6-02) — contract-level data dependency
  propagates the parameter through the internal call.
- **6.3** the parameter was removed entirely (N6-03) — the function's `full_name`
  changes, so the N-1 function has no N match and is never compared.
- **6.5** check replaced by an equivalent custom error, same condition (N6-04) —
  compared semantically (a conditional guard node with the same parameter
  dependency), not by text.
- **6.7** test/mock path (N6-05) — segment-based `source_path` match.
- **Rule 1 boundary** (N6-06) — a guard whose condition depends on `msg.sender`
  is discarded from the parameter-guard set, so its removal never fires Rule 6;
  Rule 1 owns it (declared via `also_fires`). The highest-severity sub-case
  (slippage / `minAmountOut` removal, P6-02) surfaces as an ordinary
  parameter-guard loss and fires CONFIRMED with no special-casing.

**Deferred — untested, NOT implemented:**

| # | Exclusion | Direction |
|---|---|---|
| 6-L1 | **6.4 — a type change makes the check redundant** (e.g. a parameter narrowed `uint256` → `uint8` that bounds a range). Not implemented and no fixture exercises it, so a guard removed alongside such a narrowing would currently fire as a **false positive**. Deliberately deferred: shipping an untested exclusion trades an FP for a silent FN. Build the fixture first, then the logic. Tracked in TODO.md. | **[FP risk]** |
| 6-L2 | **6.6 — enforced by the type system or a validated struct at the call boundary.** Same posture as 6-L1: not implemented, no fixture, fixture-first before logic. Tracked in TODO.md. | **[FP risk]** |

### RC-OZ5-R6 — Rule 6 false-positives on OZ5 assembly-assigned namespace pointers

**Type: FALSE POSITIVE. Rule 6. HIGH real-world exposure — 2026 OZ 5.x is
default. LATENT (surfaced by fixture, not yet by a real repo).**

Rule 6 fires when a removed guard's condition reads an ERC-7201 namespace
storage pointer (`$`, assigned via `assembly { $.slot := ... }`) even when the
condition is provably parameter-independent. Slither's
`is_dependent(local, param, contract)` returns spurious True for a local
storage pointer assigned inside an inline-assembly block, and Rule 6's
`_param_guarded_names` accepts that as evidence the guard depended on the
parameter. Removing a parameter-INDEPENDENT rate-limit guard
(`block.timestamp` + `$.namespacedStateMember`) then reads as a param-
validation regression the commit never introduced.

**Evidence, measured.** On `fixtures-ext/negative/N3b-ratelimit-oz5`:

```
--- before.sol: RateLimited.rotateGuardian(address) ---
  guarded params (Rule 6 thinks): {'newGuardian'}
    node EXPRESSION: require(bool,string)(block.timestamp >= $.lastRotation + ROTATION_COOLDOWN, ...)
      hits: [('$', 'LocalVariable')]
--- after.sol ---
  guarded params (Rule 6 thinks): set()
```

The require reads `block.timestamp` (`SolidityVariable`) and `$.lastRotation`
(a struct member reached through a storage pointer). `newGuardian` never
appears in the guard's read set. Yet
`is_dependent($, newGuardian, RateLimited)` is True, so Rule 6 counts
`newGuardian` as guarded at N-1 and unguarded at N -> FIRE. The OZ 4 sibling
`fixtures-ext/negative/N3b-ratelimit-oz4` — same rate-limit shape, but
`lastRotation` is a plain declared state variable, not routed through an
assembly-assigned local — stays quiet. The Rule 6 error is confined to the
OZ 5 storage-pointer indirection; the rule's OZ 4 behaviour is unaffected.

**Not a documented deferral.** No entry in this file or in TODO.md previously
recorded this class. `fixtures-ext/negative/N3b-ratelimit-oz5/case.json`
declares neither `also_fires` nor `known_unsupported` for Rule 6; the fixture
was built to test Rule 3b's rate-limit discriminator, and its silence on Rule 6
was the intended, currently-broken behaviour.

**Scope, honestly.**
- OZ 5-only, and only on functions whose guard condition dereferences an
  assembly-assigned namespace pointer local. Any OZ 5 project using ERC-7201
  namespaced storage in its own contracts (the default pattern in OZ 5.x) is
  exposed.
- LATENT: no real-repo hit has been measured. Monetrix ran under OZ 4 mode
  (see 3x-L2 / 3c-oz5-realworld-gap); the Reserve trajectory slice did not
  touch this pattern. But 2026 OZ 5.x is default, and rate-limit guards on
  namespaced state are a common shape, so this WILL fire on a real OZ 5 repo
  as soon as one is analysed.

**Fix direction (not implemented — Phase-3 STEP 5, after Reserve fixes).**
The rule must verify a REAL data path from the guard's condition to the
parameter, not accept Slither's over-approximation on assembly-assigned
locals. The simplest tightening: require the parameter (or a direct-storage
read of a state variable the parameter was written into) to appear in the
guard's transitive read set BEFORE the `is_dependent` fallback runs; treat a
sole hit through an assembly-assigned local as inconclusive. A dedicated
`fixtures-r6-oz5/` set is a prerequisite: a negative whose removed guard is
verifiably parameter-independent through a namespace pointer (this current
shape) AND a paired positive whose guard genuinely reads the parameter
through the same pointer (so the fix cannot pass by blanket-silencing the
namespace-pointer shape). `N3b-ratelimit-oz5` must not double as that
fixture — it exists to test Rule 3b, not to lock a Rule 6 exclusion.

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

**RESOLVED.** Rate-limit negative fixtures were built (`fixtures-ext/negative/`,
both `N3b-ratelimit-oz4` and `N3b-ratelimit-oz5`, each confirmed to fire on the
pre-fix rule and go quiet after), and a discriminator was added to
`is_oneshot_init_guard` / `has_init_guard`: a gate-on-and-write-same-var counts
as an init guard only if **at least one gated-and-written variable is written to
a compile-time constant somewhere** in the function. Verified against the OZ IR:
`initializer` writes `_initialized = 1` (constant) and `reinitializer` writes
`_initializing = true/false` (constant) even though its `_initialized = version`
write is not — so both remain init guards — while a rate-limit member written
only from `block.timestamp` does not. `MonetrixVault.keeperBridge` now classifies
as not-an-init-guard, and all three fixture sets hold at precision 1.00.

**Scope consequence, decided deliberately.** The discriminator also reclassifies
the **set-once-address** pattern:

```solidity
if (vault != address(0)) revert VaultAlreadySet();   // gate on vault
vault = _vault;                                        // written from an argument
```

Because `vault` is written from an argument rather than a compile-time constant,
this now reads as **not** a Rule 3b init guard (it dropped `USDM.setVault`,
`sUSDM.setVault`, `sUSDM.setEscrow` from the Monetrix init-guarded list, leaving
only the six real `.initialize` functions). This is intended, not a regression:

- A set-once setter is **configuration**, not proxy initialization. Sub-rule 3b
  is specifically SC10 "initializer re-callable" (the OZ `initializer` modifier /
  `_disableInitializers()`). Reporting removal of a `VaultAlreadySet`-style guard
  under 3b would be a **mislabeled SC10 finding** — the same defect class as the
  `keeperBridge` symptom this fix exists to remove.
- Its correct home is **Rule 6 (input validation)**, which is not built yet.
- No fixture treats set-once-address as a 3b positive, so nothing regressed; the
  three fixture sets remain 1.00/1.00.

The conceptual definition (monotonic-close vs reopen) would also cover
set-once-address, since once `vault` is nonzero the guard reverts forever. The
constant-write test is a deliberately narrower operational proxy that keeps 3b
scoped to genuine proxy-initialization machinery. Retaining set-once-address
under a "monotonic-close" discriminator was considered and deferred to Rule 6.

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

## Trajectory mode — walking a real repository's commit history

### WALK-L1 — path-keyed caches silently replay the previous commit's analysis

**Type: SILENT WRONG RESULT (not a false positive — a fabricated verdict of
either polarity). Trajectory mode / `walker.py`. MEASURED and FIXED 2026-08-15.
This one produced a documented false conclusion before it was caught.**

`_shared.parse` and `_storage.storage_layouts` both memoize on the file's
absolute path alone. That contract is sound for the scorer, where a fixture
path's content never changes within a process. It is **unsound for a trajectory
walker**, which deliberately reuses two scratch worktree paths across every pair
(that reuse is what lets the dependency-install cache pay off) — so one path
holds different commits' content over a run. The second and later pairs to touch
a given file receive the first pair's analysis.

**How it was caught, and what it cost.** The first PHASE 5 run over four Reserve
pairs reported FP4 and FP6 quiet. Both were replays:

```
file                              analyzed by pairs
contracts/spells/4_2_0.sol        FP1/FP2, FP4, FP6   <- 3 pairs, one real analysis
contracts/facade/facets/ActFacet.sol  FP1/FP2, FP4    <- 2 pairs
contracts/p1/AssetRegistry.sol    FP5                 <- unique, uncontaminated
```

On the strength of that run, LIMITATIONS.md and TODO.md were edited to record
RC-5 as "RESOLVED — empirically confirmed mislabel". **That conclusion was
false and had to be retracted** (see the retraction note in the DESIGN-L2 §).
Re-running with cache invalidation showed FP4 and FP6 both still firing; FP6's
real cause turned out to be [RC-ROLE](#rc-role--rule-2b-admin-gate-discriminator-misses-role-based-access-control).
FP5 was the only originally-"confirmed" result that survived, because
`AssetRegistry.sol` happened to be unique to its pair.

**Fix (implemented).** `reset_caches()` added to both `_shared` and `_storage`,
with the cache contract now stated explicitly in `parse`'s and
`storage_layouts`' docstrings; `walker.py` calls both immediately after every
checkout. The reset is cheap — the next `parse` simply recompiles — and the
install cache (keyed on the resolved dependency set, not on a path) is
unaffected, so the amortisation that motivated path reuse is preserved.

**The generalisable lesson.** Every earlier finding in this file concerns a
detection rule being wrong. This one concerns the *instrument* being wrong, and
it is more dangerous: a bad rule produces a finding a human can inspect, while a
bad instrument produces a confident silence that reads exactly like success. The
project's own discipline — fixtures first, measure before concluding — has to
extend to the measuring tools themselves. A walker result is only evidence once
the walker has been shown to distinguish the commits it claims to compare.

---

### WALK-L2 — Rule 3c's solc invocation resolves paths against the WRONG ROOT

**Type: LATENT correctness hazard in trajectory mode. NOT DEMONSTRATED — no run
in this project has ever triggered it. Hardened in PHASE 6.**

> **STATUS CORRECTION (recorded, not silently rewritten).** The first version of
> this section was headed "ran solc in the WRONG DIRECTORY", typed as "TOTAL
> COVERAGE LOSS … was 42/42 errors on the Reserve window", and closed as FIXED
> on a before/after of "42/42 errors -> 0 errors". **All three of those claims
> are retracted.** The 42/42 figure was inherited from a pre-existing TODO.md
> entry describing a different, larger run (HIST-L1's 29-pair window) and was
> paired with a 4-pair, 8-file PHASE 6 measurement — two different workloads.
> The retained analysis below is a code reading, not a reproduction.

`_storage._run_layout` invoked solc with `cwd=ROOT` and `--allow-paths .`, where
`ROOT` is *Chainwatch's own* repository root rather than the checkout that owns
the file being compiled. For the fixture scorer that is correct, since fixtures
live inside this repo.

**Why it never fired.** The scratch worktrees live at
`<chainwatch>/.walker-worktrees/…` — *inside* `ROOT`. So `--allow-paths ROOT`
covered them, `src.is_relative_to(ROOT)` held, and the relative path solc
received resolved correctly. The defect is real in the code but unreachable in
every configuration this project has actually run. It becomes reachable the
moment a worktree, a clone, or a dependency tree lives outside the Chainwatch
root — which is a supported thing to ask for (`--worktrees`), and is why the
hardening was kept rather than reverted.

**What the artifacts actually show.** `.walker-out.json` / `-v2` / `-v3` (the
4-pair Reserve window) record **6 errored comparisons for every one of the nine
rules** — 3 Curve\* files x 2 pairs. Identical across rules means the cause is
shared, not Rule 3c-specific: it is the repo-root-relative import failure
(HIST-L1 residual, fixed separately in `derive_remaps`). On that same window
Rule 3c completed its other 12 comparisons and fired correctly on FP5, which is
direct evidence that its solc invocation was working.

**The misdiagnosis is still the most useful part of this entry.** The failure
was originally recorded as "`_storage.py` does not honor the walker's
`SOLC_VERSION`, falls back to ambient 0.7.6". `SOLC_VERSION` *is* inherited
(`env = dict(os.environ)` copies it), so that mechanism was wrong — but the
replacement mechanism proposed here was then asserted with the same confidence
and the same absence of a reproduction. Two successive plausible stories, neither
measured. The generalisable lesson stands and now cuts both ways:

- **When a fallback path exists, the error you are shown is the fallback's
  error, not the original one.** A retry loop that swallows the first failure is
  a diagnostic hazard even when it is a correctness feature.
- **A root cause is not established until the failing workload is re-run.**
  Replacing one unreproduced explanation with another is not progress.

**Hardening applied (not a fix for an observed failure).** `_root_and_remaps(src)`
resolves which registered checkout owns a file; solc then runs in that checkout
with `--allow-paths <that root>`. Verified non-regressive: all 14 frozen sets
produce identical per-rule TP/FP/FN afterwards, and a live 4-pair Reserve walk
gives 8/8 comparisons with 0 rule errors — an improvement attributable to the
`derive_remaps` self-mapping fix, since that is what those 6 errors were.

**To close this properly**, re-run the workload the 42/42 figure came from and
capture Rule 3c's per-comparison error text; and add a case that puts a worktree
OUTSIDE the Chainwatch root, which is the configuration under which this defect
would actually bite. Tracked in TODO.md.

---

### WALK-L3 — one global remap list cannot describe two checkouts

**Type: SILENT MIS-COMPILATION. Latent (no verdict is known to have changed).
FIXED (PHASE 6).**

A trajectory pair spans two working trees — the N-1 checkout and the N checkout —
and the survival check adds a third at HEAD. `_shared.REMAPS` and
`_storage.REMAPPINGS` are single module-level lists, so whichever side was
applied last described *both* sides. For adjacent commits the dependency trees
are almost always identical (this is the same observation that makes
`EnvSpec.key` collapse 30 installs into one), which is exactly why this was
invisible: it only bites when a commit adds, removes, or bumps a package, and
then it silently compiles the N-1 file against N's dependencies.

**Fix.** `_shared.register_root(root, remaps)` binds a checkout directory to its
own commit's remappings; `remaps_for(path)` picks the longest matching root, and
`_storage._root_and_remaps` does the same for the layout extractor. The global
lists remain as the fallback, so the fixture scorer — which registers nothing —
behaves exactly as before. Verified: all 14 frozen sets produce byte-identical
per-rule TP/FP/FN counts after the change.

---

### WALK-L4 — the dependency cache's own junction is unreadable to older solc

**Type: TOTAL COVERAGE LOSS, silent, MEASURED AND REPRODUCED. Affects every
rule on any repository pinned to an older compiler. FIXED.**

`install()` materialises a cached dependency set by pointing
`<worktree>/node_modules` at `<cache>/<key>/node_modules` with an NTFS junction
(`_link_dir`) — the optimisation that collapses 30 commits' installs into one.
**solc's import read callback cannot traverse that junction on older
compilers.** Measured on solc 0.5.17:

```
$ solc "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/" ... contracts/NFT.sol
contracts/NFT.sol:3:1: Error: Source ".../node_modules/@openzeppelin/contracts/token/ERC721/ERC721Metadata.sol"
   not found: Unknown exception in read callback.

$ ls node_modules/@openzeppelin/contracts/token/ERC721/ | grep Metadata
ERC721Metadata.sol            <-- the file is right there

$ solc "@openzeppelin/contracts/=<the junction's TARGET>/" ... contracts/NFT.sol
{"contracts":{"contracts/NFT.sol:NFT":{}, ...              <-- identical sources, compiles
```

**Why this one is nasty.** The error says *"not found"* about a file that
exists, so it reads as a missing dependency or a botched install — i.e. it
impersonates HIST-L1, the failure mode this project already knows about and has
machinery for. Two full scan attempts were spent on wrong hypotheses (path
length, then drive) before the junction was checked. Both wrong hypotheses were
disproven by measurement, which is the only reason the real cause was reached:
a minimal copy of the SAME sources compiled fine at a short path on `C:`, then
at a short path on `B:`, which eliminated both.

**Fix.** `derive_remaps(absolute=True)` now emits `pkg_dir.resolve()` — the
junction's target — so solc is handed a real directory. `_run_layout` widens
`--allow-paths` to include every remap target, because the resolved dependency
path legitimately lies outside the checkout. Effect on the 88mph measurement:
**8 of 9 rules went from erroring to producing verdicts.**

**Scope.** Windows-specific in this form (junction), but the same shape exists
wherever the dependency tree is reached through a link. Not observed on
solc 0.8.x, which traverses the junction without complaint — which is exactly
why every previous run (all 0.8.x targets) missed it, and why "it works on our
test repo" was never evidence.

---

### HIST-L1 — historical COMPILATION, not rule logic, is the coverage limit

**Type: SILENT COVERAGE LOSS. HIGH priority. Affects every rule in trajectory
mode. Same class as 3x-L1 and 3x-L2: the output of a skipped analysis is
indistinguishable from the output of a clean one.**

> **STATUS: MITIGATED AND MEASURED.** Per-commit environment reconstruction took
> reserve-protocol/protocol's failing window from **0/29 to 28/29 analyzable
> pairs**. Residual causes are listed below and are reported per pair, never
> swallowed. The coverage barrier is broken; see the caveat at the end of this
> entry — the same run exposed a *precision* defect (R5-L1), so "analyzable" now
> outruns "trustworthy", and the two must not be conflated.

**Priority rationale:** trajectory mode is the tool's headline use — point it at
a repo, get its regression history. This limitation means that mode can report a
confident, wrong answer, and nothing in the output reveals it.

**Status of the walker itself.** `src/history.py` was **empty** (0 bytes, created
by the Phase 1 skeleton commit `0d47141`) through the first trajectory test,
which is why that test did not exercise it — pairs were extracted by an ad-hoc
`git diff --name-status` script, deliberately, so a history-walk bug could be
told apart from a rule bug. The walker and the reconstruction stage now exist in
`src/history.py`.

**What that test did establish.** Pair extraction is the easy half. Against a
full clone of `reserve-protocol/protocol` (5577 commits, OZ 4.9.6, upgradeable),
the last 30 commits touching `contracts/**/*.sol` yielded **29 consecutive pairs,
28 with at least one modified `.sol`, and 46 modified-file comparisons** — cleanly
and unambiguously, straight from git. Getting the pairs is not the problem.

**The problem: none of those 46 comparisons could be compiled.** Reproducing an
old commit's build requires **that commit's environment**, not the current one.
Observed at the 30-commit window, in order of how immediately each one bites:

| Cause | Evidence from the run |
|---|---|
| **Compiler version not available** | All 46 modified files pin `pragma solidity 0.8.28;` — an *exact* pin, which no fallback can satisfy from another release. Installed: 0.7.6 / 0.8.9 / 0.8.20 / 0.8.22 / 0.8.27. Raw error: `Source file requires different compiler version (current compiler is 0.8.27+commit.40a35a09…)`. Across the wider tree the pragma range also includes `0.6.12`, `^0.6.0` and `>=0.6.0 <0.8.0`, so a full-history walk needs a far broader compiler set than any one window suggests. |
| **Dependency tree absent at that commit** | The clone has no `node_modules`. Every contract imports `@openzeppelin/…`, which resolves only against the dependency set *that commit* declared. |
| **Contracts do not compile in isolation** | Files import sibling project paths (`../interfaces/IRToken.sol`), so `git show <sha>:<path>` into a temp file can never compile. The walk must materialise the **whole tree** at each commit (`git worktree`/checkout), not the changed files. |
| **Layout, remappings and import paths drift** | The general form of the above: directory layout, remapping config and dependency versions all change over a repo's life, so a build recipe fixed at HEAD is wrong for most of history — and increasingly wrong the further back the walk goes. |

**Consequence — the part that matters.** A trajectory run can report **"0
detections"** not because the history is clean but because most pairs were never
compiled, and therefore never analysed. Silence from an uncompiled pair is
byte-identical to silence from a clean one.

**Therefore: a trajectory result MUST report analyzable-vs-skipped pair counts
alongside detections, with the reason for each skip. "0 detections" without a
coverage ratio is not a result and must never be quoted as one.** For the run
above the honest statement is *"0 of 29 pairs analyzable, 0 pairs analysed, no
precision evidence produced"* — **not** "0 detections across 29 pairs".

**The rules are not the bottleneck.** No rule failed, errored, or misfired on any
historical pair — because no historical pair reached a rule. Trajectory mode has
so far produced **no precision evidence at all, in either direction**. The
existing 0-false-positive evidence comes from a different setup entirely: the
Phase 5 Monetrix run, 20 real contracts compared self-against-self, all 9 rule
ids engaged, 0 detections and 0 candidates. That result stands on its own and is
not evidence about trajectory mode. What the trajectory test measured is that
**historical compilation** — not detection logic — is what gates real-repo
coverage, and it is the thing to fix first.

#### MEASURED MITIGATION — per-commit environment reconstruction

Implemented in `src/history.py`, measured on the identical 29-pair window that
previously yielded nothing:

| | before | after |
|---|---|---|
| **Analyzable pairs** | **0 / 29** | **28 / 29** |
| File comparisons compiled on both sides | 0 / 46 | **43 / 46** |
| Rule executions | 0 | **387** |
| Wall clock (whole window) | — | **13.0 min** |

The 29th pair is not a failure: it adds 7 files and modifies none, so no
comparable N-1 side exists. Of *comparable* pairs the ratio is **28/28**.

**How.** Check the commit out into a scratch worktree; detect the dependency
system declared at that commit; install it (cached); derive remappings and the
pinned compiler from the reconstructed tree; compile; hand the result to the
rules. crytic-compile already knew how to build the project — the missing piece
was only ever materialising the dependency set the commit declared. On the
Reserve window, the framework build also resolved the compiler pin by itself,
downloading **solc 0.8.28 (405 sources) and 0.6.12 (38 sources) in one build**,
which the previous one-`SOLC_VERSION`-per-case model structurally could not do.

**Caching — the thing that makes a walk affordable.** Keyed on the *resolved
dependency set*, never on the commit: `sha256(package.json, yarn.lock,
package-lock.json, pnpm-lock.yaml, foundry.toml, .gitmodules, remappings.txt,
solc_pin)[:16]`. Reserve's 30 commits carry exactly **one** distinct `yarn.lock`,
so the whole window cost **one** install (2m09s, 449 packages, 461 MiB, key
`586f75487c86a6e5`); every later commit was a directory-junction cache hit at
zero cost. The measured 13.0 min is therefore almost entirely Slither parse time,
not installation.

**Residual failing causes — this is the honest limit of "any repo".** Measured on
this window:

| Cause | Count | Note |
|---|---|---|
| `remapping` | **3 file comparisons** | Repo-root-relative imports (`contracts/interfaces/IAsset.sol`). Hardhat resolves these implicitly from the project root; bare solc does not. Fixable: emit `contracts/=<root>/contracts/` for top-level source dirs. |
| `no-modified-sol` | 1 pair | Not a failure — added files only, no comparable pair. |
| `dep-gone-from-registry` | 0 | Not exercised: this window is 2 months old. Expected to dominate on older history, where unpinned transitive deps get unpublished. |
| `solc-absent` | 0 | Handled by the framework build, which fetches its own compilers. |
| `needs-install-scripts` | 0 | — |
| `timeout` | 0 | — |

**"Any repo" means "most commits of most repos, transparently reported" — not
100%, and it must never be stated as 100%.** This window is the easy case: one
lockfile, one framework, no submodules, no registry decay. Older history, Foundry
eras, and yanked packages are untested. The reporting invariant above is what
makes the difference safe: every non-analyzed pair carries a cause.

**Safety posture (recorded, per CHARTER rule 5).**
- Dependency installs run with **lifecycle scripts disabled** — `npm ci
  --ignore-scripts` / `npm install --ignore-scripts` for npm, `yarn install
  --immutable --mode=skip-build` for yarn (the command actually used on Reserve,
  which is a yarn project), `pnpm install --ignore-scripts` for pnpm. Installing
  a historical dependency set means fetching arbitrary third-party code;
  executing its postinstall hooks is a remote-code-execution surface that a
  static analyser does not need. Native modules consequently do not build; if a
  project genuinely requires scripts, `install()` records `NEEDS_SCRIPTS` and
  stops rather than silently enabling them — a per-project human decision.
- **Read-only on the target.** Only the repo's history is read. Nothing is
  committed, pushed, or written to a tracked path. The one write is `git
  worktree` bookkeeping inside the target's `.git`; an archive-based mode avoids
  even that where submodules are not needed.
- Worktrees, installs and build artifacts live in an **isolated scratch
  directory** outside both the target repo and this one.

**CAVEAT — coverage is solved, precision is now the open problem.** The same run
produced **11 detections, of which 10 are proven false positives** from a genuine
Rule 5 defect (see **R5-L1**), and 1 (Rule 2b) remains unverified. Rule 3c could
not run at all across the window (42 errors — its `storage_layouts` helper builds
paths relative to this repo's root, so it cannot address an external worktree).
Raising the analyzable ratio raised the *false-positive* count from zero to ten,
because pairs that never compiled also never produced a wrong answer. A
trajectory report must therefore carry BOTH ratios: coverage, and a verified
precision figure. Coverage alone is not trustworthiness.

### R5-L1 — Rule 5's call key is not unique per call site

**Type: FALSE POSITIVE, confirmed on real code. Rule 5.** Found by the first
env-reconstructed trajectory run; no fixture exercises the shape.

`_call_records` keys a call as `(kind, destination, method)`. That key is stable
across commits, which is what DESIGN-L1 demands — but it is **not injective
within a single commit**. When one function calls the same method on the same
destination more than once and at least one of those sites sits inside a
`try/catch`, `before_checked` (a dict on that key) retains only the try/catch
record. Any unchecked after-record with the same key then matches it, `in_try` is
True, and the rule reports "try/catch removed" **on code that did not change**.

Proven on `reserve-protocol/protocol` at `5ad5ee8b→76ec1234`. The rule fired in
`AllowanceLib.safeApproveFallbackToMax`, inside `contracts/libraries/Allowance.sol`
— **a file unchanged in that commit** — whose before and after record sets are
byte-identical. The source is the standard approve-reset idiom:

```solidity
token.approve(spender, 0);                                 // not in try
try token.approve(spender, value) { ... } catch {}         // in try -> checked
if (!success) { token.approve(spender, type(uint256).max); // not in try
```

All three collapse to one key, so the rule fires on every pair whose changed file
transitively imports that library. Same signature confirmed in two further cases,
both in genuinely changed files: `AssetRegistryP1.swapRegistered` (`erc20`) and
`ReadFacet.basketBreakdown` (`main`).

**Second-order finding, same run:** the fire above is attributed to
`contracts/p1/BackingManager.sol`, the changed file, but lives in an unchanged
library. Compiling a changed file pulls its whole import closure and the rules
iterate every contract in the compilation, so a finding can be **attributed to
the wrong file and commit**. Any trajectory finding must be filtered to
declarations in the changed file, or reported against the file that actually
contains it.

**Fix order:** fixture first — a function with two same-method calls on one
destination, one inside a `try/catch`, unchanged across commits, which must stay
quiet — then make the key injective per call site (e.g. include the node id or
source offset in the within-commit map while keeping the cross-commit key
stable). Tracked in TODO.md.

### AST-MODE — measured: AST-only execution is real, but it is NOT a HIST-L1 mitigation

**Type: DESIGN MEASUREMENT. Not a defect.** Recorded because the result
contradicts the assumption that motivated it, and because a future reader will
otherwise re-derive the wrong answer.

**The mechanism (found by reading the installed source, not assumed).**
`crytic_compile/platform/solc_standard_json.py:122` builds a solc standard-json
input whose `settings.outputSelection` defaults to `["abi", "metadata",
"devdoc", "userdoc", "evm.bytecode", "evm.deployedBytecode"]` plus `"": ["ast"]`.
Overriding that key asks solc for the AST and nothing else:

```python
sj = SolcStandardJson()
sj.add_source_file(path)
for r in remaps:
    sj.add_remapping(r)
sj._json["settings"]["outputSelection"] = {"*": {"*": [], "": ["ast"]}}
Slither(CryticCompile(sj))
```

This is the **only** reduced-build lever these versions expose. solc's
`--stop-after parsing` is unreachable: `grep -rn "stop-after\|stop_after"` over
slither 0.11.5 and crytic-compile 0.3.11 returns nothing. The plain `solc`
platform hardcodes `--combined-json abi,ast,bin,bin-runtime,srcmap,…`
(`_build_options`, solc.py:417) with no AST-only toggle. Verified the override
actually skips code generation: with it, `contracts_with_runtime_bytecode=0` and
`ast_present=1`; without it, `contracts_with_runtime_bytecode=2`.

**Measured result — 69 fixture cases × 9 rule ids = 621 verdict comparisons**,
across every frozen set (`fixtures`, `r1`, `r2`, `r2b`, `r4`, `r5`, `r6`, `oz5`,
`r1-oz5`), each rule's `parse` swapped at runtime and restored, no rule modified:

| rule | AST-only parse | AST-only + storage-layout denied | capability | reason |
|---|---|---|---|---|
| 1 SC01 | IDENTICAL 69/69 | IDENTICAL | AST-only-capable | CFG + data dependency are lowered from the AST |
| 2a SC08 | IDENTICAL 69/69 | IDENTICAL | **AST-only-capable** | SlithIR comes from the AST, not from bytecode |
| 2b SC08 | IDENTICAL 69/69 | IDENTICAL | **AST-only-capable** | same — CFG ordering is AST-derived |
| 3a SC10 | IDENTICAL 69/69 | IDENTICAL | **AST-only-capable** | inheritance-resolved modifiers are resolved by Slither from the AST |
| 3b SC10 | IDENTICAL 69/69 | IDENTICAL | **AST-only-capable** | same |
| 3c SC10 | IDENTICAL 69/69 | **DIFFERS 63/69** | **full-compile-only** | needs a *second, non-AST* artifact: `solc --combined-json storage-layout`. Denying it turns 63 cases into `RuntimeError`, including the true positive `fixtures/P3c-01` (`FIRE` → `ERROR`) |
| 4 SC09 | IDENTICAL 69/69 | IDENTICAL | AST-only-capable | `scope.is_checked`, pragma directives and Binary IR are all AST-derived |
| 5 SC06 | IDENTICAL 69/69 | IDENTICAL | AST-only-capable | call IR + CFG dominators, AST-derived |
| 6 SC05 | IDENTICAL 69/69 | IDENTICAL | AST-only-capable | guard structure is pure AST |

**8 of 9 rule ids are AST-only-capable. Only 3c is full-compile-only.** The
prior expectation — that 2a/2b need IR and 3a/3b need resolved modifiers, so all
of them need a full compile — is **wrong, and was measured wrong**: SlithIR and
the CFG are lowered by Slither *from the AST*, so removing bytecode removes
nothing they use. 3c is the sole exception, and not because it needs IR: it
shells out separately for the compiler's own storage layout.

**Significance for HIST-L1: none. AST-only does not raise trajectory coverage.**
Asking solc for only the AST does not relax import resolution — solc must still
locate every import to parse and analyse, and fails before emitting anything:

```
OZ-importing file, remapping absent (HIST-L1's exact failure mode):
  ParserError: Source "@openzeppelin/contracts/access/Ownable.sol" not found: File not found.
```

Checked against each cause recorded in HIST-L1: missing dependency tree — **not
fixed**; sibling-path imports needing the whole tree — **not fixed**; exact-pinned
compiler version unavailable — **not fixed** (AST-only changes what is asked of
solc, not which solc exists). All 46 reserve-protocol comparisons would still
fail, and coverage on that window stays 0/29 pairs. **Only per-commit environment
reconstruction (TODO option B) addresses the coverage gap.**

**What AST-only is actually worth**, and why it is still worth building:
~21% less compile time (1.931s → 1.515s per OZ-importing file, 10-run mean); and
immunity to *code-generation* failures — "stack too deep", optimizer crashes,
contract-size limits — which are real historical build breakers, just not the
ones HIST-L1 observed. It also frees 8 of 9 rule ids from ever needing bytecode.

---

## Cross-cutting

| # | Limitation | Direction |
|---|---|---|
| X-L1 | **No CANDIDATE state exists yet.** `src/verdict.py` is still empty; rules return a binary fire/quiet. Every exclusion RULES.md designates as "CANDIDATE, needs human read" (3a.1, and later 2.10 and 5.3) is currently a silent discard. The three-state model is specified but not implemented. | **[FN risk]** |
| X-L2 | **The fixture set is small and narrow.** Precision 1.00 across 10 hand-written single-file cases, all OpenZeppelin 4.9.6, all solc 0.8.20. This demonstrates the rules do what they were designed to do; it is **not** evidence of precision on real repositories. Charter success criteria 6 and 7 (a CONFIRMED finding on a real independent repo, and a real-world false positive root-caused and added as a permanent negative fixture) remain unmet. | **[FP risk]** |
| X-L3 | **Single-file analysis.** Every fixture is one self-contained file. Real repos spread contracts, bases, and proxies across directories and imports; multi-file resolution and per-commit `pragma`/solc-version switching via solc-select are not yet exercised by the history walker (`src/history.py` is empty). | **[FN risk]** |

---

## Architectural design lessons

Not a per-rule failure but an implementation invariant that every future rule
must honour. Recorded here because violating it silently produces false
positives, and because it is invisible until a rule crosses commits.

### DESIGN-L1 — cross-commit set operations MUST diff by canonical_name, never by object identity

**Type: FALSE POSITIVE risk. Applies to every diff-based rule.**

`before.sol` and `after.sol` are compiled by **two separate Slither
invocations**. Slither returns fresh Python objects for each compilation, so the
same source-level entity — a `StateVariable`, a `Function`, a `Contract` — is a
**distinct object instance** in the before-parse and the after-parse. Those
objects use default (identity) hashing and equality, so a set built from one
compilation shares no members with a set built from the other, even for entities
that are byte-for-byte identical in source.

The trap:

```python
# WRONG — compares by object identity across two compilations.
moved = state_writes_after_calls(fn_after) - state_writes_after_calls(fn_before)
# `balances` written after the call in BOTH commits does NOT cancel:
# balances@after and balances@before are different objects, so the set
# difference keeps balances@after -> `moved` is non-empty -> false positive.
```

```python
# RIGHT — diff by a stable cross-commit key, keep after-commit objects.
before_names = {v.canonical_name for v in state_writes_after_calls(fn_before)}
moved = {v for v in state_writes_after_calls(fn_after)
         if v.canonical_name not in before_names}
```

`canonical_name` (e.g. `Bank.balances`) is stable across compilations of the
same source entity and is the correct join key. Keep the **after-commit** objects
in the result so any *within-commit* intersection that follows
(`moved & own_guard_state_reads(fn_after)`, `_reads_by_repo_view(contract_after,
moved)`) still compares objects from a single compilation, where identity is
valid again.

**The rule of thumb:** identity comparison is only ever valid **within one
compilation**. The moment a computation spans before and after, every set/dict
join, membership test, and difference must go through `canonical_name` (or an
equivalent stable key), and only same-compilation objects may be intersected.

**How it was found.** Rule 2b's first implementation. Fixture **N2b-02** — CEI
already broken at N-1 and still broken at N, i.e. no ordering *change* — fired as
a false positive because `balances` failed to cancel across the two
compilations. The fix was to diff by `canonical_name`; N2b-02 then went quiet and
2b reached precision 1.00.

**Who is and isn't exposed.** Rules that inspect a **single** compilation never
hit this: Rule 1, Rule 2a, and Rules 3a/3b/3c all reason about the after-commit
(or one commit at a time) and their set operations stay within one parse. The
exposed rules are the ones that **compare per-commit sets**: Rule 2b today, and
the two diff-based rules still to come — **Rule 5** (return-value check removed)
and **Rule 6** (input-validation guard removed). Both must apply DESIGN-L1 to any
cross-commit set operation from the outset, with a guard/test that a shared
entity present in both commits cancels. Tracked in TODO.md.

### DESIGN-L2 — rules iterate the full import closure, mis-attributing phantom regressions to unchanged imported files

**Type: FALSE POSITIVE risk. HIGH priority. Applies to every diff-based rule
that iterates `slither_obj.contracts_derived` without a source-file filter.**

`Slither(path)` compiles `path` **and its entire import closure**. `contracts`
and `contracts_derived` therefore return every contract from every compiled
source, not just those declared in the file passed in. A diff-based rule that
walks `contracts_derived` examines transitively-imported libraries too.

For a function declared in an **unchanged** imported file, its byte-image is
identical between N-1 and N. Its per-function record set is identical on both
sides. If the rule's cross-commit comparison has *any* within-commit
non-injective key, dict-collapse, or ordering shortcut, it can manufacture a
phantom "regression" out of **zero real change**. The mechanism fires on every
pair whose changed file transitively imports the offending pattern, and the
finding is falsely attributed to the *changed* file (the one Slither was called
on) even though the code that "changed" lives elsewhere and did not change at
all.

**Measured on `reserve-protocol/protocol` under CORRECT git-parent pairing:**

Three of the six false positives from the trajectory run are DESIGN-L2:

| FP | Cur commit | Fired-on function | Declared in | Changed between parent and cur? |
|---|---|---|---|---|
| FP1 | `b2cfd51a` | `AllowanceLib.safeApproveFallbackToMax` | `contracts/libraries/Allowance.sol` | **NO** — `git diff --name-only 43533959 b2cfd51a -- contracts/libraries/Allowance.sol` → empty |
| FP2 | `b2cfd51a` | `AllowanceLib.safeApproveFallbackToMax` | `Allowance.sol` | NO (same as FP1) |
| FP4 | `e27227b2` | `AllowanceLib.safeApproveFallbackToMax` | `Allowance.sol` | **NO** — `git diff --name-only f43202a3 e27227b2 -- contracts/libraries/Allowance.sol` → empty |

Each fire was attributed to the *changed* file (ActFacet.sol / RevenueTrader.sol /
ActFacet.sol respectively), reported against `contracts/facade/facets/…` and
`contracts/p1/…`, while the code Rule 5 actually iterated to produce the fire
lives in an unchanged library. The R5-L1 key-collision (RC-1) is the *proximate*
trigger for these three; DESIGN-L2 is the *enabler* — without closure iteration
Rule 5 would never have opened `Allowance.sol` on either side.

**The other three FPs from that run are NOT DESIGN-L2.** FP5 (RC-2, `in_try`
mis-scoping on a hoisted argument-eval call) and FP6 (RC-5, canonical_name diff
misses renames) fire on functions declared in the *changed* file. FP3 is a genuine
try/catch removal on a facade view — a true trigger with wrong severity per
RULES.md 5.3. DESIGN-L2 explains a class, not the whole run.

> **RC-5 status note (added Phase 3 STEP 6, 2026-08-14 investigation).** The
> parenthetical `(RC-5, canonical_name diff misses renames)` above is retained
> for provenance but reclassified: **RC-5 was a first-guess hypothesis in the
> DESIGN-L2 commit (86645b9), never diagnosed at the code level.** The commit's
> evidence block measures only FP1/FP2/FP4 (DESIGN-L2, with explicit
> `git diff --name-only` traces); FP5 and FP6 got labels in a single sentence
> with no code trace, no fixture, and no measurement. Precedent for the
> labels being first-guesses: STEP 3's investigation of "RC-2" found the real
> mechanism was R5-L1 key collision, not `in_try` mis-scoping — the label
> survived, the mechanism didn't.
>
> STEP 4's fixture (`fixtures-multi/R2B-SPELL-N`) was built to represent the
> admin-gate over-fire class, not a rename. Its diff introduces zero renames
> (all function/state-var/modifier identifiers byte-identical across before /
> after; only `supported[a] = true;` moved across the external call).
> STEP 4's fix (`_admin_gated_by_state_addr` in rule2b.py) silenced it via a
> within-commit structural check for `msg.sender == StateVariable` equality
> gates — **no rename logic, no `canonical_name` diffing, orthogonal to the
> RC-5 mechanism described above**.
>
> Balance-of-evidence: RC-5/FP6 may have been a mislabel of the admin-gate
> class that STEP 4 actually fixed. This is **NOT confirmed** — the mapping
> FP6 → `Upgrade4_2_0.castSpell` → commit `92ff272f` lives only in transient
> user-turn context; grep across the tracked repo returns zero hits for
> `FP6`, `92ff272f`, or the fired-on-function name in any committed file.
> The `canonical_name`-rename mechanism itself has never been reproduced,
> measured, or fixture-locked. **Rules 2b (`rule2b.py:131,134`), 4
> (`rule4.py:197,203,219,221,445,461-475,499-501`), and 5
> (`rule5.py:117`) all key by `canonical_name` across commits**, so the
> mechanism is theoretically plausible on each; whether Slither's
> `canonical_name` genuinely omits any renamed-declaration case, and whether
> any of those rules would then miss a real regression, is unverified.
> Treat RC-5 as an **open empirically-unverified gap**, not as a closed or
> scheduled defect. Definitive resolution requires either (a) a rename
> fixture that first *proves* the mechanism exists by triggering a
> false-negative on Rules 2b/4/5, or (b) re-running the Reserve trajectory
> under STEP-4-fixed rules to confirm FP6 is quiet (walker + clone needed;
> currently deferred to PHASE 5).

> **RETRACTED CLAIM — read this before the paragraph below it.** An earlier
> revision of this file asserted, on 2026-08-15, that a PHASE 5 walker run
> had shown "all 9 rules quiet on `contracts/spells/4_2_0.sol`" and that
> RC-5 was therefore a "RESOLVED — empirically confirmed mislabel". **That
> assertion was wrong and is withdrawn.** It rested on a walker run that was
> silently corrupted by a cache defect (see WALK-L1 below): the walker reuses
> two scratch worktree paths across every pair, while `_shared.parse` and
> `_storage.storage_layouts` memoize on absolute path alone, so the second
> and later pairs to touch a given file re-served the FIRST pair's analysis.
> `contracts/spells/4_2_0.sol` appears in three of the four pairs, so the FP6
> verdict was a replay of an unrelated commit's result. The lesson is the
> PHASE-3 lesson again, applied to our own tooling: a green result from an
> unvalidated instrument is not evidence.
>
> **RC-5 PHASE 5 resolution (2026-08-15, after the cache defect was fixed and
> every pair re-run). Status: NOT the FP6 mechanism — but FP6's real cause is
> now identified and fixed, and it is not a rename.**
>
> The corrected run showed FP6 **still firing** (Rule 2b on
> `contracts/spells/4_2_0.sol`). Direct inspection of the diff and of Slither's
> view of the function established the actual mechanism, recorded as
> [RC-ROLE](#rc-role--rule-2b-admin-gate-discriminator-misses-role-based-access-control):
> `Upgrade4_2_0.castSpell` is governance-only but gates via
> `main.hasRole(MAIN_OWNER_ROLE, msg.sender)` — an authority *call* — while
> STEP 4's discriminator recognised only `msg.sender == <state address>`
> equality. Widening the discriminator takes FP6 to quiet, live, on
> `6481e75d..92ff272f`.
>
> **On RC-5 itself.** The FP6 diff contains no rename: the `cast` mapping is
> DELETED and its one-shot duty folded into the pre-existing `supported`
> mapping. So the literal RC-5 mechanism ("canonical_name diff misses
> renames") is still not what drove FP6 — but that is now established by
> reading the diff and fixing the real cause, not by the retracted quiet
> result. The rename mechanism remains **empirically unobserved** on any
> measured commit or fixture. Rules 2b/4/5 do key by `canonical_name` across
> commits, so it stays theoretically plausible and unproven; a future
> real-repo hit would be a new finding under a new label, not RC-5.
>
> Provenance chain preserved (do not delete):
> 1. **DESIGN-L2 commit `86645b9` (2026-08-12)** — one-line parenthetical
>    hypothesis: "FP6 (RC-5, canonical_name diff misses renames)". No
>    evidence, no fixture, no code trace. Best guess at the time.
> 2. **Phase 3 STEP 6 (2026-08-14) — balance-of-evidence investigation.**
>    R2B-SPELL-N (the STEP-4 fixture) contains zero renames; STEP 4's fix
>    uses no rename logic; FP6→Upgrade4_2_0.castSpell mapping was untracked
>    in any committed file. Verdict at the time: "may have been a mislabel
>    of the admin-gate class, NOT confirmed."
> 3. **PHASE 5 first walker run (2026-08-15) — INVALID, retracted.** Reported
>    FP6 quiet; the result was a cache replay (WALK-L1), not a measurement.
>    Briefly recorded here as "RESOLVED"; that entry was wrong.
> 4. **PHASE 5 corrected run (2026-08-15) — the actual measurement.** With
>    cache invalidation in place FP6 still fired; the cause was diagnosed as
>    RC-ROLE (role-based gate invisible to the STEP-4 discriminator), fixed,
>    and re-measured quiet on the live commit pair. RC-5 was never the
>    mechanism; it was also never the thing that had been fixed.

**Which rules are exposed** (measured, `grep` over `src/rules/`):

| Rule | Iterates | Exposure |
|---|---|---|
| **1**  | `slither_obj.contracts_derived` via `_candidate_map` (rule1.py:107)  | **YES** |
| **2a** | own `_candidate_map` (rule2a.py:59)                                 | **YES** |
| **2b** | reuses rule2a's `_candidate_map`                                    | **YES** |
| **3a** | `slither_obj.contracts_derived` (rule3a.py:48)                      | **YES** |
| **3b** | `slither_obj.contracts_derived` (rule3b.py:83, 119, 157)            | **YES** |
| **3c** | iterates `storage_layouts()` output over every contract solc emitted | **YES** — mitigated by the `node_modules` path skip in `storage_layouts()`, which suppresses OZ-base contributions but not first-party imports |
| **4**  | `_own_functions` with `_file_of(contract) != target` filter (rule4.py:214) | **NO — scoped** |
| **5**  | reuses rule1's `_candidate_map` (rule5.py:71)                       | **YES** — confirmed by FP1/FP2/FP4 |
| **6**  | reuses rule1's `_candidate_map` (rule6.py:62)                       | **YES** |

**8 of 9 rule ids are closure-exposed. Only Rule 4 scopes to the changed file.**
Rule 4 was written after the AllowanceLib class was already known, which is why
the filter was added there; the earlier rules pre-date the finding.

**Why it hid until now.** Every frozen fixture is a **single self-contained
`.sol`** — no imports, no closure to walk into. The Monetrix real-world run was
self-vs-self, so before-map == after-map function-by-function and any
well-behaved diff cancelled. **Only a real repo with a changed file that
transitively imports an unchanged file containing the trigger pattern exposes
this.** The multi-file precondition is the reason DESIGN-L2 could ship past the
frozen sets, past Monetrix, and past the 29-pair recent-window Reserve slice
without triggering — the 29-pair window happened to change small files whose
imports did not include AllowanceLib often enough. The 191-pair slice hit
`Allowance.sol` transitively three times.

**Fix principle (not yet implemented).** A rule must only attribute a finding to
a function/declaration that lives in a file **actually changed in this commit**.
Findings whose declaring file is unchanged between the two commits are not
regressions introduced by this commit and must be suppressed. Two viable
implementations:

- **Loop-side, one change:** the trajectory harness passes the set of changed
  files, and filters each rule's findings to declarations in that set. Rule
  modules stay untouched. Preserves the ability to run the same rule on a
  single-file fixture (where "changed set" = the one file).
- **Rule-side, nine changes:** each rule adds a `_file_of(x) in changed_files`
  filter to its own iteration, symmetrical to Rule 4's `_own_functions`. Higher
  cost, but the guard travels with the rule.

Either fix must be **locked by a MULTI-FILE fixture** — a changed file that
imports an unchanged file containing the trigger pattern for the rule under test
— because the current single-file fixture set structurally cannot exercise this
shape. Without such a fixture, a future refactor could reintroduce the exposure
silently. Tracked in TODO.md.

---

### DESIGN-L3 — attribution had to be a SIDE CHANNEL, not a return-value change

**Type: architectural decision, recorded because the obvious alternative was
the dangerous one.**

Every rule's `run()` returned `True | "candidate" | False`. A product needs more
than that — which contract, which function, which line, on what evidence — and
the natural refactor is to widen the return type to a finding object.

That refactor is precisely the wrong move here, for a reason that is specific to
this project rather than general taste: **`scorer.py` is a guard-protected file
and the 14 frozen fixture sets are ground truth interpreted through its
`raw == "candidate"` / `bool(raw)` contract.** Widening the return type edits the
one artifact whose job is to be un-edited, and it re-interprets every frozen
verdict at the same time. A regression introduced that way would be invisible,
because the thing that detects regressions is what changed.

**What shipped instead.** `_shared.emit()` appends a detail record to the
`case_meta` dict the caller already passes in. Rules keep their exact return
contract; `scorer.py` is untouched and still passes the same dict it always did;
a caller that wants attribution reads `case_meta["_findings"]`, and one that does
not pays nothing. `emit()` swallows every exception by design — attribution is
reporting metadata, and a malformed source mapping must never be able to turn a
fire into a miss.

**How the two are kept in sync.** `tests/test_attribution.py` asserts both
directions across all 14 sets: a rule that FIRES emits at least one record naming
a real declaration, and a rule that stays QUIET emits nothing at all. The second
half matters more than the first — a phantom record would put a finding in the UI
that the engine never made, which is a false positive arriving by a route that
precision scoring cannot see.

**Evidence the change was verdict-neutral:** per-rule TP/FP/FN counts across all
14 frozen sets are byte-identical before and after the attribution layer.

---

### SURV-L1 — "repaired later" can also mean "renamed later"

**Type: FN-direction misreport in the TRAJECTORY field, not in detection.
Affects the HEAD-survival check in `src/scan.py`.**

Whether a regression survives to HEAD is answered by re-running the same rule
on `(file at N-1, file at HEAD)`. That reuses the rule's own semantics rather
than inventing a second notion of "still broken", which is the right call — but
it inherits the rules' cross-commit matching key. Rules 1, 2a, 2b, 5 and 6 match
functions by `(contract name, full signature)`, so between commit N and HEAD:

- a renamed function,
- a changed signature,
- a function moved to a different contract, or
- a contract renamed,

all make the rule find no counterpart, stay quiet, and be recorded as
**"repaired later"** when the control may still be missing under a new name.
The verdict direction is safe — a wrongly-quiet survival check DOWNGRADES the
finding to CANDIDATE and can never manufacture a CONFIRMED — but the trajectory
sentence shown to a reader is then wrong, and "a later commit restored the
control" is a specific claim that deserves to be true.

`survives_to_head` is already three-valued (`True` / `False` / `None` for
undetermined, e.g. the file is gone at HEAD or no HEAD environment could be
built), and `None` is never treated as evidence. The unfinished work is to route
the rename case to `None` instead of `False` — which needs a rename detector
(`git log --follow`, or matching on body similarity) that does not exist yet.

**Do not fix this by loosening the rules' matching key.** That key is what makes
exclusion 1.12 (whole function deleted) work, and weakening it trades a wrong
trajectory label for a real false positive.

---

### RC-RENAME1 — a control that moves from CONSTRUCT-TIME to RUN-TIME is invisible

**Type: FALSE NEGATIVE, structural. Affected rules 1, 2a, 2b, 3a, 3b, 5, 6 (every
name-keyed diff rule). MEASURED on a real, publicly disclosed, exploited
regression. FIXED — Rule 10.**

> **STATUS: FIXED (commit `f8c8a24`).** Closed by a NEW rule keyed on the
> contract's external surface — `src/rules/rule10.py`, specified in RULES.md
> §RULE 10, locked by `fixtures-r10/` (1 positive, 5 negatives, precision 1.00 /
> recall 1.00). Closed **empirically**, the same way PHASE 5 closed RC-5: the
> exact pair below (`5f52a2ea..a4c48d61`) re-run through `src/scan.py` now
> produces **1 finding — rule 10, `NFT.init`, verdict CANDIDATE**. CANDIDATE and
> not CONFIRMED is correct and deliberate: no address was supplied, so liveness
> is unset and `src/verdict.py` caps it, per the six-evidence-field rule.
> All 14 pre-existing fixture sets are unchanged at 35/84 detections.
>
> Everything below this line is the ORIGINAL entry, preserved verbatim as
> provenance — the measurement that motivated the rule, and the fix direction
> that turned out to be only half right. Two of its assumptions were wrong; see
> §R10-M1 and §R10-M2, both of which were caught by probing the real 88mph parse
> **before** trusting a fixture built to match the design.

**Naming note.** This is a NEW label, deliberately not `RC-5`. `RC-5` was the
hypothesised "rename breaks `canonical_name` matching" mechanism, which was
retired as a mislabel of the admin-gate class (see TODO.md). RC-RENAME1 is a
distinct, now-observed mechanism, and reusing the retired number would repeat
the RC-4/RC-5 confusion this file already had to untangle once.

**The case.** 88mph `contracts/NFT.sol`, commit `a4c48d61661a` ("integrate
EIP-1167 into NFT deployment"), parent `5f52a2ead702`. Public, whitehat-reported
via Immunefi, $6.5M at risk, funds returned, contracts deprecated. The diff:

```solidity
-    constructor(string memory name, string memory symbol)
-        public ERC721Metadata(name, symbol)
-    {}
+    function init(address newOwner, string calldata tokenName,
+                  string calldata tokenSymbol) external {
+        _transferOwnership(newOwner);
```

A one-shot, deployer-only entry point became a permanently callable external
function that hands over ownership. It is exactly Chainwatch's claim shape — a
control that existed at N-1 and does not at N.

**Chainwatch is completely quiet on it.** All eight rules that could run
returned quiet (Rule 3c could not run at all — solc 0.5.17 has no
`--combined-json storage-layout`; irrelevant here, 3c is about storage
collisions).

**Mechanism, measured rather than reasoned.** Probing both sides directly:

```
N-1  5f52a2ea    constructor(string,string)     is_constructor=True   init_guard=False
N    a4c48d61    init(address,string,string)    is_constructor=False  init_guard=False
                                                writes=['_owner', '_tokenName', ...]

rule3b._candidate_functions, NFT only:
  N-1: [contractURI, mint, burn, setContractURI, setTokenURI, setBaseURI]
  N:   [init, name, symbol, contractURI, mint, burn, setContractURI, ...]
```

Two independent reasons, either sufficient on its own:

1. **No counterpart to diff against.** Every diff rule matches a function across
   commits by `(contract, name)` or `(contract, full_name)`. `init` exists only
   at N. There is no `('NFT','init')` at N-1 that could have "lost" anything, so
   no trigger can evaluate.
2. **The N-1 protection is not a modifier at all.** It is the *constructor
   mechanism itself* — one-shot and deployer-only, enforced by the EVM, not by
   any AST node a rule inspects. `has_init_guard(constructor)` is False, and
   constructors are filtered out of Rule 3b's candidate map entirely, so even a
   same-named counterpart would not satisfy trigger 1's precondition.

**The generalisation, which is bigger than "renames".** Chainwatch detects a
control removed from a *surviving, same-named function*. It does not detect
**responsibility migrating between entry points** — construct-time to run-time,
one function to another, a modifier's job absorbed into a caller. The protection
did not lose a guard; the protected thing moved somewhere with no guard. Every
proxy/clone migration has this shape, which is why it matters: EIP-1167 and
upgradeable-proxy patterns *require* replacing a constructor with an
initializer, and that refactor is precisely where the guard gets forgotten.

**Scope.**
- Any constructor -> `init`/`initialize` migration (EIP-1167 clones, UUPS,
  Transparent proxies). Common and deliberate, not exotic.
- Any commit that deletes a guarded function and adds an unguarded successor
  under a different name or signature.
- NOT limited to Rule 3b: Rule 1 also cannot fire here, because it defers every
  constructor to Rule 3 (`_is_rule3_territory`) and likewise finds no N-1
  counterpart for `init`.

**Fix direction (deliberately NOT implemented).** A trigger keyed on the
*contract's external surface* rather than on per-function name matching:
a contract that had a constructor at N-1 and at N has a state-writing external
function that is not one-shot-guarded and writes an access-control state
variable (here `_owner`, via `_transferOwnership`). That is a NEW rule, not a
tweak to 3b, and it inverts the matching direction, so it needs its own fixture
set first: a positive (this exact shape) plus at least two negatives — a
legitimate constructor->`initializer`-guarded migration, which must stay quiet,
and a contract that simply gained an unrelated external setter. Without those
negatives, the obvious implementation fires on every proxy migration ever made
and destroys precision. **Fixtures before code, as always.**

**Evidence trail.** Repo `github.com/88mphapp/88mph-contracts`, commit
`a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e`; Immunefi bugfix review
"88mph function initialization"; six affected mainnet addresses published there.
Chainwatch run: 1/1 pairs analysed, 8/9 rules executed, 0 findings.

---

### R10-M1 — `contract.constructor` does not cross the inheritance chain

**Type: WRONG SLITHER USAGE, general. Would have caused a FALSE NEGATIVE on
Rule 10's own positive case. MEASURED on the real 88mph parse. FIXED in Rule 10;
one pre-existing site carries the same pattern and is REPORTED, NOT FIXED.**

**This is a general Slither-usage lesson, not a Rule 10 detail.** Any rule that
asks "what did the constructor establish?" through `contract.constructor` is
asking a narrower question than it thinks.

**Mechanism, measured rather than reasoned.** Probing 88mph `NFT` on both sides:

```
N-1  5f52a2ea
  nft.constructor.all_state_variables_written()
    = ['ERC165._supportedInterfaces','ERC721Metadata._name','ERC721Metadata._symbol']
                                                            <-- NO Ownable._owner
  iterating the chain instead:
    chain member Ownable: constructor writes=['Ownable._owner']   <-- it is HERE

N    a4c48d61
  nft.constructors_declared = None          (NFT declares no constructor)
  nft.constructor.all_state_variables_written() = ['Ownable._owner']
```

`all_state_variables_written()` on the derived constructor does **not** reach the
full base-constructor chain. At N-1 it captured `ERC721Metadata`'s writes —
because that base constructor is explicitly invoked in the constructor header —
but not `Ownable`'s, which runs implicitly. Worse, `contract.constructor`
resolves to a *different function* on the two sides: NFT's own at N-1, an
inherited one at N.

**Why a fixture could never have caught this.** In a single-contract fixture the
constructor and the write live in the same contract, so the accessor works. The
defect only appears when the write happens in an implicitly-invoked base
constructor — i.e. in exactly the real-world inheritance shape (`Ownable`) that
motivates the rule. This is why Rule 10's three measurement checks were run
against the real 88mph parse **before** the fixtures were trusted: a fixture
built to match a design can only ever confirm it.

**Consequence had it shipped.** T1 would have found no one-shot writer of
`_owner` at N-1, so Rule 10 would have stayed **silent on the exact case it was
written to detect** — and the fixture suite would have passed, because the
fixture's constructor writes directly.

**Fix (Rule 10).** Collect constructors by iterating `contract.functions` and
filtering `fn.is_constructor`, which reaches every constructor in the chain.
`contract.constructor` is not used, with a comment saying why.

**Scope — one other site carries this pattern. REPORTED, NOT FIXED.**
`src/rules/rule3b.py:98`, `_constructor_disables_init()`:

```python
ctor = contract.constructor
...
for f in reachable(ctor):
```

`reachable()` follows modifiers and internal calls but not implicit base
constructors, so a `_disableInitializers()` call made in a BASE constructor is
invisible to it. Two mitigating facts, neither a reason to leave it forever:
1. **The failure direction is safe.** It is used as
   `_constructor_disables_init(before) and not _constructor_disables_init(after)`.
   A miss on both sides yields False, so the trigger stays quiet — a false
   negative, which is the correct direction under the precision-first tie-break.
2. **The path is unfixtured anyway.** `rule3b.py` already records that trigger 2
   has no fixture exercising it ("spec-faithful but currently unproven by the
   fixture set").
Fixing it means building that missing fixture first. Not done under this section.

---

### R10-M2 — a guard node's `state_variables_read` stops at the node boundary

**Type: SILENT EMPTY RESULT. Produced an empty gate-variable set on the entire
OZ 4 fixture stack, which made five negatives pass VACUOUSLY. MEASURED. FIXED in
Rule 10; pre-existing sites REPORTED, NOT FIXED.**

**Mechanism.** `_gate_vars` originally collected `node.state_variables_read` for
guard nodes that depend on `msg.sender`. Under OZ 4.9.6:

```
Ownable._checkOwner   msg.sender-dep=True   node.state_variables_read=[]
    node: require(owner() == _msgSender(), "Ownable: caller is not the owner")
      calls Ownable.owner() -> reads ['Ownable._owner']
```

The guard node **is** correctly identified as msg.sender-dependent. It simply
reads no state variable *itself*: OZ 4 reaches `_owner` one call-hop away inside
the `owner()` getter. OZ 2 (88mph's stack) exposes it more directly, which is why
the real-contract probe passed while every OZ 4 fixture returned the empty set.

**The dangerous part is how it failed.** `gate_vars = []` means the trigger
ranges over nothing, so *every case is quiet*. The first fixture run scored
**5/6 "agreeing" with their labels** — all five negatives "passed" while
evaluating nothing at all, and only the positive's failure revealed it. A
negative that passes vacuously is not evidence, and a 5/6 that looks like
near-success is worse than an outright 0/6. This is METHODOLOGY Face B with a
new face: not a check that was never run adversarially, but a check that
silently had **no input**.

**Fix (Rule 10).** `_gate_vars` resolves one call-hop: the guard node's own state
reads, plus state read by functions that node invokes. Verified on both stacks —
OZ 4 fixture recovers `Ownable._owner`; the real OZ 2 contract goes from 3 to 5
candidate variables and still produces **exactly one** fire, so the widening
introduced no false positive.

**A claim this corrects.** The Rule 10 design originally justified a bespoke
helper over `_shared.access_control_state_vars` on a measured 3-vs-6 narrowing.
With the call-hop fix the real figures are **5 vs 6** — one variable. The
semantic argument stands (gate variables should be what the authorization
decision reads); the empirical case for it was overstated and is corrected here.

**Scope — which existing logic shares the shape.** Four sites read
`node.state_variables_read` directly. None is currently known to misbehave,
because every library form in use reads its flag directly at the guard node (OZ 4
`Initializable` reads `_initialized`/`_initializing` inline; OZ `ReentrancyGuard`
reads `_status` inline), and the OZ 5 namespaced form was already handled
separately — **finding 3x-L3 is the prior instance of this same class**, where
the state a guard depends on is not reachable as a declared variable at the node.

| site | what it does | exposure |
|---|---|---|
| `_shared.py:644` `is_oneshot_init_guard` | gated flag ∩ written flag | a getter-mediated init flag would be missed |
| `_shared.py:670` `has_init_guard` | same, inline form | same |
| `_cfg.py:150` `own_guard_state_reads` | deliberately node-local by contract | miss ⇒ CONFIRMED degrades to CANDIDATE — safe |
| `_cfg.py:177` `_gated_const_assigns` | crosses functions via `reachable()`, but still node-local *within* each node | miss ⇒ mutex unseen |

**One asymmetry worth naming, because it is a real trap.** The same
`has_init_guard` limitation fails in **opposite directions** for different rules.
For Rule 3b it is a false negative (guard unseen on both sides ⇒ no trigger ⇒
quiet — safe). For **Rule 10 it is a false POSITIVE**: an unseen init guard makes
a writer look unguarded, satisfying T3. Rule 10 is therefore more exposed to this
helper's limits than the rule the helper was written for. Not currently
reachable with OZ 4/5, but it is the direction a future OZ refactor would break.

`constrains_msg_sender` is **not** affected: it iterates `reachable(fn)` and
tests each function's guard nodes, so it crosses the call boundary already. That
is why `constrains_msg_sender(init)` returned the correct `False` on real 88mph
while `_gate_vars` was returning nothing.

---

### RC-INLINE1 — inlining an inherited body reads as a CEI reordering

**Type: FALSE POSITIVE, Rule 2b. MEASURED on a real protocol commit during the
B4 stress re-run. FIXED.**

> **STATUS: FIXED.** Closed by `_after_call_writes()` in `src/rules/rule2b.py` —
> a delegation-resolving replacement for the body-local
> `_cfg.state_writes_after_calls`, kept LOCAL to rule 2b so that `_cfg.py` and
> rule 2a are untouched. Locked by `fixtures-r2b-inline/` (1 positive,
> 3 negatives; pre-fix **precision 0.33 FAIL** → post-fix **1.00 / 1.00 PASS**).
> All 16 fixture sets PASS with pre-existing counts unchanged — including
> `fixtures-r2b` at 3/7, the set most exposed to this change, since making the
> write-set transitive could have cancelled an existing true positive.
>
> **Closed empirically, not just by fixture.** The originating pair
> `57d092db..0cfe9683` re-run through `src/scan.py`: **6/6 files analysed,
> 0 errors, `findings: 0`** — Rule 2b is now quiet on
> `CurveStableRTokenMetapoolCollateral.refresh`, where it previously produced
> the single finding of the entire 25-pair stress run.
>
> **Two limitations of that proof, stated rather than left implied.** (1) The
> positive direction — a genuine CEI break hidden inside an inlining commit —
> is proven ONLY by the synthetic `P2bi-01`. No commit in the 25-pair Reserve
> sample exercises that shape, so there is no real-world evidence for it.
> (2) The claim "the 25-pair set now has zero Rule 2b fires" is DERIVED from
> re-running the one pair that produced the one finding, not from re-running
> the 12.8-hour stress test.
>
> Everything below this line is the ORIGINAL entry, preserved as provenance.
> Its fix direction posed the resolve-vs-distinguish question as open; Step 1
> measured the answer (Slither DOES resolve `super.X()` to its target
> `Function`), so the first option was taken.

**The case.** Reserve Protocol `0cfe9683` ("Convex ETH+/ETH Collateral Plugin",
PR #1113, 2024-04-11), file
`contracts/plugins/assets/curve/CurveStableRTokenMetapoolCollateral.sol`.
Rule 2b fired on `refresh()` with "moved a state write across an external call".

At N-1 the override is two lines:

```solidity
function refresh() public override {
    pairedAssetRegistry.refresh();
    super.refresh();               // already handles all necessary default checks
}
```

At N it is ~80 lines that INLINE the parent's body and add a
`pairedBasketHandler.isReady()` check. The parent —
`CurveStableCollateral.refresh()`, present unchanged at BOTH commits — already
had exactly this shape:

```solidity
try this.underlyingRefPerTok() returns (uint192 underlyingRefPerTok_) {
    ...
    exposedReferencePrice = underlyingRefPerTok_;      // write AFTER an external call
    try this.tryPrice() returns (uint192 low, uint192 high, uint192) {
        savedLowPrice = low; savedHighPrice = high; lastSave = uint48(block.timestamp);
```

**Execution order did not change.** `exposedReferencePrice` was written after
`this.underlyingRefPerTok()` at N-1 too — inside the parent rather than inside
the override. Code moved between contracts; nothing moved across a call.

**Mechanism, read from the source rather than inferred.** `_cfg.py:102`:

```python
def state_writes_after_calls(fn: Function) -> set:
    call_nodes = [node for node, _ in external_call_nodes(fn)]   # fn's OWN nodes
    ...
    for node in after: out.update(node.state_variables_written)
```

Body-local: it never descends into `super.refresh()`. So at N-1 it returns the
**empty set** — not because the writes were correctly ordered, but because the
function has no writes of its own. `rule2b.py` then computes:

```python
after_at_n1_names = {v.canonical_name for v in state_writes_after_calls(fn_b)}
moved = {v for v in after_at_n if v.canonical_name not in after_at_n1_names}
```

With the N-1 set empty, **every** write at N is classified as newly-moved, and
the trigger fires.

**The generalisation.** Rule 2b's precondition "at N-1 all state writes preceded
every external call" is satisfied **VACUOUSLY** whenever the N-1 function
delegates its body to a parent. Absence of writes is being read as evidence of
correct ordering.

**Relation to R10-M2 — same shape, inverted, and that inversion is the point.**
R10-M2 was an empty set silently standing in for a real answer, which made five
negatives pass while evaluating nothing. Here an empty set stands in for a real
answer and makes a check FIRE. A vacuous emptiness is a false negative in one
direction and a false positive in the other; this project has now met both. The
lesson is not "check for empty sets" but "an empty set must never be
interpreted as a measured result until you know WHY it is empty."

**Scope.** Any commit that inlines, flattens, or de-delegates an inherited
implementation — a routine refactor, and common in plugin/collateral hierarchies
where an override starts as `super.X()` and later needs custom behaviour.
Independent of Rule 2a (which keys on mutex presence, unchanged here).

**Not a Reserve issue, stated explicitly so this entry cannot be misread.** The
commit is a public merged PR, the execution semantics are unchanged by it, the
try/catch-around-`this.tryPrice()` pattern is Reserve's long-standing audited
design predating the commit, and the verdict was CANDIDATE with no liveness
evidence. This entry records a defect in **Chainwatch**, not in Reserve.

**Fix direction (NOT implemented, and deliberately not in this commit).** The
open question is whether Slither resolves a `super.X()` call to its target at
the IR level. If it does, `state_writes_after_calls` can include the delegated
body's own after-call writes — the function's real behaviour includes what it
delegates. If it does not, the fallback is to treat "N-1 body consists only of
delegating calls, with no local writes" as a DISTINCT case from "N-1 genuinely
writes nothing", and exclude it from the comparison rather than resolve it.
**Which of those is possible must be MEASURED before either is designed.**
Fixtures first, in both directions: a negative (inlined parent body, order
genuinely unchanged — must go quiet) and a positive (a genuine reorder hidden
inside an inlining commit — must still fire). Without that positive, the
obvious fix degenerates into "any inlining commit is safe", which replaces a
vacuous-empty-set with a vacuous-blanket-pass: the same failure, inverted a
third time.

---

### RC-INLINE2 — `cei_correct` calls a delegating function CEI-correct, vacuously

**Type: FALSE NEGATIVE, Rule 2a (exclusion 2.2). Same root cause as RC-INLINE1,
opposite direction. FIXED.**

> **STATUS: FIXED.** `cei_correct` now asks `_cfg.after_call_writes_resolved`
> instead of the body-local `state_writes_after_calls`, and `rule2a`'s evidence
> set uses the same resolved view — fixing only the gate would have cleared it
> and then emitted a finding listing no variables. Locked by
> `fixtures-r2a-inline/` (1 positive, 2 negatives, precision 1.00 / recall
> 1.00); 17 fixture sets PASS with counts identical to baseline.
>
> The resolver was **moved into `_cfg.py`** rather than duplicated: rule 2a
> cannot import rule 2b (rule 2b already imports rule 2a, so that edge would be
> a cycle), and two copies of this much subtle CFG logic would drift. Rule 2b's
> local copy was collapsed onto the shared one in the same change.
>
> **The trap this fix had to avoid, locked by `N2ai-02`:** making `cei_correct`
> return False whenever an internal call exists would trade a silent miss for a
> false-positive flood. There the delegated parent writes no state at all and
> CEI genuinely is correct, so it must stay quiet — and does.
>
> **Live re-check, stated honestly.** Four Reserve pairs plus the 88mph pair
> produced **no** new Rule 2a fire, and the 88mph result is unchanged (1
> finding, rule 10, CANDIDATE). No case in the history available to this
> project exercises the positive direction, so **`P2ai-01` is the only proof
> that a violation hidden behind delegation now fires.** That is a real limit
> on the evidence, recorded rather than hidden.
>
> Everything below is the original entry, preserved as provenance.

**Why this ranks above RC-INLINE1 despite being the smaller-looking bug.**
RC-INLINE1 was a false POSITIVE: it fired, a human read it, and it was
classified and fixed within one session. RC-INLINE2 is a false NEGATIVE, and a
miss is **silent** — Rule 2a stays quiet, no artifact is produced, nothing
surfaces for review, and the absence of a finding is indistinguishable from a
clean result. Chainwatch's entire coverage-honesty discipline exists because of
exactly this asymmetry: HIST-L2 was a silence that read as a headline
precision result. A false positive costs credibility once; a false negative can
cost it permanently and without ever announcing itself.

**Mechanism.** `_cfg.py`:

```python
def cei_correct(fn: Function) -> bool:
    if not has_external_call(fn):
        return True
    return not state_writes_after_calls(fn)
```

`state_writes_after_calls` is body-local — the same property that produced
RC-INLINE1. For a function whose body is a delegation
(`registry.sync(); super.refresh();`) it returns the EMPTY set, so
`cei_correct` returns **True**. But that emptiness is not evidence the writes
are correctly ordered; it is the absence of any local writes to have an
ordering. The parent's writes — which really do land after an external call —
are never inspected.

`rule2a.py:132` consumes it as exclusion 2.2:

```python
if cei_correct(fn_a):
    continue        # DISCARDED
```

So a function that delegates its body to a CEI-broken parent is **discarded as
CEI-correct**, and Rule 2a never evaluates it.

**Evidence.** Not observed on a real commit — derived from reading the shared
helper while fixing RC-INLINE1, and grounded in the same measurement that
proved RC-INLINE1: the Step 1 probe showed `ChildDelegating.refresh` has
`state_writes_after_calls = (EMPTY)` while the parent it delegates to has
`{exposedRef, savedLow}`. `cei_correct` on that function returns True today.
The 25-pair Reserve sample contains no case that would have surfaced it, which
is consistent with a false negative and is not evidence of absence.

**Scope.**
- Rule 2a only. Rule 2b is fixed (RC-INLINE1) and does not use `cei_correct`.
- Any function whose body delegates to a parent that writes state after an
  external call — the same delegate-then-inline hierarchies RC-INLINE1 covers,
  read from the other end.
- The **de-inlining direction** is the sharpest instance: N-1 delegates to a
  CEI-broken parent (discarded as "correct"), N removes the delegation. Rule
  2a's comparison starts from a baseline that was never true.

**Fix direction (NOT implemented).** The resolver already exists —
`rule2b._after_call_writes()` — and the honest fix is to promote it into `_cfg`
so `cei_correct` and Rule 2a share it. That is deliberately NOT a
copy-paste-and-ship: it changes a SHARED helper, so it reaches Rule 2a's
verdicts and needs the same justification standard Rule 10's `gate_vars`
used, plus its own fixture set FIRST — at minimum a negative (delegating to a
correctly-ordered parent, must stay quiet) and a positive (delegating to a
CEI-broken parent, must fire where it is currently discarded). Note the
positive is the hard one to build and the whole point: it is the case that is
silently missed today, so nothing existing can be adapted into it.

**Do not "fix" this by making `cei_correct` conservative.** Returning False
whenever a function contains an internal call would trade a silent miss for a
flood of Rule 2a false positives — the vacuous-blanket-pass failure this
project has now met three times in different clothing (R10-M2's empty set,
RC-INLINE1's empty set, and the blanket-suppression trap `P2bi-01` was built to
catch). The answer is to compute the real ordering fact, not to guess safely.

---

### RC-EXTRACT1 — arithmetic extracted into a helper reads as unprotected

**Type: FALSE POSITIVE, Rule 4. MEASURED on Aave v2 `20bbae88d399`,
`UniswapLiquiditySwapAdapter.executeOperation`. DOCUMENTED, NOT FIXED.**

**The case.** The commit ("Add swapAllBalance parameter for liquidity swap")
refactors a loop body out of `executeOperation` into a new internal
`_swapLiquidity` helper. The SafeMath call went with it:

```
N-1  UniswapLiquiditySwapAdapter.sol:82   amounts[i].add(premiums[i])   (in executeOperation)
N    UniswapLiquiditySwapAdapter.sol:187  amount.add(premium)           (in _swapLiquidity)
```

`_swapLiquidity` also introduces `.sub()`. Nothing lost its checking; the
arithmetic moved one call away.

**Mechanism.** Rule 4 asks whether a function performed its arithmetic through a
checked library at N-1 and performs it "in the open" at N, judged on the
function's OWN body. After extraction, `executeOperation` still contains raw
arithmetic — the loop counter `i++`, present at both commits — but no longer
contains the `.add()`. The pair "checked-arithmetic disappeared, raw arithmetic
remains" is exactly the trigger, and it is satisfied by a pure refactor.

**Relation to the RC-INLINE family — this is the DE-inlining direction.**
RC-INLINE1 fired when a parent's body was inlined INTO a function; this fires
when a function's body is extracted OUT of it. Same root confusion — a
body-local question asked of a function whose body has moved — reached from the
opposite direction, and on a different rule. The fix for rules 2a/2b was
`_cfg.after_call_writes_resolved`; Rule 4 has no equivalent and does not consult
`reachable()`.

**Scope.** Any rule judging a property of a function's own body across commits
where a commit extracts or inlines code: Rule 4 confirmed by measurement; Rules
5 and 6 are structurally exposed for the same reason and are NOT claimed as
affected without their own evidence.

**Fix direction (NOT implemented).** Evaluate Rule 4's arithmetic question over
`reachable(fn)` rather than `fn.nodes`, matching what rules 2a/2b now do.
Fixtures needed in both directions: a pure extraction that must go quiet, and a
commit that extracts a helper AND genuinely drops SafeMath inside it, which must
still fire — the second is the one any fix must be measured against.

---

### RC-NEWCALL1 — a function's FIRST external call makes every write look moved

**Type: FALSE POSITIVE, Rule 2b. MEASURED on Uniswap v3-periphery
`a796106e098c`, `NonfungiblePositionManager.permit`. DOCUMENTED, NOT FIXED.**

**Mechanism.** `_cfg.state_writes_after_calls` opens with

```python
call_nodes = [node for node, _ in external_call_nodes(fn)]
if not call_nodes:
    return set()
```

A function with **no external call at all** therefore returns the empty set — by
construction, not because its writes precede anything. Rule 2b then computes
`moved = after_at_N - after_at_N-1` and every write following the newly-added
call is classified as having moved across it.

**The case.** At N-1 `permit` verifies a signature with `ecrecover` (a builtin,
not an external call) and calls `_approve`. The commit adds EIP-1271 contract
signature support, introducing the contract's first external call —
`IERC1271(owner).isValidSignature(...)` — with `_approve` after it.

**Why it is not a regression.** Rule 2b's premise is that a write CHANGED
position relative to a call. At N-1 there was no call for anything to be
positioned against. This is CHARTER's "a contract that was never safe is out of
scope" applied to ordering: there was no ordering to regress from.

**Fix direction (NOT implemented).** Rule 2b should require that `fn_b` had at
least one external call before comparing sets — the same shape as Rule 10's T2
precondition. A fixture pair is needed in both directions: no-call-at-N-1 gaining
a call (quiet), and a genuine reorder where both commits already had calls
(must still fire).

---

### RC-NEWVAR1 — a state variable introduced at N cannot have "moved"

**Type: FALSE POSITIVE, Rule 2b. MEASURED on Uniswap v3-periphery
`0239382f49b3`, `Quoter.quoteExactOutputSingle`. DOCUMENTED, NOT FIXED.**

**Mechanism.** Rule 2b diffs the two after-call write sets by
`canonical_name`. A variable that does not exist at N-1 cannot appear in the
N-1 set, so any write to it at N is unconditionally "moved".

**The case.** The commit introduces `uint256 private amountOutCached` as
transient storage: it is written before `getPool(...).swap(...)` and `delete`d
in the `catch` afterwards, and it is read by a guard in the swap callback
(`if (amountOutCached != 0) require(amountReceived == amountOutCached)`), which
is what routes it to the CONFIRMED branch.

**Why it is not a regression.** A variable with no previous existence has no
previous position. Separately, `Quoter` is a lens contract whose swaps always
revert by design — but that is context, not the mechanism, and the mechanism
alone is enough to reject the fire.

**Relation to RC-NEWCALL1.** Same family, different missing baseline: there the
CALL is new, here the VARIABLE is. Both are the vacuous-empty-set failure this
project has now met four times (R10-M2, RC-INLINE1, RC-INLINE2, and this pair).
**The generalised lesson, now earned rather than asserted: an empty set is a
measurement only when you know WHY it is empty.**

**Fix direction (NOT implemented).** Restrict `moved` to variables that existed
at N-1, matched by canonical name against `contract_b.state_variables`.

---

### RC-RENAME2 — a parameter rename reads as a removed require (Rule 6)

**Type: FALSE POSITIVE, Rule 6. MEASURED on Uniswap v3-periphery
`f3ab2f1aa21a`, `NonfungiblePositionManager.decreaseLiquidity`. DOCUMENTED, NOT
FIXED.**

**This is the rename mechanism the project predicted and had never observed.**
TODO.md, on retiring RC-5: *"The rename mechanism remains **empirically
unobserved**; Rules 2b/4/5 do key by `canonical_name` across commits, so it
stays plausible and unproven. A future real-repo hit is a NEW finding under a
new label, not RC-5."* This is that hit, on Rule 6 rather than 2b/4/5.

**The case.** The commit ("Events in the NFT Contract") renames a parameter and
nothing else about the check:

```diff
-        uint128 amount,
+        uint128 liquidity,
-        require(amount > 0);
+        require(liquidity > 0);
```

The validation is intact. Keyed by the guarded variable's name, the N-1 check on
`amount` has no counterpart at N, so it reads as removed.

**Scope.** Any rule keying a guard to a parameter or local by name. Rule 6 is
confirmed by measurement; Rules 2b/4/5 remain plausible-and-unobserved for the
same reason they were before, and must not be claimed as affected without their
own evidence.

**Fix direction (NOT implemented).** Match the guard by its POSITION in the
signature and the shape of its comparison, not by the identifier. Requires
fixtures in both directions: a pure rename (quiet) and a genuinely removed
require whose parameter was also renamed in the same commit (must still fire) -
that second case is the hard one and is what any fix must be measured against.

---

### RC-MUTEX1 — a reentrancy mutex is mistaken for one-shot init machinery

**Type: FALSE POSITIVE, Rule 3c, via a SHARED helper. MEASURED on Uniswap
v3-core `76a9ffa6ebc4`, `UniswapV3Pair`. DOCUMENTED, NOT FIXED. Highest-impact
of the four, because the helper is shared and the shape is ubiquitous.**

**Mechanism.** `_shared.is_oneshot_init_guard(mod)` returns True when a modifier
gates on a storage flag, writes that same flag, and writes it to a compile-time
CONSTANT. A set/clear reentrancy mutex satisfies all three:

```solidity
uint256 private unlocked = 1;
modifier lock() {
    require(unlocked == 1, 'UniswapV3Pair::lock: reentrancy prohibited');
    unlocked = 0;
    _;
    unlocked = 1;
}
```

It gates on `unlocked`, writes `unlocked`, and writes constants — `0` and `1`.
`defines_init_machinery` therefore reports the contract as proxy-deployed,
which **disables Rule 3c exclusion 3c.3**, and 3c fires on a contract that can
never be upgraded. The emitted detail even asserts "on a proxy-deployed
contract", which is false: Uniswap v3 pools are immutable, CREATE2-deployed,
with no fallback, no delegatecall and no initializer.

**Why the existing discriminator does not catch it.** The `3b-L-ratelimit`
discriminator distinguishes an init flag from a rate limit by asking whether the
gated variable is ever written to a constant — a rate limit is written from
`block.timestamp` or an argument. A mutex is written to constants in BOTH
directions, so that test passes it.

**The missing property is MONOTONICITY.** A one-shot initializer closes its gate
permanently; a mutex closes and then REOPENS it. The project already knows how
to detect exactly that shape — `_cfg.has_setclear_mutex` exists for Rule 2a —
and `is_oneshot_init_guard` simply does not consult it.

**Scope.** Every consumer of `is_oneshot_init_guard` / `defines_init_machinery`:
Rule 3b's exclusion 3b.4, Rule 3c's 3c.3, and Rule 10's `has_init_guard` path
(exclusion 10.1). For Rule 10 the direction is the dangerous one — a mutex-
carrying writer would be classified one-shot-guarded and the rule would go
QUIET, a false negative. Not observed, and stated as unobserved.

**Fix direction (NOT implemented).** Require the gated flag to be written to
exactly one constant value on all reachable paths, or explicitly exclude
modifiers that `has_setclear_mutex` recognises. Needs a fixture set covering a
real initializer, a real mutex, and a contract carrying both.

**Secondary observation, same finding.** The identical contract-level 3c result
was emitted TWICE — once attributed to `contracts/UniswapV3Factory.sol` and once
to `contracts/UniswapV3Pair.sol` — because `UniswapV3Pair` is reachable from
both compiled units and DESIGN-L2's `accept_finding` accepts both, each file
being genuinely in the commit's changed set. Contract-level findings need
deduplication by (contract, variable), not by file.

---

### WALK-L7 — a rule can be fully registered, fully tested, and never run

**Type: PIPELINE WIRING. A shipped rule was silently absent from the product.
MEASURED. FIXED.**

**Mechanism.** `src/rules/register_all()` registers every rule module, and
`scorer.py` runs whatever is registered — so a new rule is fixture-tested the
moment it exists. The product does **not** run what is registered. It runs:

```python
# src/scan.py
RULE_ORDER = ["1", "2a", "2b", "3a", "3b", "3c", "4", "5", "6"]
...
rule_ids = [r for r in (opts.rules or RULE_ORDER) if r in RULES]
```

Rule 10 was in `RULES` and absent from `RULE_ORDER`, so the intersection dropped
it. The first real-repo run reported it plainly and it was still easy to miss:

```
{'kind': 'start', ..., 'rules': ['1','2a','2b','3a','3b','3c','4','5','6']}
```

**Why this is its own lesson and not "just a bug."** Every gate the project
normally trusts was **green** while the rule did nothing in the product:
`fixtures-r10` 6/6, precision 1.00, recall 1.00, all 14 sets unchanged, the
attribution suite passing. The fixture harness and the product reach the rule
registry by **different paths**, and only one of them was tested. A unit that
passes its tests and is never invoked is indistinguishable, from the test
suite's point of view, from one that works.

**Evidence.** Detected only by running the real 88mph pair through
`src/scan.py` (A4). Fixed by adding `"10"` to `RULE_ORDER` plus a `RULE_TITLES`
entry; `chainwatch.py` and `webapp/server.py` both import `RULE_ORDER` from
`src/scan.py`, so both front ends picked it up from the single change.

**Scope.** Any future rule. There is currently **no check that
`set(RULE_ORDER) == set(RULES)`**, so the next rule can repeat this exactly.

**Fix direction (NOT implemented).** A one-line invariant test asserting that
every registered rule id appears in `RULE_ORDER`, so the omission fails a test
instead of failing silently in production. Deliberately not written under this
section — it is a new test, and tests get added on purpose, not in passing.

**Related but distinct.** `walker.py` cannot run a target other than the last one
scanned: it reuses flat `prev`/`cur` worktrees still belonging to an earlier
Reserve run, so an 88mph SHA reports `fatal: unable to read tree`. That entry
point is already recorded in TODO.md as superseded by `src/scan.py`, which
carries the WALK-L6 mirror-clone fix. Noted here only so the next person who
reaches for `walker.py` on a fresh repository knows why it fails.

---

## METHODOLOGY — a self-consistent story is not evidence

**Project-level lesson, not tied to any one finding. Four instances so far,
each of which cost real time and one of which shipped a hole in a security
gate.** They look like two different mistakes and are one: *plausibility
mistaken for verification.* It has two faces.

**Face A — the error you are shown came through a fallback, so it describes the
fallback.** Chainwatch has two retry loops, both deliberate and both correct as
features: `_shared._compile` retries every installed solc when the ambient one
refuses a file, and `_storage.storage_layouts` does the same for the layout
extractor. Each keeps the LAST attempt's error and discards the first. The
message a human eventually reads therefore describes the last thing tried, not
the thing that broke — and it is always a coherent, self-consistent story,
which is exactly what makes it dangerous.

**Face B — the check you read and approved was never executed against anything
that should fail.** Code that looks right reads as right. Only an input designed
to break it distinguishes "correct" from "correct-looking".

| # | Face | What was believed | What was true |
|---|---|---|---|
| 1 | A | "`_storage.py` does not honor the walker's `SOLC_VERSION`, falls back to ambient 0.7.6" (TODO.md, pre-PHASE 6) | Never established. The 0.7.6 text was the retry loop's last candidate. |
| 2 | A | WALK-L2: "Rule 3c ran solc in the wrong directory — TOTAL COVERAGE LOSS, 42/42 errors, FIXED" | Also never reproduced. A second plausible mechanism asserted with the confidence of the first, and a 42/42 figure from a different run pasted onto a 4-pair measurement. Retracted; the defect is real in code but latent. |
| 3 | A | 88mph run: "current compiler is 0.7.6" on Rule 3c, with `SOLC_VERSION=0.5.17` explicitly set | `solc 0.5.17` has no `--combined-json storage-layout` **at all** (`Invalid option to --combined-json: storage-layout`). Nothing to do with versions: the first attempt failed on an unsupported option, and 0.7.6 is merely last in the candidate ranking. |
| 4 | B | `agent/verify.py`'s `_EXPLOIT` pattern, written and reviewed as correct | It could not match anything ending in punctuation. The pattern closed with a `` word boundary, which can never follow `(` or `)`, so `abi.encodeWithSelector(` and `exploit()` were silently unmatched. **A hole in the hallucination gate that reading did not reveal.** `tests/test_agent_tools.py::test_exploit_material_is_caught` found it on the first adversarial run (19/20) — the only reason it is not still there. |

Instance 2 is the worst, because it was produced *while investigating instance
1*: the same fallback fooled the same investigation twice, in opposite
directions. Instance 4 is the most expensive if missed, because a gate with a
hole in it reports "verified" forever.

**The rule, applied from here on.**

1. **Reproduce the first failure by hand before diagnosing.** An error surfaced
   through a retry or fallback path is not evidence. In instance 3 one command
   with no fallback gave the answer immediately.
2. **A hypothesis that cannot be reproduced on demand is a hypothesis.** Label
   it as one here. Do not tick a TODO item on it.
3. **Never carry a measurement across workloads.** A count from a 29-pair run
   says nothing about a 4-pair run, and pairing them manufactures a
   before/after that was never observed.
4. **Every check ships with an input that must fail it.** A gate that has never
   rejected anything is not known to work. This is the same discipline as a
   negative fixture, applied to validators instead of rules — and it is why
   `verify_report` is tested with an invented hash, an invented address, an
   invented path, an out-of-range line, an invented qualified name, three
   overclaim phrasings, a stripped header, and exploit material.
5. **A passing test proves the unit works, never that it runs.** See §WALK-L7.
   Deliberately NOT filed as a fifth instance above: those four are all
   *plausibility mistaken for verification*, where the evidence was
   misread. WALK-L7 is the opposite shape — every gate was green and every
   number was true, and the rule still did nothing in the product, because the
   test harness and the product reach the rule registry by different paths.
   The lesson is about the **scope** of what was verified, not the quality of
   the evidence, so it earns its own entry rather than a row in that table.
   Its sibling is §R10-M2's vacuous pass: there the checks ran with no input,
   here the check ran on input the product never sees.

**Structural fix direction (not implemented).** Both retry loops should retain
the FIRST failure alongside the last and report both, e.g.
`first attempt (ambient 0.5.17): <error>; after N fallbacks (0.7.6): <error>`.
Cheap, and it would have prevented instances 1 through 3. Tracked in TODO.md.

---

### HIST-L2 — the per-commit COMPILER is never provisioned, only the dependencies

**Type: SILENT COVERAGE LOSS, severe. Affects every rule. MEASURED on a 25-pair
Reserve stress run: 5 of 72 file comparisons completed (6.9%). NOT FIXED —
documented first, per the fixtures-and-measurement-before-code discipline.**

HIST-L1 built per-commit environment reconstruction and proved it on a 29-pair
window: node/submodule installs, cached on the resolved dependency set. That
machinery reconstructs **dependencies**. It does not reconstruct the
**compiler**. `detect_env` reads a `solc_pin` out of the framework config and
`_apply_build_config` exports it as `SOLC_VERSION`, but nothing ever installs
it, and `solc_available()` is never consulted before a run.

**Why it stayed invisible until now.** Every previous trajectory measurement —
the whole FP1–FP6 loop — ran on commits whose pragma happened to match a locally
installed compiler (0.8.28). The stress run was the first to walk *older*
history, and older history pins older compilers.

**Evidence.** Required pragma across the 25 stress pairs' 76 file comparisons:

| pragma | comparisons | installed? |
|---|---|---|
| `0.8.19` (exact) | 45 | **NO** |
| `0.8.17` (exact) | 12 | **NO** |
| `0.8.28` | 11 | yes |
| `0.8.9` | 4 | yes |
| `^0.8.19` | 2 | yes (caret: any 0.8.x satisfies) |
| `^0.8.17` | 2 | yes |

**57 of 76 comparisons (75%) were uncompilable purely because two compiler
versions were absent from the box.** The resulting error is
`Solidity version not found` from solc-select's shim, surfaced through
`_shared._compile`'s fallback loop after every installed candidate has been
tried and rejected — because an EXACT pin (`pragma solidity 0.8.19;`, no caret)
cannot be satisfied by any other version, by construction. Reserve pins exactly;
so do most audited protocols.

**The result this produced, and why it is the whole point of the coverage
invariant.** The stress run reported `findings: 0`. Taken alone that reads as
"25 pairs across nine contract families, zero false positives" — a headline
result. The coverage line says `files 5/72 ok`. **The run tested the
environment layer, not the rules.** Without that line in the report this would
have been recorded as a precision success. It is the HIST-L1 lesson recurring
with a different cause, and it is the second time in this project that a
confident silence turned out to be an unmeasured one.

**Scope.**
- Any repository old enough that its pinned compiler is not on the analysis box
  — which is most repositories, since trajectory analysis is by definition about
  the past.
- Exact pins are the common case in audited Solidity; caret ranges degrade
  gracefully and are the minority (4 of 76 here).
- Independent of HIST-L1: dependencies installed correctly on 23 of 25 pairs.

**Fix direction (NOT implemented).** `solc-select install <pin>` on demand
during env reconstruction, keyed and cached like the dependency install, with
the pin taken from the file's own pragma when the framework config does not
declare one. Two things must be got right before writing it:
1. **Report, do not silently succeed.** An install that fails (no network, a
   yanked build, an unsupported platform) must produce a per-pair skip reason,
   not a compile error 200 lines later.
2. **Bound it.** A multi-year walk can request a dozen compilers; the run should
   say up front which versions it will fetch and how large that is.
A pre-flight pass that reports "this walk needs solc 0.8.17, 0.8.19 — 2 not
installed" *before* analysing anything would have turned this 69-minute run into
a 5-second answer.

---

### HIST-L3 — the install command set predates Yarn Berry

**Type: COVERAGE LOSS plus a SAFETY guarantee resting on an accident. FIXED.**

`INSTALL_CMDS["yarn"]` tries `yarn install --immutable --mode=skip-build`, then
falls back to `yarn install --frozen-lockfile --ignore-scripts`. Yarn 2+ (Berry)
rejects the second outright:

```
Unknown Syntax Error: Unsupported option name ("--ignore-scripts").
```

Both stress-run skips (`feab683c..6fed5516`, `55f24458..aab30189`) are this, and
both were correctly reported as `env-reconstruction-failed (dep-missing)` with
the reason attached — the skip accounting worked, the command set is stale.
Berry disables lifecycle scripts through `enableScripts: false` in `.yarnrc.yml`
or `YARN_ENABLE_SCRIPTS=0`, not a CLI flag.

**The safety half turned out to matter more than the coverage half.** The whole
reason `--ignore-scripts` is passed is CHARTER rule 5 — never execute a target
repository's code. On a Berry repo that flag does nothing, so the guarantee was
resting entirely on `--mode=skip-build` being the command that happened to run
FIRST. Measured on the Reserve checkout:

```
$ yarn config get enableScripts                      -> true
$ YARN_ENABLE_SCRIPTS=0 yarn config get enableScripts -> false
```

Scripts were enabled in the target tree, and only the fallback ORDERING kept
them from running. Safety that depends on which command wins a retry race is
not safety; it is a coincidence that has not failed yet — the same shape as
HIST-L5, where a junction left by a previous run decided whether an install
worked.

**Fix.** `INSTALL_ENV` overlays the subprocess environment per package manager:
`YARN_ENABLE_SCRIPTS=0` for yarn, `npm_config_ignore_scripts=true` for
npm/pnpm. The environment holds regardless of which command wins, what the
installer's CLI dialect is, or what a repo's own `.yarnrc.yml` says. The
command list is unchanged and still ordered Berry-first-then-yarn-1, so each
dialect's install still works; the guarantee simply no longer depends on that
ordering.

---

### HIST-L4 — the dependency cache accepted a POISONED entry, permanently

**Type: SILENT WRONG ANSWER — the worst class in this file. It did not lose
coverage, it lost a TRUE POSITIVE while reporting success. MEASURED, ROOT-CAUSED
AND FIXED.**

`install()` decided a cache hit like this:

```python
cached = cache_root / spec.key / "node_modules"
if cached.is_dir():
    _link_dir(link, cached)
    return True, "", f"cache hit {spec.key}"
```

The existence of a directory was the entire test. Nothing checked whether the
install that created it had finished, or had fetched everything. So one
incomplete install — an npm run that exited 0 without retrieving a git
dependency, or an install interrupted between `shutil.move` and completion —
is written into the cache and returned as a successful hit **forever**, because
nothing ever re-checks it.

**How it surfaced.** `tests/test_realworld_reserve.py` failed on the assertion
it exists to make:

```
E  AssertionError: the known TRUE POSITIVE (Rule 5, try/catch removal in
E  ActFacet.sol at e27227b2) did not fire - a fix that silences real findings
E  is not a fix
```

The false-positive half still passed. Only the true-positive half caught it,
which is precisely why that half was written.

**Evidence.** The cached entry for reserve-protocol's dependency set held **900
packages and was missing 3**, one of them `@reserve-protocol/trusted-fillers` —
a GitHub dependency (`github:reserve-protocol/trusted-fillers#a3fdf80…`) that
every `ActFacet.sol` compile needs transitively through `DutchTrade`. solc's
error named the symptom and hid the cause:

```
Source "@reserve-protocol/trusted-fillers/.../ITrustedFillerRegistry.sol"
not found: File not found. Searched the following locations: "".
```

`Searched the following locations: ""` means no remapping was emitted at all —
`derive_remaps` only emits one when the package directory exists, and it did
not. The dependency was fetchable the whole time (`git ls-remote` → exit 0);
nothing was wrong with the network when the failure was observed.

**A wrong suspect, recorded because the reasoning matters.** The obvious
candidate was WALK-L4, which had just changed `derive_remaps` to resolve
junctions. It was innocent, and the reason is structural rather than empirical:
the `pkg_dir.is_dir()` gate that decides *whether* a remap is emitted was
untouched — WALK-L4 only changed the target string for directories that already
exist. A package absent from disk produces no remap under either version. The
suspect was cleared by reading what the change could and could not affect, then
confirmed by finding the package absent from all ten cache entries.

**Fix, two parts.**
1. **Verify before caching.** After an install reports success, check that every
   package the repo's Solidity actually IMPORTS is present on disk. If any is
   missing, return `dep-missing` naming it, and cache nothing. Deliberately
   scoped to imported packages rather than all declared dependencies: requiring
   the latter would turn a perfectly usable tree into a skip over an unrelated
   devDependency.
2. **A completion marker decides cache hits.** `.chainwatch-install-ok` is
   written last, only after verification. A cache hit requires the marker. An
   entry without one is **verified in place** and marked if it turns out
   complete; if it is incomplete the run reports `dep-missing`, names the
   packages, and says which directory to delete.

**A wrong first fix, recorded because it did real damage.** The first version of
part 2 `shutil.rmtree`'d any unmarked entry — "discard rather than trust". That
deleted a 900-package tree which, with the installer broken (HIST-L5 below),
could not be rebuilt, and turned a latent fault into an acute one: the next test
run failed BOTH assertions in 65s instead of one in 1138s. A dependency tree can
cost minutes to rebuild and may not be rebuildable offline at all; destroying
one to re-derive a boolean is the wrong trade. The rule now: **verification may
read, it may not delete.** `_unlink_node_modules` follows the same rule — it
removes a reparse point and refuses to touch a real directory.

**The generalisable lesson, and it is the third variant of the same mistake in
this file.** WALK-L1 was a path-keyed cache serving stale content. HIST-L4 is a
key-existence-checked cache serving incomplete content. Both returned success.
**A cache whose hit condition is weaker than its correctness condition does not
speed a system up, it makes it wrong quietly.** The hit test must assert the
property the consumer depends on — here "complete", not "present".

---

### HIST-L5 — our own cache junction made the next install impossible

**Type: SILENT COVERAGE LOSS, and the ROOT CAUSE beneath HIST-L4. MEASURED,
REPRODUCED, FIXED.**

`install()` links `<worktree>/node_modules` at the cached tree with an NTFS
junction — the optimisation that lets thirty commits share one install. That
junction **survives into the next install attempt**, and an installer cannot
populate a reparse point. Yarn Berry fails its entire link step on it:

```
➤ YN0000: ┌ Link step
➤ YN0001: │ Error: While persisting .../@aave/periphery-v3/ ->
    .../prev/node_modules/@aave/periphery-v3
    ENOTDIR: not a directory, mkdir '...\prev\node_modules'
➤ YN0000: · Failed with errors in 2s 644ms
```

Remove the junction and the identical command, in the identical tree, succeeds:

```
➤ YN0000: ┌ Link step
➤ YN0000: └ Completed in 1m 21s
➤ YN0000: · Done with warnings in 1m 23s
```

**This is the cause of the other two.** A partially-linked tree left behind by a
failed install is what HIST-L4 then cached and trusted forever, and it is why
the retry chain never recovered: HIST-L3's stale `--ignore-scripts` fallback
could not have worked either, so the failure looked like a dependency problem in
the *target repository* rather than a defect in *our own scratch state*.

**Fix.** `_unlink_node_modules(link)` runs before any installer, removing a
junction or symlink — and refusing to touch a real directory, so it can never
destroy a legitimate tree. The install then starts from the state a human would
have had.

**Why nothing caught it for so long.** The FP1-FP6 loop, every earlier
trajectory run, and the 25-pair stress run all executed against a cache entry
that had been populated *once*, successfully, before any junction existed. The
defect only appears on the second install for a given dependency set — which
happens the first time a cache entry is missing or invalidated. Every green run
this project has ever recorded was, in this respect, a first run.

**The lesson, and it is the same one three times now.** WALK-L1: a path-keyed
cache served stale content. HIST-L4: an existence-keyed cache served incomplete
content. HIST-L5: the cache's own linking mechanism broke the thing that
populates it. **Scratch state is not neutral.** Every optimisation that leaves
something behind — a memo, a directory, a link — becomes an input to the next
run, and has to be reasoned about as one.

---

### WALK-L6 — "read-only on every target" is not literally true: `git worktree` writes metadata

**Type: ACCURACY OF A STATED GUARANTEE. Not a coverage or precision defect —
a claim defect, which for this project is worse. MEASURED, then FIXED PROPERLY:
the claim was first narrowed to match the code, and the code was then changed so
the original, stronger claim is true again.**

CHARTER rule 5: *"Read-only on every external target. Never write to, push to,
commit to, or authenticate beyond public-read on any repository."*
`src/scan.py`'s docstring restated it as *"the target repository is only ever
read — `git worktree`, `git log`, `git show`."*

**`git worktree add` writes.** It creates administrative entries inside the
target repository's own `.git` directory. Measured directly, on a target
mounted read-only into the container:

```
fatal: could not create directory of '.git/worktrees/prev1': Read-only file system
```

and on a writable target, after a scan:

```
$ ls demo-repo/.git/worktrees/
cur  head  prev
```

**What is and is not true, precisely.** Chainwatch does not modify a target's
CONTENT, index, branches, or HEAD; it never commits, pushes, or authenticates.
Verified after a full scan: `git status --short` is empty and HEAD is unchanged.
What it does write is worktree bookkeeping under `.git/worktrees/`, and those
entries are removed when the worktree is removed. So the honest phrasing is
**"never modifies a target's content or history; does create and remove git
worktree metadata inside it"** — not "only ever read".

**Why this is worth a finding rather than a footnote.** This project's entire
pitch rests on the difference between a claim that was measured and a claim that
sounded right. A read-only guarantee that is 95% true is exactly the kind of
statement the CANDIDATE cap exists to refuse elsewhere. It was also invisible
for the whole project until a *read-only mount* forced the question — the same
lesson as HIST-L5: our own scratch mechanism was doing something nobody had
checked.

**Fix — IMPLEMENTED.** `history.mirror_clone` makes a bare clone of the target
inside Chainwatch's own scratch directory, and `scan()` runs every worktree,
checkout, `git log`, `git diff` and `git show` against THAT. The target is
touched only by the clone and by the fetch that refreshes it on a repeat scan,
both of which read it and nothing else. `--local` hardlinks the object store
when the filesystem allows, so the cost is small; git falls back to copying by
itself when it cannot.

**Verified by the test the defect originally failed** — a target bind-mounted
**read-only** into the container:

```
BEFORE the scan:  .git/worktrees in target  ->  ABSENT
scan              -> pairs 2/2, 2 CANDIDATE findings, 8.0s   (previously: refused)
AFTER the scan:   .git/worktrees in target  ->  ABSENT       <- never written to
                  git status --short        ->  (empty)
                  HEAD                      ->  unchanged
worktrees now live at   <scratch>/wt/{prev,cur,head}
registered against      <scratch>/origin.git/worktrees/{prev,cur,head}
```

Absence, not "unchanged", is the point: there is nothing to clean up afterwards
because nothing was created.

**Two notes.** The scratch worktrees moved to `<scratch>/wt/` rather than reusing
the old flat paths, because worktrees created by earlier versions are registered
against the TARGET and reusing those names would collide with another
repository's bookkeeping. And a repository scanned by an earlier version may
still carry stale `.git/worktrees/` entries from it; `git worktree prune` in the
target clears them, but Chainwatch does not run it, because that would be the
very write this fix removed.

**Consequence for CHARTER.** Rule 5 was narrowed to match the code (commit
7165a10) before this fix landed. That narrowed wording is now weaker than the
truth: it permits a write that no longer happens. It is permissive rather than
false, so it is not urgent — but the stronger original phrasing is accurate
again and the charter can be restored to it.
