# Chainwatch — RULES.md
Exact detection specifications. Companion to CHARTER.md.

**Design principle:** a rule is defined by its **exclusions**, not its trigger.
Anyone can write "detect when `onlyOwner` disappears." The tool is only worth
building because of the twelve cases where `onlyOwner` disappears and it is
*not* a vulnerability. Every exclusion below is a false positive that would
otherwise reach your report.

---

## Verdict model (applies to every rule)

Three states. Only one of them is ever shown as a finding.

| Verdict | Condition | Action |
|---|---|---|
| **DISCARDED** | any exclusion in the rule's exclusion set matched | silently logged, never surfaced, never sent to LLM |
| **CANDIDATE** | trigger matched, no exclusion matched, liveness not yet confirmed | logged for review, **not** a finding. Reaches the LLM report layer **only** through the constrained CANDIDATE template — see the amendment below |
| **CONFIRMED** | CANDIDATE + all required evidence present + liveness = LIVE | finding. Only this state reaches the LLM's full disclosure template. |

**Hard rule (original, superseded in part — retained verbatim for provenance):**

> the LLM never sees CANDIDATE or DISCARDED. If it never sees a non-finding, it
> can never write a convincing report about one. This is the entire
> false-positive defence — architectural, not probabilistic.

**AMENDMENT (2026-08-15, human-approved). Amended hard rule, verbatim:**

> The LLM never sees a **DISCARDED** verdict, and never sees raw rule output. It
> may see a **CANDIDATE** only through a template that is structurally incapable
> of asserting a vulnerability: for a CANDIDATE the document's thesis is *"this
> did not meet the bar, and here is precisely which evidence is missing."*

**What "structurally incapable" means here, and it is not a prompt
instruction.** The verdict framing is a **template wrapper the model's prose is
injected into**, never text the model is asked to produce or preserve. For a
CANDIDATE the renderer emits a hardcoded header — `NOT CONFIRMED — missing
evidence: {missing_fields}` — and the model contributes only named prose slots
inside that skeleton. The model cannot override, omit, or reword the framing,
because it never authors it. The CANDIDATE skeleton additionally has **no
severity and no impact section to fill**, so there is no slot in which
"confirmed" or "exploitable" language could legitimately land. This is the same
discipline as fact-slots in `draft_report`: facts come from code, narrative
comes from the model, and the model is never the thing standing between a
non-finding and an overclaim.

**Why the original rule's purpose survives.** Its stated purpose is that the
model can never write *a convincing vulnerability report about a non-finding*.
A template that can only produce a "not confirmed, here is the missing
evidence" dossier preserves that purpose exactly, while making the honest
negative case reportable — which is itself a product capability, not a
concession.

**Implementing spec:** `AGENT-DESIGN.md` §3 (tool `draft_report`, the
verdict-dispatched output table) and §2 (the five structural properties of the
agent boundary). Any change to the CANDIDATE template's framing is a change to
this rule and belongs here first.

**Precision-first tie-break:** when a rule is uncertain between CANDIDATE and
DISCARDED, it discards. You will miss real bugs this way. That is the correct
trade — a missed bug costs you one finding; a false finding costs you credibility
with a triage team, and credibility is the actual asset in bug bounty.

---

## Required evidence (every CONFIRMED finding carries all six)

1. `regression_commit` — hash, author, date, the exact line range changed
2. `pre_state` — the AST node proving the control existed before
3. `post_state` — the AST node proving it does not exist now (or is weakened)
4. `reachability_proof` — the function is externally callable and state-changing at HEAD
5. `no_compensating_control` — explicit proof that no other mechanism enforces the same guarantee (see per-rule exclusion sets)
6. `liveness` — deployed bytecode hash comparison result: LIVE / PATCHED / UNKNOWN

Missing any one → downgrade to CANDIDATE. No exceptions, no "confidence 0.8."

---

# RULE 1 — SC01 Access Control regression

### Trigger
A function that at commit `N-1` had an access-control constraint has none at commit `N`.

Access-control constraint means any of:
- a modifier resolving to a `require`/`revert` on `msg.sender` (`onlyOwner`, `onlyRole`, `onlyAdmin`, custom)
- an inline `require(msg.sender == X)` / `if (msg.sender != X) revert`
- an OpenZeppelin `AccessControl._checkRole` / `Ownable._checkOwner` call

Resolve modifiers **through inheritance and through the modifier body's AST** —
never by name string. Name matching is the single largest FP source in this rule.

### Exclusion set — DISCARD if any is true

| # | Exclusion | Why it's not a bug |
|---|---|---|
| 1.1 | Modifier renamed, body AST semantically identical | pure refactor |
| 1.2 | Modifier removed, equivalent `require(msg.sender...)` added inline in same function | protection relocated, not removed |
| 1.3 | Function visibility changed to `internal`/`private` in same commit | no longer externally reachable |
| 1.4 | Function became `view`/`pure` in same commit | no state change to protect |
| 1.5 | Protection moved to an upstream single entry point that is itself protected, and this function has no other external caller path | compensating control exists |
| 1.6 | File path matches test/mock/script patterns (`test/`, `mock/`, `script/`, `*.t.sol`, `*Mock*`, `*Harness*`) | not production code |
| 1.7 | Contract is `abstract` and function is overridden with protection in every concrete child | protection at the implementation layer |
| 1.8 | Contract removed from deployment path in same commit (no longer imported by any deployed contract) | dead code |
| 1.9 | The base contract providing the modifier is still inherited AND applies it via `_beforeTokenTransfer`-style hook | hook-level enforcement |
| 1.10 | Constructor or `initializer`-modified function | different rule (see Rule 3), not general access control |
| 1.11 | Access control replaced by a timelock/governance router that is itself access-controlled | control changed, not removed |
| 1.12 | Whole function deleted at commit N | nothing to exploit |

### Additional CONFIRMED requirements
- Function must be reachable at HEAD (not just at commit N — the regression must survive to today)
- Function must write state or move value (`sstore`, external call with value, token transfer)
- Slither's own `suicidal` / `arbitrary-send` / `unprotected-upgrade` detectors run at HEAD as a cross-check; disagreement → CANDIDATE, not CONFIRMED

---

# RULE 2 — SC08 Reentrancy regression

### Trigger (two independent sub-rules, report separately)

**2a — guard removed:** `nonReentrant` (or equivalent mutex: a bool/uint storage
lock set-then-cleared around the body) present at `N-1`, absent at `N`, and the
function still contains an external call.

**2b — CEI ordering broken:** at `N-1` all state writes to variables read by the
function preceded every external call; at `N` at least one such write moved after
an external call. This requires control-flow ordering, not text diff — use
Slither's IR ordering.

### Exclusion set — DISCARD if any is true

| # | Exclusion | Why it's not a bug |
|---|---|---|
| 2.1 | No external call remains in the function at commit N | nothing to re-enter through |
| 2.2 | Guard removed but CEI ordering is provably correct (all state writes precede all external calls) | CEI is a valid alternative defence |
| 2.3 | The only external call target is an `immutable`/`constant` address set at construction to a known-trusted contract | attacker cannot control callee |
| 2.4 | External call is to a contract in the same repo with no further external calls (provably non-reentrant callee) | closed call graph |
| 2.5 | Function is `view`/`pure` at commit N | no state to corrupt |
| 2.6 | Guard moved to the sole external entry point calling this function | relocated, not removed |
| 2.7 | Call uses a hard gas stipend (`transfer`/`send`, 2300 gas) AND no state read-after depends on it | classic stipend defence — flag as INFO only |
| 2.8 | Test/mock/script path (same patterns as 1.6) | not production |
| 2.9 | The state variable written after the call is not read anywhere in the reachable re-entry path | no exploitable inconsistency |
| 2.10 | Read-only reentrancy where no external protocol reads this contract's view functions | needs judgment — downgrade to CANDIDATE, do not auto-confirm |

**Note on 2.10:** read-only reentrancy is real and has caused large losses, but
proving a *third-party* protocol reads your view function during the window is
outside a single-repo tool's knowledge. Cap it at CANDIDATE permanently.

---

# RULE 3 — SC10 Proxy & Upgradeability regression

Highest-value rule: SC10 is new in the 2026 list and ranked critical. Three sub-rules.

### 3a — Upgrade authorization weakened
**Trigger:** the access constraint on `_authorizeUpgrade`, `upgradeTo`,
`upgradeToAndCall`, or the proxy admin setter changed such that the caller set widened.

Two structurally distinct ways a commit satisfies this trigger, implemented
as two independent checks (`src/rules/rule3a.py`), reported via a `"trigger"`
evidence discriminator:

- **`constraint-removed`** (original). Every msg.sender-dependent guard on the
  target function disappears outright.
- **`caller-set-widened`** (3a-L2, closed 2026-08-26). A msg.sender check
  *survives*, but what it compares against does not: `onlyOwner` replaced by
  an inline `require(msg.sender == admin)` looks like a lateral refactor, but
  if `admin` has no protection of its own — any unguarded function can set it
  — the caller set is unrestricted in practice, identically to deleting the
  modifier. Detected by reusing Rule 10's own gate-variable classification
  (`_classify`): the comparison target is "illusory" iff it has a genuinely
  unguarded run-time writer, checked at both commits (must be absent at N-1,
  present at N — an already-illusory target is not a regression introduced
  by this commit). Single-hop only, matching Rule 10's own scope boundary:
  a target's writer that is ITSELF msg.sender-gated is never chased
  transitively for whether THAT gate is in turn illusory. See LIMITATIONS.md
  §3a-L2 for the fixture set and §3a-L4 for a real, pre-existing reachability
  gap this trigger surfaced (not caused): `_authorizeUpgrade` is `internal`
  by UUPS's own design, so a finding on it — from EITHER trigger — currently
  cannot reach CONFIRMED; `upgradeTo`/`changeAdmin`/`changeProxyAdmin` are
  unaffected.

**Exclusions:**
- 3a.1 Authority moved to a timelock or multisig contract (widened in name, narrowed in practice) — CANDIDATE, needs human read. Also covers `caller-set-widened`: a comparison target whose only writer is itself msg.sender-constrained, or written exactly once (constructor / `initializer`-guarded, the same shape OpenZeppelin's own `_owner` uses), is never illusory.
- 3a.2 Contract changed from upgradeable to immutable (upgrade path removed entirely)
- 3a.3 Test/mock path

**Known residual (honestly not closed):** `caller-set-widened` only examines
guards that compare msg.sender against a STATE VARIABLE. A near-tautological
guard like `require(msg.sender != address(0))` — msg.sender-dependent, but
reads no state variable at all — is invisible to this trigger exactly as it
was before 3a-L2. No fixture exercises it. Tracked in TODO.md.

### 3b — Initializer re-callable
**Trigger:** a function that sets ownership/admin/critical config lost its
`initializer` modifier, or the `_disableInitializers()` call in the constructor was removed.

**Exclusions:**
- 3b.1 `reinitializer(n)` used instead — intentional versioned re-init
- 3b.2 An explicit `initialized` bool guard added manually in the same commit
- 3b.3 The function became `internal` and its only caller is itself guarded
- 3b.4 DISCARD only if the contract is provably never deployed behind a proxy (no
  proxy in the repo references it). `_disableInitializers()` alone is NOT grounds
  for discard - it protects the implementation contract's own storage, not the
  proxy's storage, which is where real state lives. A missing `initializer` on a
  proxied contract is exploitable regardless. (Corrected during Phase 2 human
  review: the original wording would have caused a silent false negative on
  fixture P3b-01.)

### 3c — Storage layout collision
**Trigger:** in an upgradeable contract, an existing storage variable's slot index
or type changed between commits (insertion, reordering, or type-width change).

**Exclusions:**
- 3c.1 Variable appended strictly after all existing ones (safe pattern)
- 3c.2 Change consumes a declared `__gap` array with matching size reduction
- 3c.3 Contract is not actually behind a proxy (no proxy references it) — this is the key exclusion; a layout change in a non-upgradeable contract is meaningless
- 3c.4 `constant`/`immutable` variables (no storage slot)

**This sub-rule needs a real storage-layout comparator** (`solc --storage-layout`
at both commits, compare slot-by-slot), not AST heuristics.

**Known blind spots:** see [LIMITATIONS.md](LIMITATIONS.md) — exclusion 3c.3 proves intent to be proxied, not the fact of it, and ERC-7201 namespaced storage (OZ 5.x default) defeats slot comparison silently.

---

# RULE 4 — SC09 Integer Overflow/Underflow regression

### Trigger
- `unchecked { }` block added around arithmetic that was previously checked, **or**
- SafeMath usage removed on solc `<0.8.0`, **or**
- pragma lowered from `>=0.8.0` to `<0.8.0` (removes global checks — rare but catastrophic)

### Exclusion set — DISCARD if any is true

| # | Exclusion | Why it's not a bug |
|---|---|---|
| 4.1 | `unchecked` wraps a loop counter with a bound provably `< type(uintN).max` | standard accepted gas optimisation — **the trap that will hurt you most; get this right** |
| 4.2 | A `require()` bounding the operands exists earlier in the same function | checked manually |
| 4.3 | Operands are of a type where the operation cannot overflow (e.g. `uint256 a - b` guarded by prior `require(a >= b)`) | provably safe |
| 4.4 | Subtraction where the minuend is provably ≥ subtrahend via a preceding balance check | provably safe |
| 4.5 | SafeMath removed *and* pragma raised to ≥0.8.0 in the same commit | migration to built-in checks — the most common FP in this rule |
| 4.6 | Test/mock path | not production |

**4.5 deserves emphasis:** thousands of repos removed SafeMath when upgrading to
0.8.x. If your rule fires on those, it produces noise on nearly every mature
Solidity repo in existence and the tool is unusable. Pragma-aware analysis is
mandatory, not optional.

---

# RULE 5 — SC06 Unchecked External Calls regression

### Trigger
Return value of `.call()`, `.delegatecall()`, `.staticcall()`, `.send()`, or a
raw ERC20 `transfer`/`transferFrom` was checked at `N-1` and is not at `N`.
Also: `try/catch` around an external call removed.

### Exclusion set
- 5.1 Call wrapped in `SafeERC20` (`safeTransfer` etc.) at commit N — checking is internal to the library
- 5.2 Return value assigned and checked later in the function or by the caller
- 5.3 Failure is provably intentional and non-security-relevant (e.g. best-effort notification hook) — **CANDIDATE only, human decides**
- 5.4 The call is to a known non-reverting target (`address(this)`, precompile)
- 5.5 Solidity version where the call auto-reverts (high-level typed call to a contract with a checked interface)
- 5.6 Test/mock path

---

# RULE 6 — SC05 Input Validation regression

### Trigger
A `require()` / `revert` / custom-error guard on a function *parameter* (not on
`msg.sender` — that's Rule 1) present at `N-1`, absent at `N`.

Track specifically: zero-address checks, zero-amount checks, array-length equality
checks, bounds/range checks, deadline checks, slippage-minimum (`minAmountOut`) checks.

### Exclusion set
- 6.1 Check moved into a modifier applied to the same function
- 6.2 Check enforced downstream in a function this one always calls, on the same value, before any state change
- 6.3 The parameter was removed entirely
- 6.4 Type change makes the check redundant (e.g. `uint256` → `uint8` bounding a range)
- 6.5 Check replaced by an equivalent custom error with the same condition — semantic compare, not text compare
- 6.6 Enforced by the type system or a validated struct at the call boundary
- 6.7 Test/mock path

**Highest-severity sub-case, always CONFIRMED if it survives exclusions:**
removal of a slippage/`minAmountOut` or deadline check on a swap path. These map
directly to real 2025-2026 loss events and are unambiguous when genuinely absent.

---

# RULE 10 — SC01 Control migrated to an unguarded entry point

Closes LIMITATIONS.md §RC-RENAME1. Implemented in `src/rules/rule10.py`, locked
by `fixtures-r10/`.

### Why this is not a diff rule

Rules 1–9 match a function across commits by `(contract, name)` and ask what
that function **lost**. That is structurally incapable of seeing a control that
**moved**. In the motivating case (88mph `contracts/NFT.sol` `a4c48d61`) the
constructor is deleted and an unguarded `init()` appears: there is no `init` at
N-1 to diff against, and the N-1 protection was the *constructor mechanism
itself* — one-shot and deployer-only, enforced by the EVM rather than by any AST
node a rule inspects.

Rule 10 therefore **inverts the matching direction** and keys on the contract's
external surface rather than on per-function name matching.

### Trigger

For each contract present at both commits, and each **gate variable** `v` of it,
all three must hold:

| | Condition | What it encodes |
|---|---|---|
| **T1** | at N-1, `v` had at least one *one-shot* writer — a constructor **anywhere in the inheritance chain**, or a function carrying a one-shot init guard | a control existed |
| **T2** | at N-1, `v` had **no** unguarded run-time writer | that control was the only run-time story |
| **T3** | at N, `v` **has** an unguarded run-time writer | the control broke |

**T2 is what makes this a regression rule.** A contract that already had an
unguarded writer was never safe, and CHARTER.md puts "a contract that was never
safe" out of scope by definition. Reporting current state is Slither's job;
claiming it here would be the "Slither with extra steps" failure the charter
names. Locked by `fixtures-r10/negative/N10-05`.

**"Unguarded run-time writer"** means a function that writes `v` and is: not a
constructor, not one-shot-guarded, does not constrain `msg.sender`, and is
externally reachable (directly, or internal with at least one unguarded external
caller).

### `gate_vars` — the variable set the trigger ranges over

State variables that an access-control decision actually **reads**: for every
guard node that depends on `msg.sender`, the node's own state reads **plus the
state read by functions that node invokes** (one call-hop resolution).

The call-hop is not optional. OZ 4's `onlyOwner` reaches `_owner` through
`_checkOwner() → owner()`, so the guard node itself reads **no state variable at
all** and a node-local definition returns the empty set — measured, see
LIMITATIONS.md §R10-M2.

Deliberately tighter than `_shared.access_control_state_vars`, which returns
everything read by a function that merely *has* a msg.sender guard (so
`onlyOwner setFee()` would contribute `_fee` as well as `_owner`). Measured
difference on the real 88mph contract: 5 variables vs 6.

### Exclusion set — DISCARD if any is true

| # | Exclusion | Why it's not a bug |
|---|---|---|
| 10.1 | New writer carries a one-shot init guard (`initializer`, `reinitializer(n)`, or an inline set-once flag) | still one-shot, not freely callable |
| 10.2 | New writer constrains `msg.sender` | protection relocated, not removed |
| 10.3 | File path matches test/mock/script patterns (segment-matched) | not production code |
| 10.4 | Declaration is not in a file this commit actually changed | DESIGN-L2 phantom-attribution guard |
| 10.5 | Writer is internal/private and every external caller is itself guarded | not externally reachable |
| 10.6 | The written variable is not a gate variable | no security control is involved — this is what keeps an ordinary new setter, and a renamed getter, quiet |
| 10.8 | The unguarded writer at N has a **same-named** counterpart at N-1 that also wrote this gate variable | the function survived and lost a guard — Rule 1 / Rule 3b territory, not a migration |

**10.8 is the rule boundary and is not cosmetic.** Without it Rule 10 co-fires
on every Rule 3b positive (measured on `fixtures/` P3b-01 and P3b-02, where
`initialize` exists at both commits and merely drops its `initializer`
modifier). The underlying regression there is real, but it is already owned:
**Rule 3b owns "the guard left the function"; Rule 10 owns "the responsibility
left the guarded function."** Matching is by NAME rather than full signature —
the more suppressive choice, per the precision-first tie-break.

### 10.7 — value-holding variables: NOW IN SCOPE, with one stated limit

**CLOSED.** The trigger ranges over `gate_vars ∪ value_vars`. T1/T2/T3 and every
exclusion are unchanged — this was purely a widening of *which variables* the
rule considers, which is why it extends Rule 10 rather than shipping as a
separate rule.

A **value variable** is one that receives funds, determined structurally: a
native value-moving operation (`Transfer`, `Send`, or a `LowLevelCall` carrying
a call value) sends to a destination that is data-dependent on it. Naming it
`treasury` counts for nothing — name matching is the exact blind spot
RC-RENAME1 documents, and re-introducing it here would be a poor trade.

`fixtures-r10v/negative/N10v-03` is what makes the definition testable: an
`oracle` address migrated in exactly the positive's shape, only ever *read*
through `IOracle(oracle).price()`. Address-typed, unguarded, and it must stay
quiet — so an implementation that treated every address-typed state variable as
value-holding fails there while passing everything else.

Findings carry `variable_class: "gate" | "value"` so the two are never conflated
downstream.

**ERC20 recipients now count**, by ARGUMENT POSITION on exactly two methods:
`transfer(to, amount)` → argument 0, `transferFrom(from, to, amount)` →
argument **1**. Names come from `_shared.ERC20_RETURN_FNS`, which Rule 5 already
depends on, so no new convention is introduced.

Widening brought three false-positive risks native-only never had, each locked
by its own negative:

| risk | why it is not a treasury | fixture |
|---|---|---|
| `approve(spender, amount)` | names a SPENDER, not a destination; no value moves to it, and approving a DEX router is routine | `N10e-01` |
| `transferFrom` argument 0 | that is the SOURCE — value moves AWAY from it | `N10e-02` |
| every other ERC20 method | `balanceOf`, `allowance` and friends are reads | `N10e-03` |

**SafeERC20 wrapper transfers now count too** — `safeTransfer`/`safeTransferFrom`
via `using SafeERC20 for IERC20`, the pattern Reserve uses throughout. These
compile to a `LibraryCall`, not a `HighLevelCall`, so the branch above never
sees them; matched separately via `_shared.SAFE_ERC20_DEST_POS`. Measured (not
assumed) against a real Slither parse: the `using` receiver rides as the
LibraryCall's own `arguments[0]`, so every destination position shifts by one
relative to the raw calls above — `safeTransfer(token, to, amt)` → argument
**1**, `safeTransferFrom(token, from, to, amt)` → argument **2**. Two more
negatives lock the SafeERC20-side risks: `safeApprove` is not in the position
table at all (`N10se-01`, the SafeERC20 counterpart of `N10e-01`), and
`safeTransferFrom`'s SOURCE is argument 1 in the shifted scheme, not argument 0
(`N10se-02`, the shift-aware counterpart of `N10e-02`).

### Additional CONFIRMED requirements

Unchanged from every other rule: the six evidence fields, and liveness = LIVE.
The rule concludes `severity_hint = CONFIRMED`; `src/verdict.py` still caps the
verdict at CANDIDATE when liveness is absent. On the 88mph re-run with no
address supplied, the finding is correctly a CANDIDATE.

---

# CAPABILITY 13 — Live one-shot-exposure probe

Added 2026-08-26. Implemented in `src/exposure.py`, wired into `scan.py`'s
`_check_exposure`, locked by `tests/test_exposure.py`. **Not a rule** — it
produces no finding, carries no verdict, and never touches the six-field
CONFIRMED/CANDIDATE evidence model above. It is a second, independent,
present-tense question, answered separately and reported in its own section
(`report["exposure"]`, never `report["findings"]`).

### The question this answers, and why it's a different one

Rule 3b asks a HISTORICAL, source-diff question: *was a one-shot init guard
ever removed across two commits.* This capability asks a LIVE, deployed-state
question: *for a one-shot init guard that Rule 3b would recognise as real and
intact right now, has anyone actually consumed the one-shot window yet?* A
contract can be exposed here with a perfectly clean Rule 3b history — the
guard was never removed, it simply was never called. This is the mechanism
behind a real, currently active 2026 attack class: automated scanners hunt
continuously for freshly-deployed-but-not-yet-initialized proxies (and
EIP-2535 Diamond facets, which carry the same shape) and race the legitimate
deployer to call the initializer first, planting a dormant backdoor. Kinto
Protocol ($1.55M) is the named 2025 case still cited in 2026 write-ups; a
broader "Uninitialized Proxy Campaign" put losses at $10M+ across protocols.
Chainwatch had zero coverage for this class before this capability existed.

### Method

Exactly the technique this project used, by hand, to verify the real 88mph
`NFT.init()` regression is still callable on real mainnet contracts
(2026-08-26, see TODO.md and LIMITATIONS.md §11-L1): a real, read-only
`eth_call` simulating the call, from an arbitrary address, with safe non-zero
dummy arguments matching the function's own ABI signature. Never a guess at
exploitability — a direct, verified answer from the chain itself. Never a
real transaction (CHARTER rule 5): `eth_call` cannot mutate state, cost gas,
or be mined.

1. **Candidate identification** (`exposure.find_candidates`) — reuses Rule
   3b's own `_contract_initializer` unchanged: `has_init_guard(fn) and
   _sets_critical_config(fn, contract)`. Same criteria, same trust level,
   deliberately not reimplemented.
2. **Calldata construction** (`exposure.build_probe_calldata`) — ABI-encodes
   safe, non-zero dummy arguments for the function's real parameter types.
   Supports `address`, `bool`, `string`, `bytesN` (1–32), and `uintN`/`intN`.
   Refuses (returns `None`, reported as `UNKNOWN`, never a guess) on arrays,
   tuples/structs, and dynamic `bytes` — a narrower type set than a rule's
   evidence model needs, because a wrong guess here would misreport
   exploitability, not just miss a regression.
3. **Non-zero dummy values are deliberate**, not incidental: an all-zero
   `address` argument could trip an unrelated `require(x != address(0))` and
   be misread as the one-shot guard itself firing — exactly the failure mode
   a naive probe would hit. Locked by
   `test_probe_sends_nonzero_address_argument`.
4. **The probe** (`exposure.probe`) — one `eth_call`. Does not revert → OPEN
   (verified exploitable right now). Reverts → CLOSED (consistent with
   already-consumed, though not general proof of safety — an unrelated
   `require` could also revert). Calldata could not be built, or the RPC call
   itself failed → UNKNOWN, never silently reported as CLOSED.

### Scope, stated plainly

- **CLI**: `--check-exposure`, requires `--address`. Off by default.
- **Files checked**: only files this scan already produced a finding on
  (`_check_exposure` iterates `{f.file for f in findings}`), not a whole-repo
  compile — a file with no finding was never established as in-scope the way
  a changed-file set establishes it elsewhere in this project.
- **Single-address assumption, inherited, not new**: every candidate found
  across every finding file is probed against the one `--address` given.
  Correct for a single-contract investigation (every real scan this project
  has run so far); silently wrong for a multi-contract repo where a
  different finding file belongs to an unrelated contract with its own
  address. `_attach_liveness` (capability 11) has had the identical
  assumption since it was written; this capability doesn't introduce it.
- **Not yet verified against a live OPEN or CLOSED result through the CLI
  flag itself** — the mechanism, candidate-identification, and calldata
  construction are each independently verified (against the real 88mph
  signature, a real compiled OZ `Initializable` fixture, and the exact
  `eth_call` idiom already proven live this session), and the full pipeline
  is verified not to crash against a real repo+address (88mph, correctly
  returns empty — no OZ-guarded candidate exists there, Rule 10 owns that
  contract's exposure instead). A live positive/negative example through
  `--check-exposure` specifically is the natural next verification step, not
  yet done. Tracked in TODO.md.

---

# CAPABILITY 14 — Read-only exploitability proof (access-control class)

Added 2026-08-26, the same session as a direct user request for a genuine
proof-of-concept capability, weighed explicitly against the CHARTER anti-goal
"generate exploit code, calldata, or working proof-of-concept transactions...
This holds even in the LLM report layer" (see the anti-goals section). The
user chose the narrowest of three offered scopes: a read-only exploitability
proof, never a working exploit handed to anyone, never touching the LLM
report layer's own exploit-material gate. Implemented in
`src/exploit_proof.py`, wired into `scan.py`'s `_attach_exploit_proof`,
locked by `tests/test_exploit_proof.py`. **Not a rule and not a seventh
evidence field** — it never touches `verdict.classify()` and is stored on
each `Finding.exploit_proof`, deliberately parallel to `liveness_reason`.

### The question this answers

For a CONFIRMED, LIVE finding, does the SPECIFIC regression this finding
reports still hold, checked against real chain state rather than inferred
from the diff? Answered only for the rule classes where "an unprivileged
call succeeds" IS the vulnerability — rules 1, 3a, 3b and 10 (10's
"unguarded run-time writer" is structurally the same one-shot-established-
then-unguarded shape as 3b, one level more general — and is the exact rule
the real 88mph `NFT.init()` regression fires under, RC-VERDICT2) — because
those are the only shapes a single read-only `eth_call` can honestly settle.
Every other shipped rule (2a/2b reentrancy, 4 overflow, 5 external-call-
check, 6 input-validation, 3c storage collision) reports `NOT_APPLICABLE`,
never a generic reachability guess — see
`src/exploit_proof.py`'s module docstring for the per-rule reasoning. A
finding outside CONFIRMED (i.e. any CANDIDATE) is always `NOT_APPLICABLE`
too: probing a CANDIDATE's missing evidence would paper over the gap rather
than settle it.

### Method

Reuses capability 13's `exposure.probe`/`build_probe_calldata` unchanged —
one real, read-only `eth_call` to the exact function this finding names, from
a dummy sender (`0x2222...2222`, deliberately distinct from capability 13's
own `0x1111...1111` so a report running both shows two independent senders
agreeing) with no relationship to the contract. Does not revert → **OPEN**:
this exact regression is proven callable right now, observed directly
against real deployed bytecode, not inferred. Reverts → **CLOSED**:
inconclusive, NOT a safety claim — the CONFIRMED verdict already rests on
byte-exact liveness comparison (capability 11), stronger evidence than one
dummy-argument call, so a revert here may simply be an unrelated `require`
rather than the removed control being intact. Calldata unbuildable, or no
signature/address on the finding → **UNKNOWN**, same "never a guess"
discipline exposure.py already applies.

### Why this stays inside the CHARTER, stated explicitly

The banned things are exploit CODE, CALLDATA, or working PoC TRANSACTIONS —
artifacts a reader could take and run against a live contract to move funds.
This capability produces none of those: the "calldata" it builds is consumed
internally by one `eth_call` and never rendered to a user as a usable
payload; no transaction is ever signed, broadcast, or capable of mutating
state; and the LLM report layer's own exploit-material gate
(`agent/verify.py`'s `_EXPLOIT` regex) is untouched — this module's evidence
strings ("simulated call... did NOT revert") do not match it, and were
checked not to. What is produced is a FACT about the deployed contract,
gathered the same way capability 11's liveness and capability 13's exposure
probe already gather facts: read-only chain state, never a script handed to
a reader.

### Scope, stated plainly

- **CLI**: `--check-exploit-proof`, requires `--address`. Off by default —
  spends one real RPC call per CONFIRMED access-control finding.
- **Web UI**: a checkbox next to capability 13's, off by default; the result
  shows as a badge on the finding row and its own drawer section.
- **Agent layer**: `agent/store.facts()` and `agent/templates._fact_block`
  expose it as a CODE-rendered fact (never model-authored), so a generated
  dossier can cite the proof without inventing exploit language of its own.
- **Not yet verified against a real live OPEN result** — `prove()` is fully
  unit-tested against a stub RPC (9 tests: scope gating for every rule id,
  both non-eligible rules and the CONFIRMED-only gate, missing signature/
  address, OPEN/CLOSED/UNKNOWN outcomes, the distinct-sender guarantee), and
  it calls capability 13's own already-live-proven `probe()` unchanged. A
  real end-to-end run against a real CONFIRMED+LIVE finding (the natural
  next check is the 88mph regression this project has anchored on all
  session, once a matching access-control-class finding is confirmed there)
  is the natural next verification step, not yet done. Tracked in TODO.md.

---

# CAPABILITY 12 addendum — ranking wired to the web UI (2026-08-26)

`agent/tools.rank_findings`/`verify_ranking` existed from capability 12's
original build but had no caller: `generate_report`'s entry point only ever
sent ONE finding id, so the ranking tools were reachable in principle and
exercised by nothing. Closed by adding `agent/tools.save_ranking` (same
mechanical-gate-then-persist discipline as `save_report`), a dedicated
`RANKING_INSTRUCTION` and `agent/runner.generate_ranking`, and
`POST /api/scan/{id}/rank` / `GET /api/scan/{id}/rank` in `webapp/server.py`.
Same hard limits as every other agent-layer capability: the model orders,
it never re-grades a verdict, and every rationale is checked against the
same fact-citation gate a dossier's prose is checked against
(`agent/verify.py`, unmodified). Available in the web UI once at least two
CONFIRMED findings exist in a scan.

---

# Rules deliberately NOT built (state this in your README — it reads as maturity)

| OWASP cat. | Why no deterministic rule |
|---|---|
| SC02 Business Logic | Requires knowing intended economic behaviour. No diff pattern exists. LLM layer may *comment*, never *detect*. |
| SC03 Price Oracle | Staleness/deviation-bound removal is detectable (borderline Rule 6 variant), but "is this oracle manipulable" needs protocol context. Cap at CANDIDATE. |
| SC04 Flash Loan | Not a single-commit regression at all — it's a chaining amplifier across SC02/SC03/SC07. No commit "introduces" it. |
| SC07 Arithmetic Errors | Rounding-direction changes are detectable but whether a change favours the protocol or the attacker requires economic reasoning. CANDIDATE ceiling. |

---

# Cross-rule arbitration

When two rules fire on the same commit:
- Report **one** finding with the highest-severity rule as primary, others as contributing factors. Never split one regression into three findings — that's inflation and triage teams notice.
- If Rule 1 and Rule 3a both fire, it is a Rule 3a finding (proxy takeover subsumes function-level access control).
- If Rule 2 and Rule 5 both fire, it is likely a single reentrancy finding — merge.
- Rule 10 vs Rules 1/3b is settled **inside Rule 10** by exclusion 10.8, not by arbitration after the fact: if the unguarded writer at N already wrote the same gate variable under the same name at N-1, the function survived and lost a guard, which is Rules 1/3b territory and Rule 10 stays quiet. Arbitration cannot fix this after the fact, because both findings would be true — the boundary has to be a trigger condition.

# Per-rule calibration requirement

Before any rule ships, it must score against `fixtures/` with:
- **Precision = 1.00** on the frozen fixture set (zero false positives — non-negotiable)
- **Recall ≥ 0.70** (misses are acceptable, false alarms are not)
- **At least 3 negative fixtures per rule** drawn from its own exclusion set — specifically 1.2, 2.2, 3c.1, 4.5, 5.1, 6.1 are mandatory negative cases, since those are the exclusions most likely to be missed in implementation

A rule that cannot hit precision 1.00 on its own fixture does not ship. It stays
in the codebase disabled, with a note explaining why.
