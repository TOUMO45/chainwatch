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
| **CANDIDATE** | trigger matched, no exclusion matched, liveness not yet confirmed | logged for review, **not** a finding, **not** sent to LLM |
| **CONFIRMED** | CANDIDATE + all required evidence present + liveness = LIVE | finding. Only this state reaches the LLM report layer. |

**Hard rule:** the LLM never sees CANDIDATE or DISCARDED. If it never sees a
non-finding, it can never write a convincing report about one. This is the entire
false-positive defence — architectural, not probabilistic.

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

**Exclusions:**
- 3a.1 Authority moved to a timelock or multisig contract (widened in name, narrowed in practice) — CANDIDATE, needs human read
- 3a.2 Contract changed from upgradeable to immutable (upgrade path removed entirely)
- 3a.3 Test/mock path

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

# Per-rule calibration requirement

Before any rule ships, it must score against `fixtures/` with:
- **Precision = 1.00** on the frozen fixture set (zero false positives — non-negotiable)
- **Recall ≥ 0.70** (misses are acceptable, false alarms are not)
- **At least 3 negative fixtures per rule** drawn from its own exclusion set — specifically 1.2, 2.2, 3c.1, 4.5, 5.1, 6.1 are mandatory negative cases, since those are the exclusions most likely to be missed in implementation

A rule that cannot hit precision 1.00 on its own fixture does not ship. It stays
in the codebase disabled, with a note explaining why.
