# Chainwatch

> Every other tool reports whether a contract is vulnerable **now**.
> Chainwatch reports **which commit made it vulnerable, and whether that commit
> is live on-chain.**

Chainwatch walks a Solidity repository's git history, runs nine deterministic
regression rules over every (parent, commit) pair, and reports the exact commit
where a security control was weakened or removed — with the contract, the
function, the line range, the author, whether the regression is still present at
HEAD, and (given an address) whether that code is what is deployed.

It detects **regressions**, not novel bugs: a control that existed and no longer
does. A contract that was never safe is out of scope by design — see
[CHARTER.md](CHARTER.md).

---

## Run it

```bash
python webapp/server.py            # UI on http://127.0.0.1:8000
```

```bash
python chainwatch.py --repo <path-or-url> --root contracts --limit 30
```

```bash
python chainwatch.py --repo <path> --address 0xYourProxy --json report.json
```

The web app is a thin shell over `src/scan.py` — the same engine the CLI uses,
so the two can never disagree about what a finding is. It binds to `127.0.0.1`
by default: starting a scan installs the target repo's dependencies (with
lifecycle scripts disabled) and reads its history, which is not an endpoint to
put on a network.

**Setup**

```bash
pip install -r requirements.txt && solc-select install 0.8.20 && solc-select use 0.8.20
```

---

## What it detects

| Rule | OWASP | Regression |
|---|---|---|
| 1 | SC01 | access-control constraint on `msg.sender` removed |
| 2a | SC08 | reentrancy mutex removed |
| 2b | SC08 | CEI ordering broken (state write moved across an external call) |
| 3a | SC10 | upgrade authorization weakened |
| 3b | SC10 | initializer became re-callable |
| 3c | SC10 | storage layout collision on a proxy-deployed contract |
| 4 | SC09 | overflow protection removed (`unchecked`, SafeMath, pragma lowered) |
| 5 | SC06 | external-call return value no longer checked |
| 6 | SC05 | input-validation `require` removed |

Every rule is semantic — Slither AST/IR and data-dependency analysis. No regex
on source, no modifier **name** matching (name matching is the single largest
false-positive source in this class of tool).

---

## How to read a result

**Coverage comes before findings, always.** A scan that could only analyse 3 of
40 commit pairs reports zero findings, and so does a scan of a clean repository.
Both the CLI and the UI print the analysed/skipped ratio with a per-skip reason
above the findings, and say so explicitly when the history was not fully seen.
A quiet result over an unanalysed commit means *unmeasured*, not *safe*.

**Three verdicts** (`RULES.md`, implemented in `src/verdict.py`):

- **DISCARDED** — an exclusion matched. Never surfaced.
- **CANDIDATE** — the trigger fired and no exclusion matched, but at least one
  of the six required evidence fields is missing.
- **CONFIRMED** — all six present, and liveness is LIVE.

The six fields are: regression commit (hash/author/date/line range), pre-state,
post-state, reachability (externally callable, state-changing, **and still
present at HEAD**), no compensating control, and on-chain liveness.

One consequence is worth stating plainly, because it surprises people: **a
repo-only scan with no `--address` produces zero CONFIRMED findings.** Liveness
is one of the six. A regression in git that is not the code holding funds is a
CANDIDATE, and calling it more than that would be the exact overclaim this
project exists to avoid.

---

## Precision discipline

- `fixtures/` and its 13 sibling sets are frozen ground truth, hash-guarded by
  `./guard.sh check`. If a check fails, the logic gets fixed — never the test.
- `python scorer.py --fixtures <set>` enforces **precision = 1.00** (zero false
  positives) and recall ≥ 0.70 per shipped rule, on all 14 sets.
- `python scorer.py --empty-detector` proves the scorer can fail.
- `tests/test_attribution.py` proves every fire is attributable to a real
  declaration, and that a quiet rule emits nothing.
- `tests/test_realworld_reserve.py` re-measures the six false positives found
  on a real repository (reserve-protocol) — five must stay quiet, and the one
  that was never an FP must still fire. A fix that silences everything fails
  this test.

Every rule's known blind spots are recorded per rule in
**[LIMITATIONS.md](LIMITATIONS.md)**. Two worth knowing before reading any
result:

- Rule 3c proves a contract was *written* to sit behind a proxy, not that it
  *does*. On-chain liveness is what closes that gap.
- Rules 3b and 3c cannot fire on ERC-7201 namespaced storage in the general
  case (the OpenZeppelin 5.x default). On such repos a quiet result from those
  two rules means *unmeasured*, not *safe*.

---

## Scope

Chainwatch does **not** fuzz, symbolically execute, or formally verify; does not
detect novel vulnerabilities; does not generate exploit code or proof-of-concept
transactions; and never auto-discloses anything. It is read-only on every target
repository and on chain — it issues `eth_getCode`, `eth_getStorageAt` and
read-only `eth_call`, and has no code path that can send a transaction.
