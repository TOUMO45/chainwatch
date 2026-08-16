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
python chainwatch.py --from-json report.json --generate-reports   # no re-scan
```

The web app is a thin shell over `src/scan.py` — the same engine the CLI uses,
so the two can never disagree about what a finding is. It binds to `127.0.0.1`
by default: starting a scan installs the target repo's dependencies (with
lifecycle scripts disabled) and reads its history, which is not an endpoint to
put on a network.

### Generating a dossier (capability 12)

```bash
python chainwatch.py --repo <path> --root contracts --generate-reports
```

or click **Generate report** on any finding in the web UI. The agent may only
read a finished finding record through six tools; it cannot analyse, cannot
reach a chain or a repository's source, and cannot change a verdict. Every
document it produces is re-verified mechanically against the finding record
before it is written — a draft citing a commit hash, address, path or line that
is not in the record is refused, not corrected.

Needs `GEMINI_API_KEY` in `.env`. **The deterministic engine never needs one**;
a scan is complete and unaffected without it. The free tier allows 15 model
requests per minute and one dossier costs several, so the runner paces itself
and reports when it is waiting. Moving to a paid tier is a config change
(`--rpm`), not an architecture change.

### Container

```bash
docker build -t chainwatch .
docker run -p 8080:8080 -e GEMINI_API_KEY=... -v /path/to/repo:/repos/target chainwatch
```

**Status: containerized and locally verified; Cloud Run deployment pending.**
The image carries the whole product — engine, scan pipeline, web app and agent —
and has been built and smoke-tested locally end to end: `scorer.py` passes a
frozen fixture set *inside* the container, a mounted repository scans to two
attributed CANDIDATE findings, and the agent drafts a verified dossier. What has
**not** happened is a deploy to Google Cloud Run; that needs a project and
credentials this machine does not have.

The API key is never baked into the image — no `ARG`, no `ENV`, and `.env` is in
`.dockerignore`. It is injected at run time (`-e` locally, Secret Manager on
Cloud Run). Verified: `docker history` contains no key material and the image's
`Config.Env` carries only `PATH`, `LANG`, `PYTHON_*` and `PORT`.

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
- `tests/test_agent_tools.py` proves the agent's hallucination gate by feeding
  it drafts that must be rejected: an invented commit hash, an invented address,
  an invented source path, an out-of-range line, an invented `Contract.function`,
  three overclaim phrasings, a stripped header, and exploit material. A gate that
  has never rejected anything is not known to work.
- `tests/test_verdict.py` pins the classifier, including that a rule's CANDIDATE
  ceiling can never be raised by complete evidence.

**Coverage is repo-dependent and reported as such.** On a modern window of
reserve-protocol every commit pair analysed; on a 25-pair walk into that same
repo's older history only **5 of 72 file comparisons completed (6.9%)**, because
57 of them pin exact compiler versions that were not installed. That number is
printed, not hidden — see `HIST-L2` in LIMITATIONS.md. A finding count is only
meaningful next to it.

Every rule's known blind spots are recorded per rule in
**[LIMITATIONS.md](LIMITATIONS.md)**. Two worth knowing before reading any
result:

- Rule 3c proves a contract was *written* to sit behind a proxy, not that it
  *does*. On-chain liveness is what closes that gap.
- Rules 3b and 3c cannot fire on ERC-7201 namespaced storage in the general
  case (the OpenZeppelin 5.x default). On such repos a quiet result from those
  two rules means *unmeasured*, not *safe*.

---

## What has and has not been demonstrated

The project's own charter set seven success criteria. Six are met. The seventh
is not, and it is recorded as a **scope finding rather than a checkbox** — the
full reasoning, including the five disclosed-incident candidates that were
searched and rejected with reasons, is in
**[SUBMISSION-NOTES.md](SUBMISSION-NOTES.md)**. The short version, unsoftened:

> **Criterion #6 as written is unsatisfiable within responsible-disclosure
> constraints.** CONFIRMED requires `liveness == LIVE`. A regression that is live
> on-chain and not yet fixed is an undisclosed vulnerability on a funded
> contract — not something to put in public material. Responsible targets are
> already patched, so their liveness is `PATCHED` and they cap at CANDIDATE. The
> only targets that could produce a public CONFIRMED are exactly the ones it
> would be irresponsible to publish.

The real-world demonstration is therefore Reserve Protocol's
`ActFacet.revenueOverview` at commit `e27227b2` — a real repo, a real commit, a
`try/catch` removed from a function that kept its name *and* signature, attributed
to lines 117-118. It caps at **CANDIDATE** because required evidence field 4 is
*"externally callable **and** state-changing"* and the function is a view. No rule
was changed and no exception written to reach that answer; it falls out of the
model.

The honest one-line claim, recorded so public material has something to match:

> Chainwatch located the exact commit that removed a control in a real public
> protocol, attributed it to the function and line, and then **declined to call
> it CONFIRMED** because one of its six required evidence fields was not
> established.

Not *"Chainwatch found a confirmed vulnerability."* It did not, and the
distinction is the product.

Separately, capability 11 **is** proven on real mainnet data: the vulnerable
88mph NFT implementation behind three EIP-1167 clones returns **LIVE**, with
normalized runtime bytecode matching the compiled artifact exactly, and the
paired no-optimizer control returns UNKNOWN rather than guessing PATCHED. Every
surface that shows a LIVE verdict shows this with it:

> LIVE = this exact bytecode is present on-chain at this address and is what
> executes there. It does NOT mean the contract is currently reachable, funded,
> or exploitable — liveness compares code, not risk.

---

## Scope

Chainwatch does **not** fuzz, symbolically execute, or formally verify; does not
detect novel vulnerabilities; does not generate exploit code or proof-of-concept
transactions; and never auto-discloses anything.

On chain it is strictly read-only — `eth_getCode`, `eth_getStorageAt` and
read-only `eth_call`, with no code path that can send a transaction.

On a target repository it is **read-only, literally**. Chainwatch makes a bare
clone inside its own scratch directory first, and every worktree, checkout and
piece of git bookkeeping happens in that clone — so the repository you point it
at is only ever the source of a clone and a fetch. Verified against a read-only
bind mount: the scan completes normally and `.git/worktrees/` in the target
stays **absent**, not merely unchanged.

This was not always true: `git worktree add` used to run against the target
directly, which writes metadata into its `.git`. That gap, its measurement and
its fix are recorded in LIMITATIONS.md under `WALK-L6` rather than quietly
corrected.
