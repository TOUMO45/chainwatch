# Chainwatch — submission draft (for review)

Working draft for the Devpost text fields. Nothing here is auto-submitted;
copy what you approve. Facts are pulled from the repo, `git log`, `pip show`,
and `LIMITATIONS.md` — not invented. See also `SUBMISSION-NOTES.md` (track,
pitch, the CANDIDATE-cap framing) which this complements rather than replaces.

---

## 1. Written description

### What it does

Every other tool tells you whether a contract is vulnerable **now**. Chainwatch
tells you **which commit made it vulnerable, and whether that commit is live
on-chain** — the two halves of one sentence, and the whole differentiator.

It walks a Solidity repository's full git history, reconstructs each commit's
build environment, and runs ten deterministic regression detectors (Slither
AST/IR, no regex, no modifier-name matching) over every `(parent, commit)` pair
that touched Solidity. For each regression it reports the introducing commit,
its first parent, author, date, the changed line range, whether the regression
still survives at HEAD, and — given a deployed address — whether the affected
code is the bytecode actually running on-chain.

The result is not a severity score. It is a **verdict** with an evidentiary
bar: a finding reaches `CONFIRMED` only when all six required evidence fields
are present *and* on-chain liveness is `LIVE`. Miss any one and it is capped at
`CANDIDATE`, and nothing downstream can raise that cap — not additional
evidence, and not the Gemini agent layer, which may only *read* a finished
finding and is re-verified mechanically against the record. **The tool's
signature behaviour is that it declines to overclaim.** Its real-world
demonstration is a genuine regression in Reserve Protocol
(`ActFacet.revenueOverview`, commit `e27227b2`) that it locates precisely and
then *refuses* to call CONFIRMED, because one required field (reachability) is
not established. That refusal is the product, not a shortfall.

### How we built it — technologies

- **Detection engine:** Slither (`slither-analyzer`) + `crytic-compile` for
  AST/IR and data-dependency analysis; `solc-select` to install and pin the
  exact Solidity compiler each historical commit declares; ten rule modules
  mapped to OWASP Smart Contract Top 10 categories (SC01, SC05, SC06, SC08,
  SC09, SC10).
- **On-chain liveness:** `web3.py` over a read-only Ethereum RPC
  (`eth_getCode` / `eth_call` only — no code path can send a transaction).
- **Agent layer (reporting):** Google **ADK** (`google-adk`) with **Gemini 3.5**
  (`google-genai`, model `gemini-3.5-flash-lite`). Eleven read-only tools (six
  on the report path); every drafted dossier is re-verified against the finding
  record before it is written, and any invented hash/address/path/line is
  rejected.
- **Agent layer (orchestration):** four ADK roles over a finished scan —
  **Hunter**, **Skeptic** and **Reproducer** proposing, and a **deterministic
  Gatekeeper** deciding. The engine's verdicts are snapshotted before a single
  token is generated and recomputed afterwards; a difference raises
  `VerdictDrift` and the run fails. The Reproducer is blinded by the type
  system — a frozen four-field brief, so there is no path that could leak the
  analyst's write-up. `chainwatch agent --repo <url>`.
- **Funnel + resolution queue:** every candidate carries its gate states, the
  gate that killed it, its distance to a decidable answer, and the exact
  deterministic input that would let each blocked gate run. Every stored verdict
  is re-derived from its own stored gate states on read; divergence is a hard
  error (`chainwatch --verify-funnel`).
- **Unattended sweep:** `chainwatch sweep` walks a repository list with nobody
  watching, as a **Cloud Run Job** on **Cloud Scheduler**. A failing target is
  recorded with its reason and never ends the sweep.
- **Interfaces:** FastAPI + SSE web app, and a CLI — both thin shells over one
  engine (`src/scan.py`) so they can never disagree about what a finding is.
- **Deployment:** Docker → Google **Cloud Run** (`2 vCPU / 4 GiB`, scale to
  zero); `GEMINI_API_KEY` via **Secret Manager**, never in an image layer;
  Firestore collections `scans`, `pairs`, `findings`, `funnel_traces`,
  `agent_runs`, `agent_turns`, `sweeps`.
- **Integrity discipline:** frozen, hash-guarded fixture sets (`guard.sh`) and
  a `scorer.py` that enforces precision = 1.00 per shipped rule.

### Data sources

- **Public git repositories** — cloned anonymously, read-only. Chainwatch makes
  a bare mirror clone inside its own scratch directory first; the target repo is
  only ever the source of a clone and a fetch (verified against a read-only bind
  mount: the target's `.git/worktrees/` stays absent after a scan).
- **On-chain bytecode** — read from an Ethereum RPC endpoint via `eth_getCode`,
  compared against the locally compiled runtime artifact for liveness.
- **Frozen fixtures** — hand-built Solidity regression pairs plus recorded real
  runs, used as ground truth for the scorer and the sizing discipline.

### What we learned

The honest log is in `LIMITATIONS.md`; four things are worth surfacing.

1. **A security tool has to survive its own "paste a link and press scan."**
   Auditing that path against a repo we had never analysed
   (`morpho-org/morpho-blue`) surfaced **WALK-L9** — a scan that *executed the
   target repository's code*. The yarn install guard relied on `--mode=skip-build`
   to suppress lifecycle scripts, with a comment asserting yarn 1 rejects that
   flag. It does not: measured on yarn 1.22.22, a project's `prepare` script ran.
   That is a remote-code-execution surface, and CHARTER rule 5's "read-only on
   every target" was simply false for a whole class of repo until we closed it.
   It announced itself as a *coverage anomaly whose skip-reason string was a lie*
   — which is exactly why coverage is a first-class, always-printed output.

2. **The same audit found WALK-L10:** one mistyped URL took the product offline
   for thirty minutes, because `git clone` inherited the machine's credential
   manager and blocked on a GUI auth dialog — while an unenforced CHARTER clause
   ("never authenticate beyond public-read") looked on. Availability and a
   security guarantee were the same bug.

3. **False positives are defeated by fixtures, not by cleverness.** `RC-MUTEX1`
   (a reentrancy mutex mistaken for one-shot initializer machinery) and
   `RC-RENAME2` (a parameter rename read as a removed `require`) were each fixed
   only after the *obvious* fix was shown wrong by a frozen fixture. `SCAN-L1`
   was worse: the scanner looked at a directory the repository does not have and
   reported it clean. Every one of these is pinned by a test that would fail if
   the bug returned.

4. **A pilot does not predict a full run, and we refused to pretend otherwise.**
   A 3-pair pilot of Aave sized a run at 48.6s/comparison; the full run measured
   634s — a 13× miss. Rather than ship a confidence interval fitted to a handful
   of points, the sizing module *reports what a run has measured and refuses to
   project past it*, in copy that names the reason (analysable coverage tracks
   commit age, so an evenly-spaced pilot is a biased sample, not merely a small
   one). The same refuse-rather-than-guess instinct runs through the whole
   product.

5. **We measured the tool against real exploits, and published the number that
   came back.** Across 63 scoreable DeFiHackLabs incidents Chainwatch
   mechanism-matched **50.8%** (32/63), at **0 high-confidence false positives
   per 1,000 mainnet contracts** (`BENCHMARK.md`). The number we are proudest
   of is a *negative* one: a candidate rule 13, written to close the worst
   class (ACCESS_CONTROL, 2/14), passed every synthetic fixture, then recovered
   2 of 12 real incidents — and **both were false positives**. It was reverted
   rather than shipped. A detector that buys recall with false positives is not
   an improvement to a tool whose entire claim is that it does not overclaim.

6. **The agentic layer had to be safe by construction, not by prompt.** The
   whole design question was how to use a model without letting it near a
   verdict. The answer was to make the boundary mechanical: verdicts
   snapshotted before generation and compared after, proposals filtered against
   the engine's own id set, and the Reproducer's inputs reduced to a frozen
   four-field type. Each is tested against a stub model actively trying to
   break it. On a real run the blinding was visible in the model's own output:
   asked to plan a reproduction, Gemini listed “the exact function signature”
   and “the method used for access control” under `unknowns` — because it had
   not been told them.

---

## 1b. Pre-existing work disclosure (hackathon rule: “New Projects Only”)

Stated in full in the README under **Pre-existing work disclosure**, and worth
repeating here because the rules ask for it explicitly.

The submission period ran **3–31 Aug 2026**. Chainwatch's first commit is dated
**1 Aug 2026** — two days early. What existed before the window opened was 28
commits, **16 Python files / 2,431 lines**: the charter, seven detection rules,
`history.py`, `liveness.py`, `verdict.py`, and the fixture corpus with its
scorer and integrity guard.

What did **not** exist: the scan pipeline, the CLI, the web app, the entire
test suite (there was no `tests/` directory), rules 4/5/10, Firestore, the
Cloud Run deployment, the 13-gate evidence model, the Skeptic, the blinded
Reproducer, the Counterfactual Twin, the Deep Hunt engine, the funnel, the ADK
multi-agent layer, the unattended sweep, and every benchmark.

Measured rather than characterised: **2,431 of 43,641 tracked Python lines
predate the window — 94.4% of this repository was written during the
submission period**, along with all of its tests, its cloud deployment, and
every agentic component. Verifiable from the repo:

```bash
git log --reverse --format="%h %ad %s" --date=short --until=2026-08-03
git ls-tree -r --name-only 21aa72f | grep -E "^(src|tests|agent|webapp)/"
```

---

## 2. Third-party code and license disclosure

Chainwatch's own code is original. It builds on the following third-party
components. Versions are the actually-installed/pinned ones; licenses marked
✔ were read from package metadata (`pip show`), the rest are the components'
well-known standard licenses (please verify before final submission).

### Python (`requirements.txt` + transitive)

| Component | Version | License | How used |
|---|---|---|---|
| slither-analyzer | 0.11.5 | **AGPL-3.0** ✔ | detection engine (imported) |
| crytic-compile | 0.3.11 | **AGPL-3.0** ✔ | compilation front-end (via Slither) |
| solc-select | 1.2.0 | **AGPL-3.0** ✔ | installs/pins the solc compiler |
| solc (Solidity compiler binaries) | per-commit | GPL-3.0 | fetched at runtime by solc-select |
| web3.py | 7.16.0 | MIT ✔ | on-chain liveness (read-only RPC) |
| google-adk | 2.7.0 | Apache-2.0 | agent framework |
| google-genai | 2.18.1 | Apache-2.0 | Gemini client |
| fastapi | 0.139.0 | MIT | web app |
| uvicorn | (req range) | BSD-3-Clause | ASGI server |
| sse-starlette | (req range) | BSD-3-Clause | server-sent events |
| pydantic | (req range) | MIT | request models |
| python-dotenv | (req range) | BSD-3-Clause | `.env` loading |
| pytest | (req range) | MIT | test harness |

### JavaScript (`package.json`) — used only as fixture compile targets

| Component | Version | License | How used |
|---|---|---|---|
| @openzeppelin/contracts | 4.9.6 | MIT ✔ (well-known) | fixtures compile against these |
| @openzeppelin/contracts-upgradeable | 4.9.6 | MIT | fixtures (proxy/upgrade rules) |

### Managed services

- **Google Cloud Run**, **Cloud Build**, **Artifact Registry**, **Secret
  Manager** — deployment/runtime.
- **Google Gemini API** (`gemini-3.5-flash-lite`) — the agent's model.

> ⚠️ **Worth a human decision before submitting:** Slither, crytic-compile and
> solc-select are **AGPL-3.0**, and `slither-analyzer` is imported directly. AGPL
> is strong copyleft; depending on how the judges/organizers treat combined
> works and distribution, this may have implications for how Chainwatch itself
> must be licensed or described. This is a flag, not legal advice — decide
> deliberately.

---

## 3. Repository visibility — ACTION REQUIRED

**Current state: the remote exists but the work is not pushed.** `origin` is
`https://github.com/TOUMO45/chainwatch.git` and the local `master` is **ahead
by 32+ commits**, including every capability described above.

**A human must push.** This machine has no cached GitHub credential: `git push`
and even `git credential-manager get` hang until timeout, there is no `gh` CLI
and no `GH_TOKEN`. That is not a retryable failure — it needs a credential
only you can supply.

```bash
git push -u origin master
```

Then choose one:
- **Public** (simplest for judging): the `--public` above is enough. Confirm at
  `https://github.com/<you>/chainwatch` in an incognito window.
- **Private:** add the judges as read collaborators — repo **Settings →
  Collaborators → Add people** → invite `testing@devpost.com` and
  `cloudhackathons@google.com` (accounts, not just emails, may be required by
  the specific hackathon — check its rules).

**Note:** everything after the last pushed commit is local only until you push
— confirm with `git rev-list --count origin/master..master`.

---

## 4. "Google SDK used + project start date"

- **Google SDKs used:** `google-adk` **2.7.0** and `google-genai` **2.18.1**
  (both confirmed via `pip show`; model `gemini-3.5-flash-lite`). Also Google
  Cloud Run / Cloud Build / Artifact Registry / Secret Manager.
- **Project start date:** **2026-08-01** — the first commit,
  `0d47141 "Phase 1: skeleton + charter. Gate 1 passed."` (from `git log --reverse`).
