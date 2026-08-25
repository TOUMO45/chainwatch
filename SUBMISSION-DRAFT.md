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
- **Agent layer (reporting):** Google **ADK** (`google-adk`) with **Gemini**
  (`google-genai`, model `gemini-3.5-flash-lite`). Six read-only tools; every
  drafted dossier is re-verified against the finding record before it is
  written, and any invented hash/address/path/line is rejected.
- **Interfaces:** FastAPI + SSE web app, and a CLI — both thin shells over one
  engine (`src/scan.py`) so they can never disagree about what a finding is.
- **Deployment:** Docker → Google **Cloud Run** (`2 vCPU / 4 GiB`, scale to
  zero); `GEMINI_API_KEY` via **Secret Manager**, never in an image layer.
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

**Current state: the repository has no git remote at all** (`git remote -v` is
empty). It exists only on this machine — it is neither public nor private on
GitHub, because it is not on GitHub yet.

Before judges (`testing@devpost.com`, `cloudhackathons@google.com`) can see it,
**you** must create and push the repo (I can't — it needs your GitHub
credentials):

```bash
# 1. Create the repo (gh CLI) — or make it on github.com and copy the URL.
gh repo create <you>/chainwatch --public --source=. --remote=origin

# 2. Push (current branch is `master`).
git push -u origin master
```

Then choose one:
- **Public** (simplest for judging): the `--public` above is enough. Confirm at
  `https://github.com/<you>/chainwatch` in an incognito window.
- **Private:** add the judges as read collaborators — repo **Settings →
  Collaborators → Add people** → invite `testing@devpost.com` and
  `cloudhackathons@google.com` (accounts, not just emails, may be required by
  the specific hackathon — check its rules).

**Note:** the three commits made this session (`0270fff`, `0c72626`, `ed5e2d3`)
plus these packaging commits are local only until you push.

---

## 4. "Google SDK used + project start date"

- **Google SDKs used:** `google-adk` **2.7.0** and `google-genai` **2.18.1**
  (both confirmed via `pip show`; model `gemini-3.5-flash-lite`). Also Google
  Cloud Run / Cloud Build / Artifact Registry / Secret Manager.
- **Project start date:** **2026-08-01** — the first commit,
  `0d47141 "Phase 1: skeleton + charter. Gate 1 passed."` (from `git log --reverse`).
