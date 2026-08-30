# Chainwatch — demo script (~4 min, live, unedited)

**Track: The Taskmaster.** Judging weights this is built around: 40%
*innovation & operational utility — autonomous, high-value action, not a chat
loop*; 30% *architectural discipline*; 30% *demo & production readiness*.

**The spine, said once at the top and paid off at the end:** every other tool
answers *"is this contract vulnerable now."* Chainwatch answers *"when did a
control break, is that broken version live on-chain, and — where it can't
prove that — exactly which check is missing."* The model proposes; mechanical
gates decide; **it cannot hallucinate a finding.**

**Nothing in this script is staged.** Every command below has been run and
every number measured on 2026-08-30. Where a result is a limitation, the
script says so on camera — that is the product, not a blemish on it.

The rules require the video to show: the problem, the value proposition, the
app in action, **and proof the backend runs on Google Cloud.** Live terminal,
no jump cuts.

---

## 0:00–0:30 — the problem

**Screen:** title card, then the terminal.

**Say:** "Smart contracts get upgraded, refactored and forked. Protections get
removed in the middle of ordinary-looking refactors, and nobody is watching
history. In 2021, 88mph replaced a constructor with an `init()` function and
dropped the access control. A whitehat caught it — six weeks later. That
implementation is immutable, so the vulnerable code is still deployed today,
five years on."

**Do not say** "we found this bug." A whitehat found it in 2021. Chainwatch
demonstrates *locating the commit from history alone*.

---

## 0:30–1:00 — the value proposition

**Say:** "Chainwatch is an autonomous agent that walks a repository's git
history, rebuilds each commit's build environment, and proves a chain:
regression → reachability → liveness on-chain. It clones, installs, compiles,
runs thirteen evidence gates, tries to disprove its own findings, and attempts
a blinded reproduction — with no hand-holding. And the part that matters: a
Gemini model proposes and explains, but a deterministic gate function decides.
The model has no path to a verdict."

---

## 1:00–2:15 — live run

**Screen:** terminal.

```bash
python chainwatch.py agent --repo <target> --limit 10
```

Two stages print, labelled on screen:

**STAGE 1/2 — the deterministic engine.** Live log streams commit pairs,
dependency installs, and the finding. **Land on the coverage panel before the
findings** — it is printed above them on purpose:

```
COVERAGE (read this before the findings)
  commit pairs analyzed : 1/1  (100.0%)
```

**Say:** "Coverage first, always. A scan that analysed nothing reports zero
findings — and so does a clean repository. If you can't tell those apart, the
number is worthless."

**STAGE 2/2 — the ADK multi-agent layer.** Four roles print their turns:

```
  AGENT TURNS
    hunter      *              no gate - the Hunter proposes only
    skeptic     91dda8837dc2   input only - a challenge cannot fail a gate
    reproducer  91dda8837dc2   proposes a plan; the gate is set only by a run
    gatekeeper  *              verdicts recomputed and byte-identical
  verdicts unchanged: True  (recomputed after every agent turn)
```

**Say:** "Hunter, Skeptic and Reproducer are Gemini agents on Google's ADK.
The Gatekeeper is code. The engine's verdicts are snapshotted *before* a single
token is generated and recomputed after the last agent turn — if they ever
differed, the run fails with `VerdictDrift`. That check runs in production, not
just in a test."

**Optional 10-second beat, if the pacing allows** — the blinding, visible in
the model's own words. The Reproducer gets four fields: contract, function,
invariant, objective. Asked to plan a reproduction it answered:

```
"unknowns": ["The exact function signature and parameters for setFee",
             "The method used by FeeManager for access control"]
```

**Say:** "It doesn't know, because we didn't tell it. Blinding isn't a promise
in a prompt — the brief is a frozen four-field type."

**Then the funnel** (`--funnel`, printed automatically in agent mode):

```
  RESOLUTION QUEUE - closest to a decidable answer first
    1. [distance 2] 1-FeeManager-setFee-dac6083a  (CANDIDATE, rule 1)
       supply: address, rpc_url
```

**Say:** "This is the part I'd want if I ran a security team. Not 'zero
confirmed' — *this* candidate is two mechanical checks from a decidable answer,
and here is the exact input that runs them. Distance counts checks that haven't
run. It is not a likelihood, and supplying the input doesn't promote anything —
the same gate function decides again."

**Screen:** switch to the web app and show the same Resolution Queue rendered,
plus the Sweeps panel.

---

## 2:15–3:00 — the 88mph case, and watching the verdict move

```bash
python chainwatch.py --repo realworld-test/88mph-src \
  --address 0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634 \
  --pairs 5f52a2ead702…:a4c48d61661a… --check-exploit-proof --funnel
```

**Screen:** the trajectory strip.

```
introduced : a4c48d61661a  2021-02-16  Zefram Lou
lines      : 36-49
at HEAD    : still present
on-chain   : LIVE - matched the REGRESSION COMMIT's own build, not current
             HEAD (deployed target is a non-proxy contract, its own bytecode
             cannot be upgraded; a later source fix cannot reach it)
```

**Say:** "From history alone, with no prior knowledge of the incident:
`NFT.init`, the exact commit, the author, the line range — and now watch the
verdict. It fires as CANDIDATE first. Then liveness runs: the deployed
bytecode is compared, byte for byte, against what that commit compiles to.
Match. **CONFIRMED.** That promotion, not the finding itself, is the product."

**Then the live proof.** A read-only `eth_call` against mainnet, right now:

```
OPEN  NFT.init  init(address,string,string)
      simulated call did not revert - the one-shot window is still open
```

**Say:** "That is a real call to mainnet, made just now. Read-only — this tool
has no code path that can send a transaction. Five years after the disclosure,
the deployed implementation still accepts `init()`. The source was fixed; the
deployed code is immutable, so the fix never reached it. *Fixed in source* and
*fixed on-chain* are different claims, and that gap is what this tool exists to
surface."

**Immediately add the caveat — do not skip it:** "88mph's team emptied those
pools to treasury within 24 hours in 2021. There is nothing to steal. The
vulnerability is real; the value at risk is zero, and I'm not going to inflate
that."

**Then the funnel, briefly — the other half of the story:** `distance_to_confirmed: 0`.

**Say:** "This CONFIRMED result wasn't always reachable, and that's worth ten
seconds. Until earlier today, this exact case stopped at CANDIDATE — the
pipeline had the byte-exact evidence but a gate in the liveness check was too
narrow to reach it. That's written up as `LIVE-L1` in LIMITATIONS.md: found,
measured, fixed, eleven new tests, and re-verified against the real repo and
real mainnet, not a mock. A tool that shows its own bugs is more trustworthy
than one that's never had any."

---

## 3:00–3:30 — Google Cloud proof (MANDATORY)

**Screen, in this order:**

1. **Cloud Run dashboard** — the `chainwatch` service, region `us-central1`,
   revision and traffic.
2. **The live URL in a browser:**
   <https://chainwatch-898260334135.us-central1.run.app> — same app, running on
   Cloud Run.
3. **Firestore console** — the collections: `scans`, `pairs`, `findings`,
   `funnel_traces`, `agent_runs`, `agent_turns`, `sweeps`.
4. **Secret Manager** — `chainwatch-gemini-key`, mounted at deploy time; say
   "the API key is never in an image layer, and `docker history` is clean."

**Say:** "Gemini 3.5 through Google's ADK; Cloud Run hosting the scanner and
the UI; Firestore holding the corpus, the funnel traces and every agent turn;
Cloud Scheduler driving the unattended sweep. Every agent turn is recorded —
what it saw, what it said, and what the gate did about it."

---

## 3:30–4:00 — close

**Say:** "One sentence: the engines propose, deterministic gates decide, and
the funnel tells you exactly which check is missing for everything that didn't
make it. It's measured — 50.8% mechanism-matched detection across 63 real
DeFiHackLabs exploits, at zero high-confidence false positives per thousand
mainnet contracts — and where it falls short, that's written down too. We
rejected a rule that would have raised recall because it bought it with two
false positives."

**End card:** repo URL + <https://chainwatch-898260334135.us-central1.run.app>

---

## Production notes

- **Never show a LIVE verdict without `LIVE_CAVEAT` in frame.** LIVE means
  bytecode identity, not exploitability.
- **Never say "found a vulnerability."** Chainwatch locates a regression and
  reports evidence; the 88mph bug was found by a whitehat in 2021.
- **Never show `OPEN` without the "nothing to steal" sentence** in the same
  breath.
- **Do not cut the "wasn't always CONFIRMED" beat to save time.** It is the
  differentiator over a tool that would just show the clean result and imply
  it was always solid; cutting it removes the reason to trust anything else.
- **Timing, measured on 2026-08-30, not estimated:** the 88mph pair took
  **78–209s end to end** depending on whether npm/HEAD dependencies are
  already cached (78s warm, 209s on a cold container). Do not promise "thirty
  seconds" on camera. Either run it once immediately before recording so the
  HEAD environment is hot, or start the command, say the 0:00–0:30 problem
  framing over it, and come back to the result.

## Reproduction commands (for the recording session)

```bash
# warm the caches first, off-camera
python chainwatch.py --repo realworld-test/88mph-src \
  --address 0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634 \
  --pairs 5f52a2ead702e4cb9ab3d04a1109807462dde228:a4c48d61661ae3d8ce5aadfda6e4de27c4f07a9e \
  --check-exploit-proof --funnel --quiet

# the live eth_call shown at 2:15 (read-only, no transaction)
python -c "import sys; sys.path.insert(0,'.'); \
from src import exposure as E, liveness as L; \
print(E.probe(L._w3(None), '0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634', \
'NFT', 'init', 'init(address,string,string)'))"

# the agent run shown at 1:00
python chainwatch.py agent --repo <target> --limit 10

# every stored verdict re-derived from its own gate states; exit 1 on drift
python chainwatch.py --verify-funnel report.json
```
