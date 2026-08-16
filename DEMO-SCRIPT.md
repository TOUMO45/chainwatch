# Chainwatch — demo arc (draft, not recorded)

**Target: 2:30–3:00.** Track: The Taskmaster. The two judging weights this is
built around: 40% *autonomous, high-value action over simple chat*, 30%
*architectural discipline*.

**The spine of the whole video, said once at the top and paid off at the end:**
every other tool answers *"is this contract vulnerable now."* Chainwatch answers
*"when did a control break, and is that broken version live on-chain."* Then:
the deterministic engine decides, and the agent only explains — and the most
impressive thing in the demo is the moment the tool **refuses to overclaim**.

Nothing in this script is staged. Every number below has been measured and every
screen is real output; the segment notes say which command produces it.

---

## (a) 0:00–0:35 — a real repository, scanned live

**Screen:** the web UI, `realworld-test/reserve-src`, explicit pair
`f43202a3:e27227b2`, Rule 5 selected. Hit **Run scan**. Live log streams:
`[1/1] f43202a3..e27227b2`, then the finding line.

**Say:** "This is Reserve Protocol — a real, public, audited DeFi protocol. I'm
not scanning it for bugs that exist today. I'm asking a different question:
*which commit removed a control that used to be there.*"

**Land on the coverage panel before the findings** — it is above the table on
purpose:

```
COVERAGE — READ THIS BEFORE THE FINDINGS
  1/1 commit pairs analysed (100%)     5/8 file comparisons completed (62.5%)
```

**Say:** "Coverage comes first, always. A scan that analysed nothing reports zero
findings — and so does a clean repo. If you can't tell those apart, the number is
worthless."

*(~35s. Real timing: this scan takes ~91s, so the recording cuts from launch to
result — say "this takes about ninety seconds" rather than implying it's instant.)*

---

## (b) 0:35–1:20 — the CANDIDATE cap, which is the point

**Screen:** click the finding. Drawer opens on the trajectory strip:

```
control present  →  control removed here  →  at HEAD
f43202a3            e27227b2                still missing
                    2025-11-20 · Taylor Brent
                    lines 117-118
```

**Say:** "There it is. `ActFacet.revenueOverview`, line 117. A `try/catch` around
an external price call was removed, the function kept its name and its signature,
and the change is still in the code today. Commit, author, date, exact lines."

**Then scroll to the evidence checklist — this is the emotional beat:**

```
✓ 1. regression commit    ✓ 4. reachability … ✕
✓ 2. pre-state (N-1)      ✓ 5. no compensating control
✓ 3. post-state (N)       ✕ 6. on-chain liveness — not established

WHY THIS IS NOT CONFIRMED
  missing evidence: reachability, liveness
```

**Say:** "Five of six required fields check out. It still refuses to call this
confirmed. Field 4 requires the function be externally callable **and**
state-changing — this one is a view, so it writes nothing. A regression on a
read-only function can never reach CONFIRMED in this tool."

**The line that has to land:** "I didn't write an exception for this case. It
falls out of the model. **The interesting thing about this tool is not what it
finds — it's what it refuses to claim.**"

---

## (c) 1:20–2:05 — the agent, and its self-correction loop

**Screen:** click **Generate report**. The live tool log fills in as it runs:

```
tool: get_finding
tool: get_diff
tool: draft_report
tool: verify_report      ← ×5
tool: save_report
```

**Say, over the repeated verify calls:** "Watch the middle. The agent drafts,
then runs a **mechanical** verifier against its own output — no second model
grading the first — and revises until it passes. Five attempts here. That loop
is the product, not decoration."

**Then the result:**

```
✓ verified against the finding record — every hash, address, path and line in
  this document came from the engine, not the model

# NOT CONFIRMED - missing evidence: reachability, liveness
> This document describes a finding that did not meet Chainwatch's CONFIRMED
> bar. It is not a vulnerability report and must not be read as one.
```

**Say:** "That header is not a prompt instruction. It's a hardcoded template
wrapper — the model fills named prose slots inside it and never writes the
framing. For a CANDIDATE there is no severity section and no impact section, so
there is nowhere to put an overclaim even if it tried. And every fact is rendered
from the record by code, so the model never types a commit hash and therefore
can't get one wrong."

**One sentence on the boundary, because it's the 30% criterion:** "The agent has
six read-only tools. It can't analyse, it can't reach a chain, and there is no
tool that writes a verdict. It explains what the engine already decided."

*(If time is tight, the sentence to cut is the boundary one — the header and the
five verify calls carry the point visually.)*

---

## (d) 2:05–2:35 — liveness, proven separately and labelled honestly

**Screen:** terminal, the capability-11 result on 88mph.

```
address   0xF0b7DE03134857391d8D43Ed48e20EDF21461097   (EIP-1167 clone)
          → implementation 0xDe71B24FE56358cC0ADfd6f2e0f6D8ed9e2CF634
VERDICT : LIVE
deployed normalized keccak  cf6e4ce9bcfd1e19c84c88f40793cead6b2cfc8aaed711884e2ef1b001f34bcb
artifact normalized keccak  cf6e4ce9bcfd1e19c84c88f40793cead6b2cfc8aaed711884e2ef1b001f34bcb
```

**Say:** "The second half of the claim. This is a real mainnet address, a real
already-disclosed 2021 bug, already remediated. The vulnerable implementation's
bytecode still matches, byte for byte after normalisation."

**Immediately show the caveat — do not let LIVE sit alone on screen:**

> LIVE = this exact bytecode is present on-chain at this address and is what
> executes there. It does NOT mean the contract is currently reachable, funded,
> or exploitable — liveness compares code, not risk.

**Say:** "And the control run: same address, same source, compiled without the
project's optimizer settings — it returns UNKNOWN, not PATCHED. It refuses to
guess when a mismatch could just be build settings."

---

## (e) 2:35–3:00 — close on the rigor, not on a victory lap

**Screen:** LIMITATIONS.md scrolling — `RC-RENAME1`, `WALK-L6`, `METHODOLOGY`.

**Say:** "Two things I'd rather you heard from me than found yourselves.

**One:** Chainwatch cannot see a control that *moves*. When 88mph replaced a
constructor with an unguarded `init()`, this tool was completely silent — every
rule matches functions by name across commits, and `init` had no counterpart to
compare against. That's documented, with the measurement, as `RC-RENAME1`.

**Two:** it used to claim it was read-only on your repository, and that was not
strictly true — `git worktree` was writing metadata into it. Found it by mounting
a repo read-only in a container. Fixed it by cloning into scratch first. The
claim is now literally true, and the whole arc — including the wrong version — is
in the history."

**Final line:** "Every tool tells you what it found. This one also tells you what
it can't see, what it refused to conclude, and where it was wrong. On a security
tool, that's the feature."

---

## Production notes

- **Do not** show a CONFIRMED verdict. There isn't one, and manufacturing a
  synthetic one for the camera would invert the entire message.
- Scan timings are real: the Reserve pair is ~91s, report generation ~30–60s
  including free-tier pacing. Cut between launch and result; say the real number
  aloud rather than implying instant.
- The 88mph liveness result must never appear on screen without `LIVE_CAVEAT` in
  the same shot.
- Key must not be visible: run with `GEMINI_API_KEY` already in `.env`, and don't
  show `.env`, `docker run -e`, or shell history.
- Segment (e) is the differentiator. If the video runs long, trim (a) and (d) —
  never (b), (c) or (e).

## Reproduction commands (for the recording session)

```bash
python webapp/server.py                       # UI, then scan pair f43202a3:e27227b2
```
```bash
python chainwatch.py --from-json reports-input/reserve-actfacet.json --generate-reports
```
