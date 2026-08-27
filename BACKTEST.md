# Incident backtesting

> Would Chainwatch have fired at the commit that introduced a real, publicly
> documented vulnerability — before the incident?

```bash
python backtest.py                          # every case
python backtest.py --case 88mph-nft-init-2021
python backtest.py --json backtest-out.json
```

## Why this exists

`scorer.py` measures precision and recall against `fixtures/`. That is
necessary, and it is also self-referential: the fixtures encode what the rules
were built to catch. Perfect precision there says the implementation matches its
own specification — not that the specification catches real attacks.

A backtest anchors somewhere this project has no authorship: an incident someone
else suffered, at a commit someone else wrote, with the answer already settled by
a public post-mortem. It is the difference between

> precision 1.00 across 25 fixture sets

and

> flagged the 88mph `NFT.init()` ownership hijack at its introducing commit,
> four months before disclosure

Only the second is evidence a stranger has reason to trust.

## The admission rule

**A case may be added only once its `parent` and `commit` have been resolved
against the real repository, and its `source` verified against a public
write-up.**

This is the whole value of the file. A corpus of twenty cases with guessed
commit hashes produces a rigorous-looking percentage that means nothing — and,
worse, one that would survive review because the number itself looks careful.
One verified case is worth more than twenty plausible ones.

The corpus is therefore ground truth in the same sense `fixtures/` is: read-only
after verification, per CHARTER rule 1. If a case fails, **fix the detector or
record the miss — never relax the case.**

## Adding a case

1. **Find the incident.** A post-mortem with enough detail to identify the
   vulnerable contract and function: Immunefi, Rekt, the protocol's own
   disclosure, an audit report.
2. **Find the introducing commit.** `git log -p --follow -- <file>` around the
   vulnerable function. You need the commit where the control was weakened, and
   its parent — not the fix commit.
3. **Verify against history**, not from the write-up's prose:
   ```bash
   git -C <repo> show --stat <commit>
   git -C <repo> rev-parse <commit>^   # must equal your `parent`
   ```
4. **Write the case** into `backtest-cases.json`. `expect` names the rule, file,
   contract and function precisely — a case that only named a rule could be
   "caught" by that rule firing anywhere in the repository, which would make the
   whole harness dishonest.
5. **Run it.** If it misses, that is a real, publishable result about the
   detector. Record it; do not soften the case to make it pass.

## Reading the output

| Status | Meaning |
|---|---|
| `CAUGHT` | the expected rule fired on the expected contract and function |
| `MISSED` | the rule ran and stayed silent — a genuine result about the detector |
| `UNRUNNABLE` | the case could not execute (repo absent, nothing compiled) |

`UNRUNNABLE` is counted separately and deliberately. A miss over code that never
compiled is **unmeasured**, not a false negative — collapsing the two would let
an environment problem masquerade as detector quality, in whichever direction
happened to flatter the result. This is METHODOLOGY Face A applied to the
harness itself.

`backtest.py` exits non-zero only on a real `MISSED`.

## Current corpus

One case: **88mph `NFT.init()`**, 2021-02-16, ~$6.5M at risk, whitehat-reported
via Immunefi. It is the only incident this project has verified end to end —
including confirming that the deployed EIP-1167 clone implementation is still,
byte-for-byte, that commit's build.

Growing this corpus is the highest-value work available to this project. Each
case is bounded, independent, and permanently useful.
