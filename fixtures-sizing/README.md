# fixtures-sizing — the recorded pilot/full runs, frozen as ground truth

NOT a scorer set. No `manifest.json`, no rule is scored here. `recorded-runs.json`
is nine **real Chainwatch reports** — five repositories, four of them measured
twice (a 3-pair pilot and the full run that followed) — reduced to the fields a
sizing decision can legitimately use.

It is frozen by `guard.sh` for the same reason the detection fixtures are: it is
the evidence a design decision rests on, and a design that is measured against
numbers somebody can edit is not measured at all.

## Provenance

Every row was extracted from an `.e2-*.json` report on the machine that ran it
(`source_report` names the file). Those reports are **gitignored** — they are
run output, reproducible only at the cost of the runs themselves, and Aave's
full run alone cost 8.6 hours of wall clock. That is precisely why the numbers
are copied here instead of read from disk at test time: a test that depends on
an ignored file passes on one machine and errors on a fresh clone.

Nothing is rounded, recomputed, or adjusted. `files_ok / files_total` is the
coverage figure; `seconds` is the run's own elapsed total.

## What it is evidence FOR

| repo | pilot coverage | full coverage | direction |
|---|---|---|---|
| 88mph | 0.0% (0/5) | 31.7% (32/101) | pilot UNDER by 31.7 points |
| aave-v2 | 6.7% (1/15) | 32.7% (16/49) | pilot UNDER by 26.0 points |
| v3-core | 90.9% (10/11) | 84.3% (43/51) | pilot **OVER** by 6.6 points |
| v3-periphery | 100.0% (6/6) | 98.7% (77/78) | pilot **OVER** by 1.3 points |
| compound-v2 | 0 comparisons | (never ran) | nothing to extrapolate from |

Three facts this table is here to keep true:

1. **The misses go BOTH ways.** Any correction that assumes pilots are
   pessimistic is wrong on half the sample.
2. **A 95% Wilson interval on the pilot MISSES aave-v2** (`1/15` gives
   `[1.2%, 29.8%]`; the truth is `32.7%`). Widening the interval until all four
   pass is fitting a constant to four points, and is refused — see
   `LIMITATIONS.md SIZE-L1`.
3. **compound-v2 produced zero comparisons.** A sizing routine must refuse,
   not divide.

`seconds` carries the same lesson on the cost axis: aave-v2 went from
`729.1s / 15 = 48.6s` per comparison in the pilot to `31064.2s / 49 = 634.0s`
in the full run — a 13.0x miss. `TODO.md` records what that cost in planning
terms: a projection of ~48 minutes against an actual 8.6 hours.
