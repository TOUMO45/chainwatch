"""The Chainwatch next-gen benchmark (spec §20, §27).

A benchmark that is NOT only vulnerable examples. Every suite must contain hard
negatives - benign, suspicious-looking changes that must NOT confirm - because
the point being demonstrated is:

    Chainwatch does not merely find vulnerabilities. It knows when NOT to
    report one.

    model.py   BenchmarkCase / BenchmarkResult / Metrics (precision, recall,
               false-positive rate, false-negative rate, and the §27 ratio
               CONFIRMED / FALSE-POSITIVE)
    runner.py  run one case (through a pluggable pipeline), run a suite, tally
    cases.py   the starter offline suite - synthetic self-contained sources,
               heavy on hard negatives
"""

from __future__ import annotations
