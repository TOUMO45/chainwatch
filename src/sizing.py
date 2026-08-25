"""How long a run will take, and how much of it will be analysable — reported
as what has been MEASURED, never as a prediction (finding SIZE-L1).

The failure this replaces is on record in `TODO.md`: a 3-pair pilot sized 88mph
at 0.0% coverage (it ran at 31.7%) and Aave at 48.6s per comparison (it ran at
634.0s — 13x, turning a projected ~48 minutes into 8.6 hours). Pilot-then-scale
was the right discipline; the number it produced was worthless.

WHY ERROR BARS ARE NOT THE FIX, which is the whole design decision here. The
obvious repair is to keep the pilot and widen it into a confidence interval.
Measured against the four recorded pilot/full pairs in `fixtures-sizing/`, a
95% Wilson interval on the pilot's own file counts MISSES aave-v2 (1/15 gives
[1.2%, 29.8%]; the truth is 32.7%). A 99% interval covers all four — and
choosing 99% because it covers all four is fitting a constant to four points,
which is exactly the kind of number this project does not ship.

The reason it fails is not that three pairs is a small sample. It is that
coverage tracks repo AGE (`HANDOFF.md`), so an evenly-spaced pilot is a BIASED
sample of history, not merely a thin one — and no interval width repairs bias.
The misses confirm it by going both ways: v3-core piloted at 90.9% and ran at
84.3%.

So this module does three things and refuses a fourth:

  * it REPORTS what a run has already done. A measurement of the past is a
    fact, and a fact may be a single number.
  * it reports the SPREAD of those measurements — the real per-pair variance,
    which is what a range should be made of.
  * it PROJECTS the remainder only under the span rule below, always as a
    range, always with the caveat attached.
  * it REFUSES otherwise, in words that name the reason. A refusal a reader
    cannot understand reads as a bug, which is the standard SCAN-L1's
    "NOT A RESULT ABOUT THIS CODE" banner set.

THE SPAN RULE: never project over a remainder larger than the span already
observed. It needs no fitted constant, it is stateable in one sentence, and it
declines every recorded pilot — 3 observed pairs used to size a 12-pair run —
which is precisely the configuration that produced the 13x miss. As a live run
proceeds the observed span grows, so the projection unlocks itself and narrows
against real variance instead of guessed variance.

THERE IS NO MEAN IN THIS API, deliberately. A mean is the field a caller would
reach for and then quote in a report as if it were the answer, so there is
nothing here to reach for. `tests/test_sizing.py` asserts that over the whole
output shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# The caveat that travels with every projection. Carried in the REPORT rather
# than written into each front end, so the CLI and the web app cannot end up
# saying different things about the same run (the SCAN-L1 lesson).
CAVEAT = (
    "This is the range of what this run has actually done so far, not a "
    "prediction. It describes observed variance only: a pair that behaves "
    "unlike every pair measured so far is outside it, and the recorded worst "
    "case for that is 13x (aave-v2, 48.6s per comparison observed, 634.0s "
    "actual)."
)

SPAN_RULE = (
    "A projection is offered only for a remainder no larger than the span "
    "already measured."
)


@dataclass(frozen=True)
class Range:
    """A low/high pair with the number of observations behind it.

    `basis_n` is not decoration. A range built from two pairs and a range built
    from forty are different claims, and a reader who cannot tell them apart
    will treat the first like the second.
    """

    low: float
    high: float
    basis_n: int

    def contains(self, value: float) -> bool:
        return self.low <= value <= self.high

    def as_dict(self) -> dict:
        return {"low": round(self.low, 2), "high": round(self.high, 2),
                "basis_n": self.basis_n}


@dataclass(frozen=True)
class Observed:
    """What has already happened. Facts, so single numbers are allowed."""

    pairs: int
    comparisons: int
    comparisons_ok: int
    seconds: float

    def as_dict(self) -> dict:
        return {"pairs": self.pairs, "comparisons": self.comparisons,
                "comparisons_ok": self.comparisons_ok,
                "seconds": round(self.seconds, 1)}


@dataclass
class Sizing:
    """Accumulates per-pair observations; answers only what they support.

    Incremental on purpose: a scan feeds it one pair at a time, so the same
    object serves the live progress view and the finished report, and the
    numbers in each are the same numbers.
    """

    _pairs: list = field(default_factory=list)   # (seconds, comparisons, ok)

    # -------------------------------------------------------------- observing

    def observe_pair(self, seconds: float, comparisons: int,
                     comparisons_ok: int) -> None:
        """Record one completed pair — analysed or skipped, both are real cost.

        A skipped pair still consumed wall clock (a dependency install that
        failed can be the most expensive thing in a run), so excluding skips
        would systematically under-state the remaining time. It contributes 0
        comparisons, which is exactly right: it produced none.
        """
        self._pairs.append((float(seconds), int(comparisons), int(comparisons_ok)))

    # ----------------------------------------------------------- measurements

    @property
    def observed(self) -> Observed:
        return Observed(
            pairs=len(self._pairs),
            comparisons=sum(c for _, c, _ in self._pairs),
            comparisons_ok=sum(ok for _, _, ok in self._pairs),
            seconds=sum(s for s, _, _ in self._pairs),
        )

    def per_comparison_seconds(self) -> Range | None:
        """Observed spread of seconds-per-comparison across pairs.

        None when no comparison has been produced. There is no cost-per-thing
        when no thing was produced, and returning a number there would be a
        division by zero wearing a disguise — compound-v2's pilot ran 3 pairs
        and produced 0 comparisons.
        """
        rates = [s / c for s, c, _ in self._pairs if c]
        if not rates:
            return None
        return Range(min(rates), max(rates), len(rates))

    def coverage_pct(self) -> Range | None:
        """Observed spread of per-pair coverage, as percentages.

        The SPREAD, not the aggregate — the aggregate is in `observed` and is a
        fact. This says how much the pairs disagreed with each other, which is
        the honest input to any statement about pairs not yet run.
        """
        pcts = [ok / c * 100 for _, c, ok in self._pairs if c]
        if not pcts:
            return None
        return Range(min(pcts), max(pcts), len(pcts))

    # ------------------------------------------------------------- projection

    def project_remaining(self, remaining_pairs: int) -> Range | None:
        """Seconds still to come, as a range — or None, with `refusal_reason`
        carrying why. Never a single number.

        The bounds are the slowest and fastest PAIRS observed, multiplied out.
        Per-pair rather than per-comparison because what remains is pairs: a
        pair whose whole cost was a failed install has no comparisons to
        multiply and would otherwise vanish from the projection entirely.
        """
        if self.refusal_reason(remaining_pairs):
            return None
        if remaining_pairs <= 0:
            return None
        per_pair = [s for s, _, _ in self._pairs]
        return Range(min(per_pair) * remaining_pairs,
                     max(per_pair) * remaining_pairs, len(per_pair))

    def refusal_reason(self, remaining_pairs: int) -> str:
        """Why no projection is offered, or "" when one is.

        The text is the product, not a debug string: it is what the CLI prints
        and what the web app renders. It says what is wrong with the SAMPLE,
        because "not enough data" invites a reader to wait for more of the same
        biased sample, which is the thing that does not work.
        """
        if remaining_pairs <= 0:
            return ""
        if not self._pairs:
            return ("Nothing has been measured yet, so there is nothing to "
                    "project from. A number here would be invented.")
        if self.observed.comparisons == 0:
            return (
                f"{self.observed.pairs} pair(s) have run and produced NO file "
                f"comparisons at all, so there is no cost-per-comparison to "
                f"measure and no coverage to describe. This is the compound-v2 "
                f"shape: time was spent, nothing was analysed."
            )
        if remaining_pairs > self.observed.pairs:
            return (
                f"No projection: {self.observed.pairs} pair(s) measured, "
                f"{remaining_pairs} still to run. {SPAN_RULE} "
                f"The reason is not sample SIZE — it is that analysable "
                f"coverage tracks commit AGE, which makes an early or "
                f"evenly-spaced sample BIASED rather than merely small, and "
                f"more of a biased sample does not fix it. Measured: a 3-pair "
                f"pilot of aave-v2 gave 48.6s per comparison against an actual "
                f"634.0s, a 13x miss; 88mph piloted at 0.0% coverage and ran "
                f"at 31.7%, while v3-core piloted HIGH at 90.9% and ran at "
                f"84.3%. The misses go both ways, so there is no correction to "
                f"apply. This unlocks itself as the run measures more of its "
                f"own history."
            )
        return ""

    # ----------------------------------------------------------------- output

    def as_dict(self, remaining_pairs: int) -> dict:
        """The whole sizing picture, shaped for a report.

        `projection` and `refusal` are mutually exclusive by construction: one
        of them is always empty, so no front end has to decide which to believe.
        """
        projection = self.project_remaining(remaining_pairs)
        refusal = self.refusal_reason(remaining_pairs)
        spread = self.per_comparison_seconds()
        coverage = self.coverage_pct()
        return {
            "observed": self.observed.as_dict(),
            "per_comparison_seconds": spread.as_dict() if spread else None,
            "coverage_pct": coverage.as_dict() if coverage else None,
            "projection": projection.as_dict() if projection else None,
            "caveat": CAVEAT if projection else "",
            "refusal": refusal,
            "span_rule": SPAN_RULE,
        }


def from_pair_records(records) -> Sizing:
    """Rebuild a `Sizing` from the per-pair records a report carries.

    Lets a finished report be re-sized without re-running it, and keeps the
    scan loop free of sizing logic: it records what happened, this reads it.
    """
    s = Sizing()
    for rec in records or []:
        s.observe_pair(seconds=rec.get("seconds", 0.0),
                       comparisons=rec.get("comparisons", 0),
                       comparisons_ok=rec.get("comparisons_ok", 0))
    return s
