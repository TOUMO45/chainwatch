"""SIZE-L1: sizing a run from a pilot, and why this module refuses to.

`TODO.md` records the failure this exists to prevent: a 3-pair pilot projected
88mph at 0.0% coverage (it ran at 31.7%) and Aave at 48.6s per comparison (it
ran at 634.0s - 13x, turning a projected ~48 minutes into 8.6 hours).

The obvious repair - keep the pilot, put error bars on it - is tested here and
REJECTED, on the recorded data rather than on an argument. Two facts kill it:

  * the misses go BOTH WAYS (v3-core piloted at 90.9% and ran at 84.3%), so no
    one-sided correction is right;
  * a 95% Wilson interval on the pilot's own file counts MISSES aave-v2. The
    width that would cover all four is a constant fitted to four points, which
    is the fudge factor this project does not ship.

The reason it fails is not sample size. HANDOFF.md states it directly -
coverage tracks repo AGE - which makes an evenly-spaced pilot a BIASED sample,
not merely a small one, and no interval width repairs bias.

So `src.sizing` reports MEASUREMENTS of what a run has already done, offers a
projection only over a span no larger than the one it has observed, and refuses
otherwise - in words that say why, because a refusal a user cannot understand
reads as a bug (the standard SCAN-L1's banner set).

Ground truth is `fixtures-sizing/recorded-runs.json`, frozen by guard.sh: nine
real reports, four repositories measured twice. See that directory's README.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import sizing as S  # noqa: E402

RECORDED = json.loads(
    (ROOT / "fixtures-sizing" / "recorded-runs.json").read_text(encoding="utf-8"))


def run(repo: str, kind: str) -> dict:
    for r in RECORDED:
        if r["repo"] == repo and r["kind"] == kind:
            return r
    raise AssertionError("no recorded %s run for %s" % (kind, repo))


def coverage_pct(r: dict) -> float:
    return r["files_ok"] / r["files_total"] * 100 if r["files_total"] else float("nan")


def per_comparison(r: dict) -> float:
    return r["seconds"] / r["files_total"] if r["files_total"] else float("nan")


# ---------------------------------------------------------------------------
# The evidence the design rests on. These test the FIXTURE, not the module -
# deliberately. If the recorded runs ever stop saying this, the refusal below
# has lost its justification and someone must be told, loudly.
# ---------------------------------------------------------------------------

def test_the_recorded_pilots_miss_in_both_directions():
    """Any 'pilots are pessimistic, scale up' correction is wrong on half the
    sample. This is why the answer is a refusal and not an adjustment."""
    under = [("88mph", 0.0, 31.7), ("aave-v2", 6.7, 32.7)]
    over = [("v3-core", 90.9, 84.3), ("v3-periphery", 100.0, 98.7)]

    for repo, pilot_pct, full_pct in under:
        assert coverage_pct(run(repo, "pilot")) < coverage_pct(run(repo, "full"))
        assert round(coverage_pct(run(repo, "pilot")), 1) == pilot_pct
        assert round(coverage_pct(run(repo, "full")), 1) == full_pct
    for repo, pilot_pct, full_pct in over:
        assert coverage_pct(run(repo, "pilot")) > coverage_pct(run(repo, "full"))
        assert round(coverage_pct(run(repo, "pilot")), 1) == pilot_pct
        assert round(coverage_pct(run(repo, "full")), 1) == full_pct


def test_the_aave_cost_miss_is_thirteen_fold():
    pilot, full = run("aave-v2", "pilot"), run("aave-v2", "full")
    assert round(per_comparison(pilot), 1) == 48.6
    assert round(per_comparison(full), 1) == 634.0
    assert per_comparison(full) / per_comparison(pilot) > 13.0


def _wilson(k: int, n: int, z: float) -> tuple[float, float]:
    """Deliberately implemented HERE and not in `src.sizing`.

    The product does not compute confidence intervals, because on this data
    they do not work; keeping the arithmetic in the test is what lets that
    claim be checked without shipping a function whose only use would be to
    tempt someone into using it.
    """
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half) * 100, min(1.0, centre + half) * 100


def test_a_95_percent_interval_on_the_pilot_misses_aave():
    """The measured reason error bars are not the fix. If this ever starts
    passing, the recorded numbers changed and SIZE-L1 needs re-deriving."""
    pilot, full = run("aave-v2", "pilot"), run("aave-v2", "full")
    lo, hi = _wilson(pilot["files_ok"], pilot["files_total"], 1.96)
    truth = coverage_pct(full)
    assert not (lo <= truth <= hi), (
        "the 95%% interval [%.1f, %.1f] now contains %.1f" % (lo, hi, truth))
    assert truth > hi


def test_the_other_three_pilots_are_covered_at_95_percent():
    """Stated so the aave miss cannot be waved away as 'intervals never work'.
    Three of four ARE covered - which is exactly what makes picking a wider
    width look reasonable, and exactly why it is a fit to four points."""
    for repo in ("88mph", "v3-core", "v3-periphery"):
        pilot, full = run(repo, "pilot"), run(repo, "full")
        lo, hi = _wilson(pilot["files_ok"], pilot["files_total"], 1.96)
        assert lo <= coverage_pct(full) <= hi, repo


# ---------------------------------------------------------------------------
# The module: measurements, a bounded projection, and refusals
# ---------------------------------------------------------------------------

def test_nothing_observed_yet_refuses_rather_than_dividing():
    s = S.Sizing()
    assert s.observed.pairs == 0
    out = s.as_dict(remaining_pairs=40)
    assert out["projection"] is None
    assert out["refusal"], "a refusal must always carry its reason"


def test_a_pair_that_compared_nothing_is_not_a_cost_sample():
    """compound-v2's pilot: 3 pairs attempted, 0 comparisons produced. There is
    no per-comparison cost to measure, and inventing one would be a division by
    zero dressed up as a number."""
    s = S.Sizing()
    for _ in range(3):
        s.observe_pair(seconds=254.3, comparisons=0, comparisons_ok=0)
    assert s.observed.pairs == 3
    assert s.observed.comparisons == 0
    assert s.per_comparison_seconds() is None
    out = s.as_dict(remaining_pairs=1)
    assert out["projection"] is None
    assert "compar" in out["refusal"].lower()


def test_measurements_are_reported_as_measurements():
    """A fact about what already happened is a point, and that is fine. What is
    forbidden is a point that claims to describe what has NOT happened."""
    s = S.Sizing()
    s.observe_pair(seconds=100.0, comparisons=10, comparisons_ok=5)
    s.observe_pair(seconds=300.0, comparisons=10, comparisons_ok=10)
    assert s.observed.pairs == 2
    assert s.observed.comparisons == 20
    assert s.observed.comparisons_ok == 15
    assert s.observed.seconds == 400.0

    spread = s.per_comparison_seconds()
    assert (spread.low, spread.high) == (10.0, 30.0), spread
    assert spread.basis_n == 2

    cov = s.coverage_pct()
    assert (cov.low, cov.high) == (50.0, 100.0), cov


def test_a_projection_is_never_a_single_number():
    s = S.Sizing()
    s.observe_pair(seconds=100.0, comparisons=10, comparisons_ok=5)
    s.observe_pair(seconds=300.0, comparisons=10, comparisons_ok=10)
    proj = s.project_remaining(2)
    assert proj is not None
    assert proj.low < proj.high, "a projection collapsed to a point estimate"
    # 2 pairs remaining, observed pair cost 100s..300s
    assert (proj.low, proj.high) == (200.0, 600.0), proj


def test_no_output_field_can_be_read_as_a_prediction():
    """Guards the API surface itself. A `mean`, an `eta`, or an `estimate` is
    the thing every caller would reach for and then quote in a report, so the
    dict must not contain one to reach for."""
    s = S.Sizing()
    s.observe_pair(seconds=100.0, comparisons=10, comparisons_ok=5)
    s.observe_pair(seconds=300.0, comparisons=10, comparisons_ok=10)
    out = s.as_dict(remaining_pairs=2)

    def keys(obj, prefix=""):
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                found.append(prefix + k)
                found += keys(v, prefix + k + ".")
        return found

    banned = ("mean", "average", "avg", "estimate", "eta", "expected", "predict")
    for key in keys(out):
        leaf = key.split(".")[-1].lower()
        assert not any(b in leaf for b in banned), "%s reads as a prediction" % key


# ------------------------------------------------------------------ span rule

def test_it_will_not_project_further_than_it_has_measured():
    """The span rule, which is the whole discipline: never project over a
    remainder larger than the span already observed. Every recorded pilot
    violates it - 3 pairs to size 12 - and that is the point."""
    s = S.Sizing()
    for _ in range(3):
        s.observe_pair(seconds=240.0, comparisons=5, comparisons_ok=1)
    assert s.project_remaining(3) is not None, "3 observed, 3 remaining: allowed"
    assert s.project_remaining(4) is None, "3 observed, 4 remaining: refused"


@pytest.mark.parametrize("repo", ["88mph", "aave-v2", "v3-core", "v3-periphery"])
def test_every_recorded_pilot_would_have_been_refused(repo):
    """The whole point, replayed on the real runs. Each pilot observed 3 pairs
    and was used to size a 12-or-more-pair run; the span rule declines every
    one of them, which is the outcome that would have prevented the 13x miss
    from ever being written down as a projection."""
    pilot, full = run(repo, "pilot"), run(repo, "full")
    s = S.Sizing()
    per_pair = pilot["seconds"] / max(pilot["pairs_total"], 1)
    for _ in range(pilot["pairs_analyzed"]):
        s.observe_pair(seconds=per_pair,
                       comparisons=pilot["files_total"],
                       comparisons_ok=pilot["files_ok"])
    remaining = full["pairs_total"] - pilot["pairs_analyzed"]
    assert remaining > s.observed.pairs, "this pilot did not over-reach; test is void"
    assert s.project_remaining(remaining) is None
    out = s.as_dict(remaining_pairs=remaining)
    assert out["projection"] is None
    assert out["refusal"]


# --------------------------------------------------------------- the UI copy

def test_the_refusal_explains_the_systematic_bias_not_just_the_sample_size():
    """The user-facing requirement. 'Not enough data' invites the reader to
    wait for more; the real reason is that an evenly-spaced sample is BIASED
    because coverage tracks commit age, and more of the same sample does not
    fix that. The text has to say so, in the report, so the CLI and the web app
    cannot disagree about why."""
    s = S.Sizing()
    for _ in range(3):
        s.observe_pair(seconds=240.0, comparisons=5, comparisons_ok=1)
    refusal = s.as_dict(remaining_pairs=40)["refusal"]
    lowered = refusal.lower()
    assert "age" in lowered, "the age correlation is not mentioned"
    assert "13" in refusal, "the measured 13x miss is not cited"
    assert any(w in lowered for w in ("bias", "biased")), "bias is not named"


def test_a_refusal_and_a_projection_are_mutually_exclusive():
    s = S.Sizing()
    for _ in range(4):
        s.observe_pair(seconds=100.0, comparisons=4, comparisons_ok=2)
    ok = s.as_dict(remaining_pairs=2)
    assert ok["projection"] is not None and not ok["refusal"]
    no = s.as_dict(remaining_pairs=99)
    assert no["projection"] is None and no["refusal"]
