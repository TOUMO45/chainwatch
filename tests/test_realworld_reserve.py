"""Real-repository regression test: the six documented Reserve false positives.

Frozen fixtures prove a rule behaves on a case built to exercise it. They do
NOT prove it behaves on the messy original - DESIGN-L2 shipped past ten green
fixture sets precisely because single-file fixtures cannot reproduce an import
closure, and RC-ROLE shipped past a green gate because the STEP 4 fixture
reproduced castSpell's SHAPE but not its MECHANISM. This test closes that gap
by re-running the real commit pairs.

Ground truth, from LIMITATIONS.md / TODO.md (each root-caused and fixed):

    FP1/FP2  43533959..b2cfd51a   DESIGN-L2   -> must be quiet
    FP4      f43202a3..e27227b2   DESIGN-L2   -> AllowanceLib phantom must be gone
    FP3      f43202a3..e27227b2   NOT an FP   -> Rule 5 must still fire on ActFacet
    FP5      cef2f655..7f65c030   R5-L1/AST1  -> must be quiet
    FP6      6481e75d..92ff272f   RC-ROLE     -> must be quiet

The FP3 expectation is the load-bearing half: a fix that silenced everything
would pass a quiet-only test. Requiring the one true positive to survive is
what makes this a precision test rather than a mute button.

Skipped automatically when the Reserve checkout is absent, so the suite still
runs on a fresh clone.

Run:  python -m pytest tests/test_realworld_reserve.py -q -s
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.scan import ScanOptions, scan  # noqa: E402

REPO = ROOT / "realworld-test" / "reserve-src"

pytestmark = pytest.mark.skipif(
    not (REPO / ".git").exists(),
    reason="realworld-test/reserve-src checkout not present",
)

PAIRS = [
    ("43533959", "b2cfd51a"),   # FP1 / FP2
    ("f43202a3", "e27227b2"),   # FP4 (quiet) + FP3 (true positive)
    ("cef2f655", "7f65c030"),   # FP5
    ("6481e75d", "92ff272f"),   # FP6
]

# The ONLY finding these four pairs may produce.
EXPECTED_TRUE_POSITIVE = {
    "rule_id": "5",
    "commit_prefix": "e27227b2",
    "file_suffix": "ActFacet.sol",
}


@pytest.fixture(scope="module")
def report():
    opts = ScanOptions(
        repo=REPO,
        explicit_pairs=PAIRS,
        root_dir="contracts",
        check_head_survival=False,   # verdict-neutral here; keeps the run short
    )
    return scan(opts)


def test_pairs_actually_analyzed(report):
    """A quiet result only means something if the pairs were analysed at all.
    This is the HIST-L1 guard applied to the test itself."""
    cov = report["coverage"]
    assert cov["pairs_analyzed"] == len(PAIRS), (
        f"only {cov['pairs_analyzed']}/{len(PAIRS)} pairs analysed - a quiet "
        f"result here would be unmeasured, not clean. skips={cov['skips']}"
    )
    assert cov["files_total"] > 0, "no file comparisons ran"


def test_no_false_positives_and_true_positive_survives(report):
    findings = report["findings"]
    unexpected = [
        f for f in findings
        if not (f["rule_id"] == EXPECTED_TRUE_POSITIVE["rule_id"]
                and (f["commit"] or "").startswith(EXPECTED_TRUE_POSITIVE["commit_prefix"])
                and f["file"].endswith(EXPECTED_TRUE_POSITIVE["file_suffix"]))
    ]
    assert not unexpected, "false positive(s) returned: " + "; ".join(
        f"rule {f['rule_id']} {f['file']}::{f['contract']}.{f['function']} "
        f"@{(f['commit'] or '')[:8]}" for f in unexpected
    )

    kept = [f for f in findings if f not in unexpected]
    assert kept, (
        "the known TRUE POSITIVE (Rule 5, try/catch removal in ActFacet.sol at "
        "e27227b2) did not fire - a fix that silences real findings is not a fix"
    )


def test_every_finding_is_attributed(report):
    """Whatever fires must name a contract and a function - the product's whole
    claim is 'which commit, which function', not 'something changed'."""
    for f in report["findings"]:
        assert f["contract"], f"finding without a contract: {f}"
        assert f["file"].endswith(".sol"), f"finding without a source file: {f}"
        assert f["commit"], f"finding without a regression commit: {f}"
        assert f["detail"], f"finding without a human-readable explanation: {f}"
