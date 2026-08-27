"""BACKTEST-1 - the harness that asks "would we have caught the real incident?"

`scorer.py` measures the rules against fixtures this project wrote, which is
necessary and also self-referential. A backtest anchors to an incident someone
else suffered, at a commit someone else wrote, with the answer already settled
by a public post-mortem.

That makes the harness itself safety-critical in a specific way: a backtest that
overstates is worse than no backtest, because the number LOOKS rigorous. These
tests pin the two properties that keep it honest:

  1. `_matches` requires every field the case names. A case that could be
     satisfied by "some rule fired somewhere in the repository" would let a
     detector claim credit for an unrelated finding.
  2. UNRUNNABLE is not MISSED. A miss over code that never compiled is
     UNMEASURED, not a false negative; collapsing the two lets an environment
     problem masquerade as detector quality (METHODOLOGY Face A, applied to the
     harness).

Run:  python -m pytest tests/test_backtest.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backtest as B  # noqa: E402

_EXPECT = {"rule": "10", "file": "contracts/NFT.sol",
           "contract": "NFT", "function": "init"}
_HIT = {"rule_id": "10", "file": "contracts/NFT.sol",
        "contract": "NFT", "function": "init"}


# ------------------------------------------------------------- _matches


def test_an_exact_match_counts():
    assert B._matches(_HIT, _EXPECT)


def test_rule_id_is_compared_as_a_string():
    """Rule ids are strings ('2a', '3b'), but a JSON case could carry 10 as an
    int. A type mismatch must not silently turn a CAUGHT into a MISSED."""
    assert B._matches({**_HIT, "rule_id": 10}, {**_EXPECT, "rule": 10})
    assert B._matches({**_HIT, "rule_id": "10"}, {**_EXPECT, "rule": 10})


def test_a_different_function_is_not_a_match():
    """THE CORE HONESTY PROPERTY. Rule 10 firing on some other function in the
    same contract is not evidence this incident would have been caught."""
    assert not B._matches({**_HIT, "function": "setOwner"}, _EXPECT)


def test_a_different_contract_is_not_a_match():
    assert not B._matches({**_HIT, "contract": "Vault"}, _EXPECT)


def test_a_different_rule_is_not_a_match():
    assert not B._matches({**_HIT, "rule_id": "1"}, _EXPECT)


def test_a_different_file_is_not_a_match():
    assert not B._matches({**_HIT, "file": "contracts/Other.sol"}, _EXPECT)


def test_path_is_matched_by_suffix_and_separator_agnostically():
    """`file` arrives repo-relative but may be reported with either separator;
    a case must not fail on a backslash."""
    assert B._matches({**_HIT, "file": "some/prefix/contracts/NFT.sol"}, _EXPECT)
    assert B._matches({**_HIT, "file": r"contracts\NFT.sol"}, _EXPECT)


def test_fields_the_case_omits_are_not_constrained():
    """A case may legitimately name only a rule and a contract (a
    contract-level finding has no function at all)."""
    loose = {"rule": "3c", "contract": "DInterest"}
    assert B._matches({"rule_id": "3c", "contract": "DInterest",
                       "function": None, "file": "x.sol"}, loose)


# ------------------------------------------------------- corpus integrity


def test_the_shipped_corpus_is_wellformed():
    """Every case must carry what the admission rule requires - notably a
    public `source`, without which the case is unverifiable by a reader."""
    cases = B.load_cases()
    assert cases, "corpus is empty"
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    for c in cases:
        for field in ("id", "repo", "parent", "commit", "expect", "source"):
            assert c.get(field), f"{c.get('id')} missing {field}"
        assert c["source"].startswith("http"), f"{c['id']} source is not a URL"
        assert c["expect"].get("rule"), f"{c['id']} names no rule"
        # A 40-char hex sha, not a 12-char prefix: the admission rule requires
        # the commit to have been resolved against the real repository.
        for field in ("parent", "commit"):
            sha = c[field]
            assert len(sha) == 40 and all(ch in "0123456789abcdef" for ch in sha), \
                f"{c['id']}.{field} is not a full resolved sha: {sha}"


def test_corpus_file_is_valid_json_with_its_admission_rule_intact():
    data = json.loads(B.CASES_FILE.read_text(encoding="utf-8"))
    readme = " ".join(data.get("_README", []))
    assert "resolved against the REAL" in readme, \
        "the admission rule was removed from the corpus file"


# --------------------------------------------------------- status handling


def test_a_missing_repo_is_unrunnable_not_missed(tmp_path):
    """An absent checkout says nothing about the detector, and must never be
    counted as a miss."""
    res = B.run_case({
        "id": "absent", "repo": str(tmp_path / "nope"),
        "parent": "a" * 40, "commit": "b" * 40,
        "expect": _EXPECT, "clone_url": "https://example.invalid/x",
    })
    assert res["status"] == B.UNRUNNABLE
    assert "not a git checkout" in res["reason"]


def test_statuses_are_three_distinct_values():
    assert len({B.CAUGHT, B.MISSED, B.UNRUNNABLE}) == 3
