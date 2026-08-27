"""COV-ACCT1 / COV-ACCT2 - coverage is earned per RULE, not per file.

Both findings came out of one real measurement (2026-08-27, sweep over eleven
local repositories). 88mph reported `file comparisons ok: 0/43 (0.0%)` while
nine of its ten rules had in fact run cleanly on every one of those 43 files
and produced a genuine rule-10 finding. The pair that produced that finding was
recorded `comparisons_ok: 0`.

Two separate defects stacked to produce that:

  COV-ACCT1  `file_ok` was ONE boolean spanning ~10 rule invocations, so a
             single failure discarded the credit for every rule that succeeded
             on that file. Fixed by counting `(file, rule)` invocations and
             splitting files into three buckets (ok / partial / lost).

  COV-ACCT2  Rule 3c needs `solc --combined-json storage-layout`, an option that
             does not exist below ~0.6.x - verified directly against solc 0.5.17,
             which answers `Invalid option to --combined-json: storage-layout`
             and nothing else. The compiler rejects the FLAG, so nothing was
             learned about the source either way. That was being counted as a
             rule error. Fixed with `RuleUnsupported`, which removes the
             invocation from BOTH sides of the coverage fraction.

The direction of the bug matters: it made the tool UNDERSTATE itself, which is
why it survived - it never tripped the zero-false-positive alarm. But it makes
every coverage-based judgement wrong, and coverage is what this project asks a
reader to consult before believing a quiet result.

Run:  python -m pytest tests/test_coverage_accounting.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.rules._shared import RuleUnsupported  # noqa: E402
from src.scan import Coverage, _run_rule  # noqa: E402
import src.scan as S  # noqa: E402


# --------------------------------------------------------------- _run_rule


def _fake_rule(result):
    """A rule stand-in. `result` is either a raw verdict or an exception."""
    def run(before_p, after_p, meta):
        if isinstance(result, Exception):
            raise result
        return result
    return run


def _with_rule(monkeypatch, rule_id, fn):
    monkeypatch.setitem(S.RULES, rule_id, fn)


def test_run_rule_reports_unsupported_separately(monkeypatch):
    """A RuleUnsupported must come back flagged, not as an ordinary error."""
    _with_rule(monkeypatch, "3c", _fake_rule(RuleUnsupported("no such option")))
    raw, records, err, unsupported = _run_rule("3c", Path("a"), Path("b"), {})
    assert raw is False
    assert records == []
    assert err and "no such option" in err
    assert unsupported is True


def test_run_rule_reports_real_error_as_not_unsupported(monkeypatch):
    """A genuine failure must NOT be excused as out-of-range."""
    _with_rule(monkeypatch, "3c", _fake_rule(RuntimeError("compiler exploded")))
    raw, _records, err, unsupported = _run_rule("3c", Path("a"), Path("b"), {})
    assert raw is False
    assert err and "compiler exploded" in err
    assert unsupported is False


def test_run_rule_success_is_unchanged(monkeypatch):
    _with_rule(monkeypatch, "1", _fake_rule(False))
    raw, records, err, unsupported = _run_rule("1", Path("a"), Path("b"), {})
    assert (raw, records, err, unsupported) == (False, [], None, False)


# --------------------------------------------------------------- Coverage


def test_unsupported_leaves_the_answerable_fraction_at_full():
    """THE 88mph CASE, in miniature. Ten rules per file, one of which cannot be
    asked of this compiler at all: the answerable work is 100% done, and the
    old file-level view must no longer report zero."""
    cov = Coverage()
    cov.files_total = 43
    for _ in range(43):
        for _rule in range(9):
            cov.rule_invocations_total += 1
            cov.rule_invocations_ok += 1
        cov.rule_invocations_total += 1
        cov.rule_invocations_unsupported += 1
        cov.files_ok += 1          # no rule FAILED, so the file is fully analysed

    d = cov.as_dict()
    assert d["rule_invocations_total"] == 430
    assert d["rule_invocations_ok"] == 387
    assert d["rule_invocations_unsupported"] == 43
    assert d["rule_invocations_error"] == 0
    # 430 asked, 43 unaskable -> 387 answerable, all 387 answered.
    assert d["rule_invocations_answerable"] == 387
    assert d["rule_coverage_pct"] == 100.0
    # And the headline file number is no longer 0/43.
    assert d["files_ok"] == 43
    assert d["files_ok_pct"] == 100.0


def test_real_rule_error_still_reduces_coverage():
    """The guard against over-correcting: a rule that BREAKS must still cost
    coverage. `unsupported` is not a way to make failures disappear."""
    cov = Coverage()
    cov.files_total = 1
    cov.rule_invocations_total = 10
    cov.rule_invocations_ok = 7
    cov.rule_invocations_error = 3
    cov.files_partial = 1

    d = cov.as_dict()
    assert d["rule_invocations_answerable"] == 10   # nothing excused
    assert d["rule_coverage_pct"] == 70.0
    assert d["files_partial"] == 1


def test_partial_is_distinct_from_lost():
    """A file where 9 of 10 rules ran is NOT the same as a file where nothing
    compiled, and the report must not collapse them."""
    cov = Coverage()
    cov.files_total = 2
    cov.files_partial = 1     # some rules ran
    cov.files_error = 1       # nothing ran
    cov.rule_invocations_total = 20
    cov.rule_invocations_ok = 9
    cov.rule_invocations_error = 11

    d = cov.as_dict()
    assert d["files_partial"] == 1
    assert d["files_error"] == 1
    assert d["files_ok"] == 0
    assert d["rule_coverage_pct"] == 45.0


def test_empty_scan_reports_zero_not_a_crash():
    """Nothing analysed must not divide by zero - and must not read as 100%."""
    d = Coverage().as_dict()
    assert d["rule_coverage_pct"] == 0.0
    assert d["rule_invocations_answerable"] == 0
    assert d["files_ok_pct"] == 0.0


def test_a_broken_source_is_never_excused_as_unsupported(tmp_path):
    """THE DANGEROUS EDGE, and a mistake this fix actually made on its first
    attempt. `solc_candidates` returns EVERY installed compiler, merely ranked -
    it does not filter by pragma. So a 0.5.x candidate rejects the
    `storage-layout` flag for ANY file, including one that is simply broken.
    Keying "unsupported" off a flag rejection alone therefore excused genuine
    syntax errors and inflated coverage - the one direction this project must
    never fail in.

    A file no compiler can parse must still raise RuntimeError (a real failure
    that costs coverage), never RuleUnsupported.
    """
    import pytest

    from src.rules import _storage

    bad = tmp_path / "Bad.sol"
    bad.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "contract Bad { function broken( {{{ not solidity )\n}\n",
        encoding="utf-8")
    _storage.reset_caches()
    with pytest.raises(RuntimeError) as exc:
        _storage.storage_layouts(bad)
    assert not isinstance(exc.value, RuleUnsupported), \
        "a source the compiler rejected must not be reported as out-of-range"


def test_all_unsupported_does_not_report_full_coverage():
    """The dangerous edge of COV-ACCT2: if EVERY rule was unaskable, the
    answerable denominator is zero. That must report 0.0%, never 100% - an
    empty question set is not a completed one."""
    cov = Coverage()
    cov.files_total = 5
    cov.rule_invocations_total = 50
    cov.rule_invocations_unsupported = 50

    d = cov.as_dict()
    assert d["rule_invocations_answerable"] == 0
    assert d["rule_coverage_pct"] == 0.0
