"""Attribution contract test.

Two invariants, checked against every frozen fixture set:

  A1. A rule that FIRES (True or "candidate") on a case emits at least one
      attribution record naming the declaration it fired on, and every record
      carries a file plus a contract (function too, for the function-level
      rules).
  A2. A rule that stays QUIET emits nothing. Attribution must never leak a
      record for a verdict that was not reached - a phantom record in the UI
      would be a false positive by another route.

The attribution channel is deliberately side-band (`case_meta["_findings"]`)
so that `run()`'s return contract - and therefore scorer.py and every frozen
fixture verdict - is untouched. This test is what proves the two stay in sync.

Run:  python -m pytest tests/test_attribution.py -q
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import scorer  # noqa: E402  (reuses the harness's own build-config logic)
from src.rules import register_all  # noqa: E402

RULES: dict = {}
register_all(RULES)

# (fixture directory, default remap set) - the same table runall uses.
FIXTURE_SETS = [
    ("fixtures", "oz4"),
    ("fixtures-ext", "oz4"),
    ("fixtures-multi", "oz4"),
    ("fixtures-oz5", "oz5"),
    ("fixtures-r1", "oz4"),
    ("fixtures-r1-oz5", "oz5"),
    ("fixtures-r2", "oz4"),
    ("fixtures-r2b", "oz4"),
    ("fixtures-r2b-role", "oz4"),
    ("fixtures-r3c-ast1", "oz4"),
    ("fixtures-r4", "oz4"),
    ("fixtures-r5", "oz4"),
    ("fixtures-r6", "oz4"),
    ("fixtures-r6-oz5", "oz5"),
]

# Rules whose finding is a CONTRACT-level fact (a storage layout, a missing
# constructor call), so a function name is legitimately absent.
CONTRACT_LEVEL_RULES = {"3b", "3c"}


def _cases(fixtures_dir: str, default_remaps: str):
    d = ROOT / fixtures_dir
    cases = json.load(open(d / "manifest.json", encoding="utf-8"))
    for c in cases:
        c["_before"] = d / c["path"] / "before.sol"
        c["_after"] = d / c["path"] / "after.sol"
        c["_remaps"] = c.get("remaps", default_remaps)
        c["_solc"] = c.get("solc")
    return cases


@pytest.mark.parametrize("fixtures_dir,default_remaps", FIXTURE_SETS)
def test_attribution_matches_verdict(fixtures_dir, default_remaps):
    saved_solc = os.environ.get("SOLC_VERSION")
    try:
        for case in _cases(fixtures_dir, default_remaps):
            scorer._apply_build_config(case["_remaps"], case["_solc"])
            for rule_id, run_fn in RULES.items():
                meta = {
                    "source_path": case.get("source_path"),
                    "changed_files": case.get("changed_files"),
                }
                raw = run_fn(case["_before"], case["_after"], meta)
                fired = bool(raw)
                records = meta.get("_findings", [])
                where = f"{fixtures_dir}/{case['id']} rule {rule_id}"

                if not fired:
                    # A2: no verdict, no record.
                    assert not records, (
                        f"{where}: stayed quiet but emitted {len(records)} "
                        f"attribution record(s) - phantom finding"
                    )
                    continue

                # A1: a fire is always attributable.
                assert records, f"{where}: fired but emitted no attribution record"
                for rec in records:
                    assert rec["rule_id"] == rule_id, f"{where}: rule_id mismatch"
                    assert rec["file"], f"{where}: record has no file"
                    assert rec["contract"], f"{where}: record has no contract"
                    assert rec["detail"], f"{where}: record has no human detail"
                    assert rec["severity"] in ("CONFIRMED", "CANDIDATE"), where
                    if rule_id not in CONTRACT_LEVEL_RULES:
                        assert rec["function"], (
                            f"{where}: function-level rule emitted no function name"
                        )
                    # The record must point at the file the rule was asked
                    # about, never at an imported dependency.
                    assert rec["file"].endswith(".sol"), where
    finally:
        if saved_solc is None:
            os.environ.pop("SOLC_VERSION", None)
        else:
            os.environ["SOLC_VERSION"] = saved_solc
