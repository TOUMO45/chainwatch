"""METHODOLOGY Face A: `_shared._compile_attempt` and `_storage.storage_layouts`
each ran a fallback loop over every installed solc and, when nothing accepted
the file, raised (or effectively raised) only the LAST candidate's error -
discarding the FIRST (ambient) attempt entirely. That produced three wrong
diagnoses historically (LIMITATIONS.md's METHODOLOGY table), and was measured
live again this session on a real repo (1inch/farming, 2026-08-25): Rule 3c
reported "Invalid option to --combined-json: storage-layout" - the same
compiler-floor symptom the 88mph incident already named - while Rule 1's error
on the same pair named "current compiler is 0.8.19", which is a property of
whichever candidate happened to run last, not of the file.

This is a pure exhaustion test, no real repo needed: a file no solc version
can ever parse (a syntax error, not a version mismatch) forces every
candidate to fail, so the fallback loop is guaranteed to reach its raise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.rules import _shared
from src.rules import _storage

UNPARSEABLE = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Bad { function broken( {{{ not solidity )\n}\n"


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_compile_attempt_reports_first_and_last_on_exhaustion(tmp_path):
    path = _write(tmp_path, "Bad.sol", UNPARSEABLE)
    with pytest.raises(RuntimeError) as exc_info:
        _shared._compile_attempt(path)
    msg = str(exc_info.value)
    assert "first attempt" in msg
    assert "last attempt" in msg
    assert "fallback" in msg


def test_compile_attempt_first_and_last_are_not_the_same_placeholder(tmp_path):
    """Regression guard: a fix that just prints the same string twice would
    still contain both substrings above and pass the first test.

    The FIRST attempt's label is whatever SOLC_VERSION happens to be set to
    when this test runs - `<ambient>` in isolation, but a specific version
    string when an earlier test in the same process left one set (env vars
    are process-global, and this suite does not isolate them). Assert on
    whichever label is actually live, not on a specific one.
    """
    import os

    path = _write(tmp_path, "Bad.sol", UNPARSEABLE)
    expected_first = os.environ.get("SOLC_VERSION") or "<ambient>"
    with pytest.raises(RuntimeError) as exc_info:
        _shared._compile_attempt(path)
    msg = str(exc_info.value)
    assert f"first attempt ({expected_first})" in msg
    assert "after 0 fallback(s)" not in msg, "no candidates were even tried"


def test_storage_layouts_reports_first_and_last_on_exhaustion(tmp_path):
    path = _write(tmp_path, "Bad.sol", UNPARSEABLE)
    _storage.reset_caches()
    with pytest.raises(RuntimeError) as exc_info:
        _storage.storage_layouts(path)
    msg = str(exc_info.value)
    assert "first attempt" in msg
    assert "last attempt" in msg
