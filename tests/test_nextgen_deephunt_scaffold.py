"""Deep Hunt Phase 0 - the scaffold is present, flag-gated, and additive.

Run:  python -m pytest tests/test_nextgen_deephunt_scaffold.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent


def test_flag_off_by_default(monkeypatch):
    monkeypatch.delenv("CHAINWATCH_DEEPHUNT", raising=False)
    from src.nextgen import deephunt
    assert deephunt.enabled() is False


def test_flag_on_when_set(monkeypatch):
    from src.nextgen import deephunt
    for v in ("1", "true", "YES", "on"):
        monkeypatch.setenv("CHAINWATCH_DEEPHUNT", v)
        assert deephunt.enabled() is True
    monkeypatch.setenv("CHAINWATCH_DEEPHUNT", "0")
    assert deephunt.enabled() is False


def test_package_imports_without_slither_or_key():
    # importing the package must not require slither / eth_utils / a Gemini key
    import importlib
    m = importlib.import_module("src.nextgen.deephunt")
    assert hasattr(m, "enabled")


def test_classic_path_does_not_reference_deephunt():
    """The classic scanner and verdict engine must not import the new package."""
    for rel in ("src/scan.py", "src/verdict.py", "src/rules/__init__.py"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "deephunt" not in text, f"{rel} references deephunt"


def test_nextgen_pipeline_does_not_import_deephunt():
    text = (ROOT / "src/nextgen/pipeline.py").read_text(encoding="utf-8")
    assert "deephunt" not in text
