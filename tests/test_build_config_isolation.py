"""11-L4 / TEST-ISO - a scan must not leave process-wide build config behind.

`_apply_build_config` points four process-wide globals at the checkout it is
configuring: `_shared.REMAPS`, `_storage.REMAPPINGS`, `_storage.PROJECT_ROOT`
and the `SOLC_VERSION` environment variable. The first three are consulted only
as a FALLBACK - both `_shared.remaps_for` and `_storage._root_and_remaps`
prefer a registered root and reach the global only for a path outside every
registered checkout.

In-process, that fallback set is precisely `fixtures/`. So a single scan left
every later fixture parse in the same interpreter pointed at some scanned
repository's dependency tree, and left the compiler pinned to that repository's
commit. `tests/test_exposure.py` still carries the work-around this forced: it
snapshots `_shared.REMAPS` at collection time and restores it around each
fixture-parsing test. That is a patch at one call site for a leak at the
source; the decorator on `scan()` fixes it for every caller, including future
tests that would otherwise have had to know about the hazard.

These tests use a stub rather than a real repository: the leak is a property of
`scan()`'s wrapper, and asserting it needs no compilation.

Run:  python -m pytest tests/test_build_config_isolation.py -q
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import src.scan as S  # noqa: E402
from src.rules import _shared, _storage  # noqa: E402


@pytest.fixture()
def pristine():
    """Snapshot the four globals, and guarantee restoration even on failure."""
    saved = (list(_shared.REMAPS), list(_storage.REMAPPINGS),
             _storage.PROJECT_ROOT, os.environ.get("SOLC_VERSION"),
             list(_shared._ROOT_REMAPS))
    yield saved
    _shared.REMAPS, _storage.REMAPPINGS = list(saved[0]), list(saved[1])
    _storage.PROJECT_ROOT = saved[2]
    if saved[3] is None:
        os.environ.pop("SOLC_VERSION", None)
    else:
        os.environ["SOLC_VERSION"] = saved[3]
    _shared._ROOT_REMAPS[:] = saved[4]


def _dirty_everything():
    """Exactly what `_apply_build_config` does, without needing a checkout."""
    _shared.REMAPS = ["@scanned/=/somewhere/node_modules/@scanned/"]
    _storage.REMAPPINGS = list(_shared.REMAPS)
    _storage.PROJECT_ROOT = Path("/somewhere/else")
    _shared.register_root("/somewhere/else", _shared.REMAPS)
    os.environ["SOLC_VERSION"] = "0.4.11"


def test_globals_are_restored_after_a_scan(pristine, monkeypatch):
    """The core guarantee: whatever the scan body does to the globals, the
    caller's process is handed back unchanged."""
    saved_remaps, saved_remappings, saved_root, saved_solc, _ = pristine

    @S._restores_build_config
    def fake_scan():
        _dirty_everything()
        return {"ok": True}

    assert fake_scan() == {"ok": True}
    assert _shared.REMAPS == saved_remaps
    assert _storage.REMAPPINGS == saved_remappings
    assert _storage.PROJECT_ROOT == saved_root
    assert os.environ.get("SOLC_VERSION") == saved_solc
    assert not _shared._ROOT_REMAPS, "registered roots leaked past the scan"


def test_globals_are_restored_even_when_the_scan_raises(pristine):
    """A scan that dies mid-walk must not poison the interpreter either - this
    is the case that actually bit, since a failing scan is exactly when a test
    run continues on to other tests."""
    saved_remaps, _, saved_root, saved_solc, _ = pristine

    @S._restores_build_config
    def exploding_scan():
        _dirty_everything()
        raise RuntimeError("compiler exploded mid-walk")

    with pytest.raises(RuntimeError, match="compiler exploded"):
        exploding_scan()

    assert _shared.REMAPS == saved_remaps
    assert _storage.PROJECT_ROOT == saved_root
    assert os.environ.get("SOLC_VERSION") == saved_solc
    assert not _shared._ROOT_REMAPS


def test_solc_version_is_unset_again_when_it_started_unset(pristine):
    """Restoring must distinguish "was absent" from "was empty string": leaving
    SOLC_VERSION='' pins the compiler to nothing and fails differently."""
    os.environ.pop("SOLC_VERSION", None)

    @S._restores_build_config
    def fake_scan():
        os.environ["SOLC_VERSION"] = "0.8.30"

    fake_scan()
    assert "SOLC_VERSION" not in os.environ


def test_the_config_is_still_live_during_the_scan(pristine):
    """Restore-AFTER, not never-set. Any code path not yet taught about
    registered roots must still see the scanned checkout's config while the
    scan is running - that is the documented reason these globals are set."""
    seen = {}

    @S._restores_build_config
    def fake_scan():
        _dirty_everything()
        seen["remaps"] = list(_shared.REMAPS)
        seen["root"] = _storage.PROJECT_ROOT

    fake_scan()
    assert seen["remaps"] == ["@scanned/=/somewhere/node_modules/@scanned/"]
    assert seen["root"] == Path("/somewhere/else")


def test_scan_still_carries_its_public_identity():
    """`functools.wraps` matters: the web app and CLI introspect nothing, but a
    decorator that renamed `scan` would break any future caller that does."""
    assert S.scan.__name__ == "scan"
    assert S.scan.__doc__ and "Walk the repository" in S.scan.__doc__
