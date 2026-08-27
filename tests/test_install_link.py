"""Unit tests for `src/history.py`'s dependency cache linking (11-L2).

Fast, deterministic, no real npm/network - a synthetic cache entry plus a
synthetic dangling junction, both built with `tmp_path`, exercise exactly the
failure this project's own trajectory walker hit for real on 88mph
(`a4c48d61661a`): `H.install()` reported "cache hit" while the worktree's
`node_modules` silently resolved to nothing, because a stale directory entry
left by an earlier run (its cache target since cleared) blocked `mklink`
without the failure ever being checked. See LIMITATIONS.md §11-L2.

Windows-only (junctions are a Windows mechanism); skipped elsewhere.

Run:  python -m pytest tests/test_install_link.py -q
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import history as H  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "nt", reason="junctions are Windows-only")


def _mklink(link: Path, target: Path) -> None:
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                   capture_output=True, text=True, check=True)


def _make_spec(root: Path) -> H.EnvSpec:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"dependencies": {"left-pad": "1.0.0"}}',
                                       encoding="utf-8")
    return H.detect_env(root)


def test_dangling_junction_from_an_earlier_run_is_cleared_and_relinked(tmp_path):
    """The real 88mph failure, reproduced deterministically.

    Sequence that produced it for real: a cache entry existed and was linked
    into a worktree; the cache entry was later cleared (a fresh `.walker-cache`
    wipe, in the real case); the worktree's `node_modules` junction was left
    dangling - its directory ENTRY still present, its target gone. A later run
    populates a (possibly different-content, but here same-key) cache entry
    and calls `install()` again: before the fix, `_link_dir`'s `mklink`
    silently failed (`Cannot create a file when that file already exists`,
    returncode never checked) and `install()` still returned `(True, ...)`.
    """
    root = tmp_path / "worktree"
    spec = _make_spec(root)
    cache_root = tmp_path / "cache"
    entry = cache_root / spec.key
    real_node_modules = entry / "node_modules"
    real_node_modules.mkdir(parents=True)
    (real_node_modules / "left-pad").mkdir()
    (real_node_modules / "left-pad" / "index.js").write_text("// stub",
                                                              encoding="utf-8")
    H._write_marker(entry, spec)

    # Simulate the dangling junction: link the worktree to a DIFFERENT,
    # now-deleted cache directory, so the entry at `link` is stale but real.
    link = root / "node_modules"
    ghost_target = tmp_path / "ghost" / "node_modules"
    ghost_target.mkdir(parents=True)
    _mklink(link, ghost_target)
    import shutil
    shutil.rmtree(tmp_path / "ghost")

    assert not link.exists(), "the junction must be dangling before install() runs"
    assert os.path.lexists(link), "but the directory ENTRY must still be present"

    ok, cause, detail = H.install(spec, cache_root)

    assert ok, f"install() must succeed once the stale entry is cleared: {cause} {detail}"
    assert link.is_dir(), "node_modules must resolve to a real directory afterward"
    assert (link / "left-pad" / "index.js").is_file(), \
        "the RIGHT cache content must be what the link resolves to"


def test_working_link_already_present_is_left_alone(tmp_path):
    """Regression guard: a link that already resolves correctly must not be
    torn down and relinked on every call - only a stale/dangling one."""
    root = tmp_path / "worktree"
    spec = _make_spec(root)
    cache_root = tmp_path / "cache"
    entry = cache_root / spec.key
    real_node_modules = entry / "node_modules"
    real_node_modules.mkdir(parents=True)
    (real_node_modules / "marker.txt").write_text("original", encoding="utf-8")
    H._write_marker(entry, spec)

    link = root / "node_modules"
    _mklink(link, real_node_modules)
    assert link.is_dir()

    ok, cause, detail = H.install(spec, cache_root)

    assert ok, f"{cause} {detail}"
    assert (link / "marker.txt").read_text(encoding="utf-8") == "original"
