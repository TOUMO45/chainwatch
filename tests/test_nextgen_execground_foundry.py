"""Phase 5 - the Foundry toolchain adapter (src/nextgen/execground/foundry.py).

Path helpers are pure and always run. The live checks (resolve / run / temp
file round-trip) run only when a real toolchain (native `forge` or WSL) is
reachable, and skip visibly otherwise.

Run:  python -m pytest tests/test_nextgen_execground_foundry.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.execground import foundry as F  # noqa: E402


def test_win_to_wsl_path_translation():
    assert F._win_to_wsl(r"C:\Users\x\y.sh") == "/mnt/c/Users/x/y.sh"
    assert F._win_to_wsl("B:\\Desktop\\Chainwatch") == "/mnt/b/Desktop/Chainwatch"
    assert F._win_to_wsl("/already/posix") == "/already/posix"


def test_sh_quote_is_injection_safe():
    q = F._sh_quote("a'b; rm -rf /")
    assert q.startswith("'") and q.endswith("'")
    assert "'\"'\"'" in q


_TC = F.resolve()
_HAVE = _TC is not None
_skip = pytest.mark.skipif(not _HAVE, reason="no reachable Foundry toolchain "
                                             "(native or WSL)")


@_skip
def test_status_reports_a_forge_version():
    st = F.status()
    assert st["available"] is True
    assert "forge" in st["version"].lower()
    assert st["kind"] in ("native", "wsl")


@_skip
def test_run_forge_version():
    r = _TC.run(["forge", "--version"], cwd=None, timeout=60)
    assert r.ok and "forge" in (r.stdout + r.stderr).lower()


@_skip
def test_tempdir_write_read_rmtree_round_trip():
    wd = _TC.make_tempdir(prefix="cw-fnd-test-")
    assert wd
    try:
        assert _TC.write_file(f"{wd}/hello.txt", "line one\nline two\n")
        assert _TC.read_file(f"{wd}/hello.txt") == "line one\nline two\n"
        # a nested path is created
        assert _TC.write_file(f"{wd}/a/b/c.txt", "deep")
        assert _TC.read_file(f"{wd}/a/b/c.txt") == "deep"
    finally:
        _TC.rmtree(wd)
    assert _TC.read_file(f"{wd}/hello.txt") is None
