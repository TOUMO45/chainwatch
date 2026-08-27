"""Regression test for a real crash found this session (2026-08-26), live,
scanning `1inch/swap-vm`: `subprocess.run(..., text=True, ...)` with no
explicit `encoding=` decodes a subprocess's stdout/stderr using
`locale.getpreferredencoding(False)` - on Windows this is the system's ANSI
codepage (e.g. `cp1252`), NOT UTF-8. Git always writes UTF-8. Any real commit
whose message, diff, or file content contains a non-ASCII character outside
cp1252's range (an emoji in a commit message, an accented name, a non-Latin
comment - all common in real-world repositories) crashes the decode inside
Python's internal `_readerthread`, which then leaves `proc.stdout` as `None`
rather than raising somewhere the caller could catch - so
`scan.changed_line_ranges` failed with a bare, uninformative
`AttributeError: 'NoneType' object has no attribute 'splitlines'` deep
inside the pipeline, on real, legitimate commit content, not malformed data.

Fixed by passing `encoding="utf-8", errors="replace"` at every
`subprocess.run(..., text=True, ...)` call site in `src/history.py`,
`src/rules/_storage.py`, `src/scan.py` and `webapp/server.py` (12 sites, all
sharing the exact same exposure) - `errors="replace"` so a genuinely
non-UTF-8 byte sequence (rare, but git accepts arbitrary bytes in a commit
message) degrades to a replacement character instead of crashing the whole
scan a second time.

Windows-only in practice (Linux containers typically default their locale to
UTF-8 already, which is very likely why this went unnoticed through every
Linux-based Cloud Run run this project has done), but the fix - explicit
`encoding="utf-8"` - is correct and harmless on any platform, so this test
runs everywhere `git` is on PATH.

Run:  python -m pytest tests/test_git_encoding.py -q
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import history as H  # noqa: E402
from src.scan import changed_line_ranges  # noqa: E402


def _run(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True,
                   capture_output=True)


#  U+1F30D (Earth Globe Europe-Africa) encodes in UTF-8 as f0 9f 8c 8d - the
#  last byte, 0x8d, is one of a handful of byte values cp1252 defines NO
#  character for at all (0x81, 0x8d, 0x8f, 0x90, 0x9d). That specific gap is
#  what turned a routine `git diff` into a crash: this project measured it
#  directly - `bytes([0x8d]).decode("cp1252")` raises the identical
#  `UnicodeDecodeError` this test now locks a fix for, and a handful of other
#  emoji tried during that measurement did NOT reproduce it (their UTF-8
#  bytes happened to avoid cp1252's undefined set), which is exactly why an
#  arbitrary-looking emoji choice here would be the wrong fixture - it has to
#  be ONE OF THESE FIVE BYTES specifically, not "some non-ASCII text".
_GLOBE = "\U0001F30D"


@pytest.fixture()
def utf8_repo(tmp_path):
    """A real, tiny git repo whose second commit's DIFF contains the exact
    class of multi-byte UTF-8 content that crashed the unfixed code -
    verified against this project's own real crash, not a synthetic string
    that merely looks similar. See `_GLOBE` above for why this specific
    character, not any non-ASCII one, is what makes this fixture real."""
    repo = tmp_path / "utf8repo"
    repo.mkdir()
    _run(repo, "init", "-q")
    _run(repo, "config", "user.email", "test@example.com")
    _run(repo, "config", "user.name", "Test")

    f = repo / "Vault.sol"
    f.write_text("// base file\ncontract Vault {}\n", encoding="utf-8")
    _run(repo, "add", "Vault.sol")
    _run(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base commit")
    prev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                          capture_output=True, text=True, encoding="utf-8").stdout.strip()

    f.write_text(
        "// base file\n"
        f"// {_GLOBE} refactored withdraw() for gas\n"
        "contract Vault {\n"
        "    function withdraw() external {}\n"
        "}\n",
        encoding="utf-8",
    )
    _run(repo, "add", "Vault.sol")
    _run(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m",
        f"refactor: withdraw() {_GLOBE}")
    cur = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                         capture_output=True, text=True, encoding="utf-8").stdout.strip()

    return repo, prev, cur


def test_git_diff_survives_real_utf8_content(utf8_repo):
    """The exact failing call from the crash: a raw `git diff -U0` whose
    output contains multi-byte UTF-8. Must return a real string, never
    `None`, and never raise."""
    repo, prev, cur = utf8_repo
    out = H._git(repo, "diff", "-U0", prev, cur, "--", "Vault.sol")
    assert out is not None
    assert isinstance(out, str)
    assert "@@" in out   # a real hunk header was parsed back out


def test_changed_line_ranges_survives_real_utf8_content(utf8_repo):
    """The actual code path that crashed live on `1inch/swap-vm`:
    `scan.changed_line_ranges` calling `.splitlines()` on the diff output.
    Before the fix this raised `AttributeError: 'NoneType' object has no
    attribute 'splitlines'` on real commit content - not a contrived case."""
    repo, prev, cur = utf8_repo
    ranges = changed_line_ranges(repo, prev, cur, "Vault.sol")
    assert ranges != []
    assert all(isinstance(r, tuple) and len(r) == 2 for r in ranges)


def test_git_log_survives_utf8_commit_message(utf8_repo):
    """commit_meta and sol_commit_pairs both read commit subjects; a
    UTF-8 subject line must not crash log parsing either."""
    repo, prev, cur = utf8_repo
    out = H._git(repo, "log", "-1", "--format=%s", cur)
    assert _GLOBE in out
