"""SEC-L1 - a malicious target repository must not read the host filesystem
through a tracked symlink.

THE REAL RISK, MEASURED. Chainwatch clones and compiles arbitrary, untrusted
public repositories - that is the whole product. A git blob tracked at file
mode 120000 is a symlink; on checkout, whatever it points to is exactly what
every rule and every compiler subsequently opens through this worktree's
paths, with no sandbox boundary of its own. Confirmed directly on this
project's own dev machine: `core.symlinks=false` there, so a hand-crafted
120000 blob checks out as an inert plain-text file (confirmed:
`is_symlink()` is False, content is the literal target-path string, not the
target's content) - but Linux, the actual Cloud Run production target,
defaults `core.symlinks` to enabled wherever the filesystem supports it,
which is the ordinary case for a container. A repository submitted through
the public web form could therefore commit a symlink at `evil.sol` pointing
at `/etc/passwd`, a service-account token, or (this project's own history)
a leaked `.env` - and a solc parse-error snippet on a partial-content parse
failure is a real, standing content-disclosure channel for whatever it
points to, independent of whether the "compile" ever fully succeeds.

WHY DELETE RATHER THAN "CHECK IT STAYS INSIDE THE WORKTREE". A
containment check still lets compile SUCCESS vs FAILURE serve as an
existence oracle for arbitrary host paths (does /root/.ssh/id_rsa exist?
different solc error either way). Deleting the entry denies that signal too
- the missing file is reported through the same "could not be read" path
any other unreadable file already takes, not a new special case.

Windows privilege restrictions block creating a REAL symlink in this
project's own dev sandbox (also confirmed directly - `os.symlink` raises
WinError 1314 without elevation, a standard, well-documented OS restriction
having nothing to do with Chainwatch). These tests therefore verify the
function's actual LOGIC via `Path.is_symlink` monkeypatching rather than
depending on this specific machine's ability to create one - a real symlink,
where the platform allows it, is covered separately in
`test_strip_symlinks_removes_a_real_symlink_where_the_platform_allows_it`.

Run:  python -m pytest tests/test_symlink_strip.py -q
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.history import _strip_symlinks, Worktree  # noqa: E402


def test_a_symlink_is_removed(tmp_path, monkeypatch):
    """The core behaviour, verified by construction rather than by relying on
    this sandbox's ability to create a real OS symlink."""
    evil = tmp_path / "evil.sol"
    evil.write_text("placeholder", encoding="utf-8")

    real_is_symlink = Path.is_symlink

    def fake_is_symlink(self):
        return self.name == "evil.sol" or real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)
    stripped = _strip_symlinks(tmp_path)
    assert stripped == ["evil.sol"]
    assert not evil.exists(), "the symlink entry must be gone after stripping"


def test_an_ordinary_file_is_left_alone(tmp_path):
    real = tmp_path / "Legit.sol"
    real.write_text("contract Legit {}", encoding="utf-8")
    stripped = _strip_symlinks(tmp_path)
    assert stripped == []
    assert real.is_file()
    assert real.read_text(encoding="utf-8") == "contract Legit {}"


def test_a_symlink_nested_in_a_subdirectory_is_found(tmp_path, monkeypatch):
    """A malicious repo would not necessarily place it at the root."""
    sub = tmp_path / "contracts" / "libs"
    sub.mkdir(parents=True)
    evil = sub / "Evil.sol"
    evil.write_text("x", encoding="utf-8")

    real_is_symlink = Path.is_symlink

    def fake_is_symlink(self):
        return self.name == "Evil.sol" or real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)
    stripped = _strip_symlinks(tmp_path)
    assert stripped == ["contracts/libs/Evil.sol"], \
        "relative path must use forward slashes regardless of platform"


def test_stripping_reports_the_relative_path_not_the_absolute_one(tmp_path, monkeypatch):
    """The absolute host path must never be echoed back into a report -
    exactly the kind of accidental disclosure this fix exists to prevent
    elsewhere."""
    evil = tmp_path / "evil.sol"
    evil.write_text("x", encoding="utf-8")
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "evil.sol")
    stripped = _strip_symlinks(tmp_path)
    assert stripped == ["evil.sol"]
    assert str(tmp_path) not in stripped[0]


def test_worktree_checkout_returns_what_was_stripped(monkeypatch, tmp_path):
    """Worktree.checkout's return value is the actual product surface
    (scan.py's `checkout()` wrapper reads it to decide whether to emit a
    warning) - lock the contract, not just the helper function underneath."""
    class _FakeGit:
        def __call__(self, *a, **k):
            return ""

    wt = Worktree.__new__(Worktree)  # bypass __init__'s real `worktree add`
    wt.repo = tmp_path
    wt.path = tmp_path
    wt.sha = None

    import src.history as H
    monkeypatch.setattr(H, "_git", lambda *a, **k: "")
    monkeypatch.setattr(H, "_strip_symlinks", lambda root: ["evil.sol", "b/Evil2.sol"])

    result = wt.checkout("deadbeef" * 5)
    assert result == ["evil.sol", "b/Evil2.sol"]


def test_checkout_of_the_same_sha_twice_does_not_rerun_git(monkeypatch, tmp_path):
    """No-op re-checkout (same sha.sha) must not call git a second time -
    and must return an empty list, not None, so scan.py's `if stripped:`
    check works unconditionally."""
    wt = Worktree.__new__(Worktree)
    wt.repo = tmp_path
    wt.path = tmp_path
    wt.sha = "abc123"

    calls = []
    import src.history as H
    monkeypatch.setattr(H, "_git", lambda *a, **k: calls.append(a) or "")
    result = wt.checkout("abc123")
    assert result == []
    assert not calls, "git was invoked despite the sha being unchanged"


@pytest.mark.skipif(
    os.name != "posix",
    reason="Windows needs elevated privileges to create a real symlink; "
           "the logic itself is covered by the monkeypatched tests above")
def test_strip_symlinks_removes_a_real_symlink_where_the_platform_allows_it(tmp_path):
    """Where the platform permits it (any ordinary Linux CI runner, and the
    real Cloud Run production target), exercise a GENUINE OS symlink end to
    end - not a simulation of one."""
    target = tmp_path.parent / "real-secret-for-test.txt"
    target.write_text("must never leak", encoding="utf-8")
    evil = tmp_path / "evil.sol"
    evil.symlink_to(target)
    assert evil.is_symlink()

    stripped = _strip_symlinks(tmp_path)
    assert stripped == ["evil.sol"]
    assert not evil.exists()
    assert target.is_file(), "the REAL target file must be untouched - only the link is removed"
