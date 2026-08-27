"""A permanently deleted git dependency must fail fast and say so honestly.

MEASURED against a real target, 0xProject/protocol (2026-08-27). Its yarn.lock
pins a git dependency at https://github.com/0xProject/gitpkg.git, and that
repository has been DELETED from GitHub. A direct, isolated `yarn install`
against a fresh checkout took 7m32s and failed with:

    error Command failed.
    Exit code: 128
    Command: git
    Arguments: ls-remote --tags --heads https://github.com/0xProject/gitpkg.git
    Output:
    remote: Repository not found.
    fatal: repository 'https://github.com/0xProject/gitpkg.git/' not found

This was initially misdiagnosed as "MONO-L1" - a large monorepo simply being
slow. It is not: no timeout, retry, or workspace-scoping fixes a dependency
that no longer exists anywhere to fetch. Before this fix, `_REGISTRY_GONE` did
not recognise this signature, so `install()`'s fallback loop ran a SECOND full
install attempt against the exact same dead dependency - another ~7.5 minutes
proving nothing new - and the eventual cause reported was either the generic
"dep-missing" or, if the combined wait crossed the per-call timeout, the
actively MISLEADING "timeout" (implying "wait longer and it might work", which
is false here).

Run:  python -m pytest tests/test_dead_git_dependency.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.history import _REGISTRY_GONE  # noqa: E402

# The real captured stderr, trimmed - not a paraphrase.
_REAL_YARN_FAILURE = """\
[1/4] Resolving packages...
[2/4] Fetching packages...
error Command failed.
Exit code: 128
Command: git
Arguments: ls-remote --tags --heads https://github.com/0xProject/gitpkg.git
Directory: /repo
Output:
remote: Repository not found.
fatal: repository 'https://github.com/0xProject/gitpkg.git/' not found

info Visit https://yarnpkg.com/en/docs/cli/install for documentation about this command.
"""


def _matches(detail: str) -> bool:
    return any(m in detail for m in _REGISTRY_GONE)


def test_the_real_captured_failure_is_recognised():
    assert _matches(_REAL_YARN_FAILURE)


def test_either_signature_alone_is_sufficient():
    """Different git/yarn versions phrase this slightly differently; matching
    only one half would leave real cases undetected."""
    assert _matches("remote: Repository not found.")
    assert _matches("fatal: repository 'https://example.com/x.git' not found")


def test_ordinary_install_failures_are_unaffected():
    """The fix must not widen what counts as 'permanently gone' - a transient
    network failure or a genuinely missing local tool should keep retrying
    through the normal fallback path, not short-circuit to CAUSE_DEP_GONE."""
    for unrelated in (
        "ETIMEDOUT: connection timed out",
        "npm ERR! network request failed",
        "ENOSPC: no space left on device",
        "sh: solc: command not found",
        "",
    ):
        assert not _matches(unrelated), unrelated


def test_existing_signatures_are_still_present():
    """Regression guard: the new entries must be ADDITIVE."""
    for original in ("404 Not Found", "ETARGET", "no matching version",
                     "Couldn't find package", "not found in the registry"):
        assert original in _REGISTRY_GONE
