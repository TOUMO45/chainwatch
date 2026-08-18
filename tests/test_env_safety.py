"""CHARTER rule 5, enforced as a test: a scan NEVER executes target code.

This file exists because the guarantee was found to be false (WALK-L9). Two
independent paths let a scanned repository run arbitrary commands on the
machine doing the scanning:

  G1a  the yarn install guard was Berry-only. `yarn install --immutable
       --mode=skip-build` under yarn 1.x ignores both unknown flags, EXITS 0
       (so the yarn-1 fallback carrying the real `--ignore-scripts` never
       ran), and executes `prepare`/`postinstall`.

  G1b  one such script - `husky install`, which is what morpho-blue's
       `prepare` runs - writes `core.hooksPath` into the git config of OUR
       scratch mirror. From then on EVERY `git checkout` through that mirror
       executed the target's `.husky/*` hooks, for every commit of every
       later scan against it.

Both are asserted here against a hermetic temp repository carrying the same
payloads a real target would, because the only trustworthy statement about
code execution is one a test can fail on.

NO NETWORK. The fixtures declare no dependencies; what is under test is
whether the installer runs a SCRIPT, not whether it can fetch a package.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import history as H  # noqa: E402


def _has(exe: str) -> bool:
    return shutil.which(exe) is not None


def _sentinel_script(target: Path) -> str:
    """A node one-liner that leaves proof it ran, at `target`."""
    p = target.as_posix()
    return "node -e \"require('fs').writeFileSync('" + p + "','executed')\""


# --------------------------------------------------------------------------- G1a


@pytest.mark.skipif(not _has("yarn") or not _has("node"),
                    reason="yarn/node not installed")
def test_yarn_lifecycle_scripts_never_execute(tmp_path):
    """G1a. A yarn project whose `prepare` writes a sentinel must install
    without that sentinel ever appearing.

    This is morpho-blue's package.json reduced to its essentials: a yarn 1
    lockfile plus a `prepare` script. Before the fix it wrote the sentinel AND
    returned ok=True - it executed target code and reported success.
    """
    root = tmp_path / "proj"
    root.mkdir()
    sentinel = tmp_path / "PREPARE_RAN"
    (root / "package.json").write_text(json.dumps({
        "name": "victim", "version": "1.0.0",
        "scripts": {"prepare": _sentinel_script(sentinel),
                    "postinstall": _sentinel_script(sentinel)},
        "dependencies": {},
    }), encoding="utf-8")
    (root / "yarn.lock").write_text("# yarn lockfile v1\n\n\n", encoding="utf-8")

    spec = H.detect_env(root)
    assert spec.node_manager == "yarn"

    ok, cause, detail = H.install(spec, tmp_path / "cache")

    assert not sentinel.exists(), (
        "target lifecycle script EXECUTED during install "
        "(ok=%r cause=%r detail=%r)" % (ok, cause, detail))


@pytest.mark.skipif(not _has("npm") or not _has("node"),
                    reason="npm/node not installed")
def test_npm_lifecycle_scripts_never_execute(tmp_path):
    """The npm side of the same guarantee, so the yarn fix cannot be mistaken
    for the whole of it."""
    root = tmp_path / "proj"
    root.mkdir()
    sentinel = tmp_path / "PREPARE_RAN_NPM"
    (root / "package.json").write_text(json.dumps({
        "name": "victim", "version": "1.0.0",
        "scripts": {"prepare": _sentinel_script(sentinel),
                    "postinstall": _sentinel_script(sentinel)},
        "dependencies": {},
    }), encoding="utf-8")

    spec = H.detect_env(root)
    assert spec.node_manager == "npm"
    H.install(spec, tmp_path / "cache")
    assert not sentinel.exists(), "npm lifecycle script EXECUTED during install"


def test_yarn_flavor_is_decided_without_running_the_target(tmp_path):
    """The Berry-vs-classic decision must come from FILES, not from invoking a
    binary inside the target: a Berry project can ship its own yarn under
    `.yarn/releases/`, so `yarn --version` run there is target code."""
    classic = tmp_path / "classic"
    classic.mkdir()
    (classic / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
    assert H.yarn_flavor(classic) == "classic"

    berry = tmp_path / "berry"
    berry.mkdir()
    (berry / ".yarnrc.yml").write_text("nodeLinker: node-modules\n", encoding="utf-8")
    (berry / "yarn.lock").write_text("__metadata:\n  version: 8\n", encoding="utf-8")
    assert H.yarn_flavor(berry) == "berry"

    berry_lock_only = tmp_path / "berry2"
    berry_lock_only.mkdir()
    (berry_lock_only / "yarn.lock").write_text(
        "__metadata:\n  version: 8\n  cacheKey: 10\n", encoding="utf-8")
    assert H.yarn_flavor(berry_lock_only) == "berry"

    berry_pm = tmp_path / "berry3"
    berry_pm.mkdir()
    (berry_pm / "package.json").write_text(
        json.dumps({"packageManager": "yarn@3.6.4"}), encoding="utf-8")
    assert H.yarn_flavor(berry_pm) == "berry"


def test_classic_yarn_command_carries_the_flag_yarn1_understands():
    """Regression lock on the actual defect: every yarn-1 command must carry
    `--ignore-scripts`, and none may carry Berry-only syntax that yarn 1
    silently ignores while exiting 0."""
    cmds = H.install_commands("yarn", flavor="classic")
    assert cmds, "no install command produced for classic yarn"
    for cmd in cmds:
        assert "--ignore-scripts" in cmd, "%r has no guard yarn 1 obeys" % (cmd,)
        assert "--mode=skip-build" not in cmd, (
            "%r leads with Berry syntax; yarn 1 ignores it and exits 0, so the "
            "guarded fallback never runs (WALK-L9)" % (cmd,))


def test_berry_command_keeps_its_own_guard():
    cmds = H.install_commands("yarn", flavor="berry")
    assert cmds
    for cmd in cmds:
        assert "--mode=skip-build" in cmd
        assert "--ignore-scripts" not in cmd, (
            "Berry rejects --ignore-scripts; passing it turns a safe install "
            "into a failed one")


def test_npm_and_pnpm_commands_still_guarded():
    for mgr in ("npm", "pnpm"):
        cmds = H.install_commands(mgr)
        assert cmds
        for cmd in cmds:
            assert "--ignore-scripts" in cmd, "%s: %r" % (mgr, cmd)


# --------------------------------------------------------------------------- G1b


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, "git %s: %s" % (" ".join(args), proc.stderr)
    return proc.stdout


def _hostile_repo(tmp_path: Path, sentinel: Path, name: str = "hostile"):
    """A git repo shipping an executable post-checkout hook, plus two commits
    so a checkout between them is a real checkout."""
    src = tmp_path / name
    (src / ".husky").mkdir(parents=True)
    hook = src / ".husky" / "post-checkout"
    hook.write_text("#!/bin/sh\nprintf 'executed' > '%s'\n" % sentinel.as_posix(),
                    encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    (src / "A.sol").write_text("pragma solidity ^0.8.0; contract A {}\n",
                               encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(src)], capture_output=True,
                   text=True, timeout=120, check=True)
    _git(src, "config", "user.email", "t@example.com")
    _git(src, "config", "user.name", "t")
    _git(src, "config", "core.hooksPath", ".git/hooks")   # keep OUR commits clean
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "one")
    first = _git(src, "rev-parse", "HEAD").strip()
    (src / "A.sol").write_text("pragma solidity ^0.8.0; contract A { uint x; }\n",
                               encoding="utf-8")
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "two")
    second = _git(src, "rev-parse", "HEAD").strip()
    return src, first, second


def test_target_hooks_never_execute_even_when_config_is_poisoned(tmp_path):
    """G1b, the dangerous half.

    The mirror's config is DELIBERATELY poisoned here exactly the way `husky
    install` poisoned it in the real run, because the guarantee cannot rest on
    the target failing to poison it. After the fix, no hook may execute no
    matter what the config says.
    """
    sentinel = tmp_path / "HOOK_RAN"
    src, first, second = _hostile_repo(tmp_path, sentinel)

    scratch = tmp_path / "scratch"
    origin = H.mirror_clone(src, scratch / "origin.git")

    # The poison. Not hypothetical: this is what was found in
    # .walker-worktrees/<hash>/origin.git/config after scanning morpho-blue.
    _git(origin, "config", "core.hooksPath", ".husky")

    wt = H.Worktree(origin, scratch / "wt" / "prev")
    wt.checkout(second)
    wt.checkout(first)          # a real checkout: the tree changes

    assert not sentinel.exists(), (
        "the target repository's post-checkout hook EXECUTED during a scan "
        "checkout (CHARTER rule 5)")


def test_checkout_succeeds_despite_a_hostile_hook(tmp_path):
    """The same defect's OTHER cost. A hook that exits non-zero made `git
    checkout` return 1, which the walker booked as `checkout-failed` and lost
    the pair - 6 of morpho-blue's 15 pairs died this way, and the recorded
    reason named a failure that had not happened."""
    sentinel = tmp_path / "HOOK_RAN2"
    src, first, _second = _hostile_repo(tmp_path, sentinel, name="hostile2")
    hook = src / ".husky" / "post-checkout"
    hook.write_text("#!/bin/sh\nexit 127\n", encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "hostile hook")
    third = _git(src, "rev-parse", "HEAD").strip()

    scratch = tmp_path / "scratch2"
    origin = H.mirror_clone(src, scratch / "origin.git")
    _git(origin, "config", "core.hooksPath", ".husky")

    wt = H.Worktree(origin, scratch / "wt" / "prev")
    wt.checkout(third)
    wt.checkout(first)          # must NOT raise
    assert (scratch / "wt" / "prev" / "A.sol").is_file()


def test_mirror_clone_neutralises_hooks_path(tmp_path):
    """Belt and braces: `-c` on every invocation protects git commands routed
    through `_git`; the STORED config protects the ones that are not - the web
    app runs `git diff` and `git show` directly."""
    sentinel = tmp_path / "HOOK_RAN3"
    src, _first, _second = _hostile_repo(tmp_path, sentinel, name="hostile3")
    origin = H.mirror_clone(src, tmp_path / "scratch3" / "origin.git")

    stored = subprocess.run(["git", "config", "--get", "core.hooksPath"],
                            cwd=str(origin), capture_output=True,
                            text=True).stdout.strip()
    assert stored, "mirror does not pin core.hooksPath at all"
    hooks_dir = Path(stored)
    if hooks_dir.is_dir():
        assert not any(hooks_dir.iterdir()), (
            "core.hooksPath points at %s, which is not empty" % hooks_dir)


def test_existing_poisoned_mirror_is_repaired_on_reuse(tmp_path):
    """A scratch directory poisoned by an EARLIER version must be CLEANED when
    reused, not merely overridden at call time. Real machines already carry
    these: .walker-worktrees/0bbc8f13b9 did."""
    sentinel = tmp_path / "HOOK_RAN4"
    src, _first, _second = _hostile_repo(tmp_path, sentinel, name="hostile4")
    dest = tmp_path / "scratch4" / "origin.git"
    origin = H.mirror_clone(src, dest)
    _git(origin, "config", "core.hooksPath", ".husky")

    origin2 = H.mirror_clone(src, dest)          # reuse path
    stored = subprocess.run(["git", "config", "--get", "core.hooksPath"],
                            cwd=str(origin2), capture_output=True,
                            text=True).stdout.strip()
    assert stored != ".husky", (
        "reusing a poisoned scratch mirror left the target's hooksPath in place")
