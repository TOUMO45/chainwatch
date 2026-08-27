"""Trajectory mode - commit-history walking with per-commit environment
reconstruction. Mitigates HIST-L1 (see LIMITATIONS.md).

The problem this exists to solve: at a historical commit a repo's dependencies
(node_modules/, lib/) are gitignored and absent, so every import fails and the
pair is unanalyzable. Measured on reserve-protocol/protocol: 0 of 29 pairs
compiled. crytic-compile already knows HOW to build Foundry/Hardhat/Truffle
projects; what it cannot do is materialise the dependency set that a commit
declared. This module does that, then hands off.

Pipeline per pair (N-1, N):
  1. check the commit out into a scratch worktree (never the target's own tree)
  2. detect the dependency system declared AT that commit
  3. install it, cached, with install scripts disabled
  4. derive remappings and the pinned solc from the reconstructed tree
  5. compile the changed contracts -> Slither objects
  6. hand those to the rules; on failure record a CAUSE, never a silent skip

CHARTER rule 5 (read-only on the target): this module only ever READS the target
repo's history. `git worktree add` writes worktree bookkeeping into the target's
.git; EXTRACT_ARCHIVE mode avoids even that at the cost of losing submodule
support. Nothing is ever committed, pushed, or written to a tracked path.

READ-ONLY IS NOT THE SAME AS DOES-NOT-EXECUTE, and this module got that wrong
once (WALK-L9). A target can hand us code to run through two channels that have
nothing to do with writing to it: package-manager lifecycle scripts, and git
hooks reached via `core.hooksPath`. Both are now closed by construction rather
than by convention - see `git_safety_args` / `harden_repo` for the hook channel
and `yarn_flavor` / `install_commands` for the script channel.

HIST-L1 reporting invariant: `walk()` returns per-pair outcomes with an explicit
cause for every non-analyzed pair. A caller that reports detections without also
reporting the analyzable/skipped ratio is reporting a broken result - "0
detections" is meaningless without coverage.

SECURITY: dependency installs run with lifecycle scripts DISABLED - npm and pnpm
`--ignore-scripts`, yarn 1 `--ignore-scripts`, yarn Berry `--mode=skip-build`
plus `YARN_ENABLE_SCRIPTS=0`. Installing a historical dependency set means
fetching arbitrary third-party code; executing its postinstall hooks is a
remote-code-execution surface and is not something a static analyser needs.
Native modules will not build as a result. If a project genuinely requires
scripts to produce a compilable tree, `install()` records NEEDS_SCRIPTS rather
than silently enabling them - that is a human decision, per project.

The yarn line matters because the two majors take INCOMPATIBLE guard flags and
yarn 1 does not complain about Berry's: it ignores them, exits 0, and runs the
scripts anyway. This sentence used to say "yarn --mode=skip-build" without
qualification and was therefore false for every yarn-1 target (WALK-L9).
`install_commands` now selects on a statically detected flavour, so which guard
applies is a decision, not a side effect of which command failed first.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# failure causes - every unanalyzable pair gets exactly one of these
# ---------------------------------------------------------------------------

CAUSE_DEP_MISSING = "dep-missing"            # no install performed / deps absent
CAUSE_DEP_GONE = "dep-gone-from-registry"    # install ran but resolution failed
CAUSE_SOLC_ABSENT = "solc-absent"            # pinned compiler unavailable
CAUSE_REMAPPING = "remapping"                # import unresolved despite deps
CAUSE_NEEDS_SCRIPTS = "needs-install-scripts"  # build requires lifecycle scripts

# Node 17+ ships OpenSSL 3, which withdrew the legacy hash provider that older
# JS toolchains still reach for; the installer then dies with this. It is a
# property of the HOST's Node, not of the repository being analysed - which is
# why it is worth one retry rather than a skip (DEP-2). Both spellings appear
# depending on Node version and which layer surfaces the error.
_LEGACY_OPENSSL_MARKERS = (
    "ERR_OSSL_EVP_UNSUPPORTED",
    "digital envelope routines::unsupported",
)


def _needs_legacy_openssl(detail: str) -> bool:
    """True iff an install failed for the OpenSSL-3 legacy-provider reason."""
    return any(m in (detail or "") for m in _LEGACY_OPENSSL_MARKERS)
CAUSE_TIMEOUT = "timeout"                    # install/build exceeded its cap
CAUSE_COMPILE = "compile-error"              # source itself does not compile
CAUSE_UNKNOWN = "unknown"

# Written into a cache entry only after its install has been VERIFIED complete.
# Its absence is what makes an unfinished or poisoned entry a cache miss rather
# than a permanent silent wrong answer (finding HIST-L4).
MARKER = ".chainwatch-install-ok"

# ---------------------------------------------------------------------------
# git: read-only history access, and NEVER an execution surface
# ---------------------------------------------------------------------------

# WALK-L9. A git repository can be configured to run arbitrary commands on
# ordinary read operations: `core.hooksPath` redirects hook lookup at any
# directory, and `git checkout` fires `post-checkout` from it. That is a
# problem for this project specifically, because
#
#   (a) targets DO ship hooks - husky puts them in a tracked `.husky/`
#       directory, so they arrive with the clone, and
#   (b) the setting that activates them was written into OUR OWN scratch
#       mirror's config by a target's `prepare` script (see `install`), which
#       means every later checkout of every later scan through that mirror ran
#       target code.
#
# The guarantee cannot be "targets do not do this". It is enforced instead by
# pointing hook lookup at a directory Chainwatch owns and keeps empty, on
# EVERY invocation - so the answer does not depend on what any config says.
HOOKS_DENY = Path(__file__).resolve().parent.parent / ".git-hooks-denied"


def hooks_deny_dir() -> Path:
    """The empty directory git is told to look for hooks in. Created on demand.

    A real, empty, existing directory rather than `/dev/null` or a bogus path:
    it is portable (Windows has no /dev/null path), it is unambiguous to a
    human reading `git config`, and "the directory exists and is EMPTY" is a
    property a test can assert directly. Nothing is ever written into it - not
    even a `.gitignore`, which would weaken that assertion to a judgement call
    about which filenames count as hooks; this repository's own `.gitignore`
    keeps it out of history instead.
    """
    try:
        HOOKS_DENY.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return HOOKS_DENY


def git_safety_args() -> list[str]:
    """`-c` overrides that must precede EVERY git subcommand we run.

    Command-line `-c` outranks repository, global and system config, so this
    holds even against a mirror whose config was poisoned by an earlier run.
    Exported because two callers run git directly rather than through `_git`:
    `webapp/server.py` (clone, diff, show) and `chainwatch.py` (clone).

    An EMPTY `credential.helper` resets the helper list rather than adding to
    it, which is what makes CHARTER rule 5's "never authenticate beyond
    public-read" true mechanically rather than by intention. Without it, a
    configured helper answers for us: on Windows `git-credential-manager` opens
    a GUI dialog, and a scan launched from a web request waits on a window
    nobody will ever see.
    """
    return ["-c", f"core.hooksPath={hooks_deny_dir()}",
            "-c", "credential.helper="]


def git_safety_env() -> dict:
    """Environment half of the same guarantee, for what `-c` cannot express.

    `GIT_TERMINAL_PROMPT=0` turns a username prompt into an immediate error.
    `GCM_INTERACTIVE=never` covers Git Credential Manager, which is a separate
    program with its own idea of interactivity and does not read git's flag.
    Both are belt and braces on top of the cleared helper list: any one of the
    three alone is enough, and the failure mode of getting this wrong is a
    thirty-minute hang rather than an error, so all three are set.
    """
    return {"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never",
            "GIT_ASKPASS": "", "SSH_ASKPASS": ""}


def harden_repo(repo) -> None:
    """Persist the hook denial into a repository WE created.

    `git_safety_args` already protects every invocation this module makes; this
    is the second layer, for git commands issued elsewhere in the process (and
    for a human who opens the scratch clone by hand). It also REPAIRS a scratch
    mirror that an earlier version already let a target poison - overriding at
    call time would leave the bad value sitting in the config file.

    REFUSES to act on a path that is not itself a repository or worktree.
    `git config` walks UP to find one, and the scratch worktrees live inside
    Chainwatch's own checkout - so an unguarded call on a directory that had
    lost its `.git` would write into the developer's repository instead of the
    scratch clone. Writing config into a repository we were not asked to touch
    is precisely the class of thing this function exists to prevent.
    """
    repo = Path(repo)
    if not (repo / ".git").exists() and not (repo / "HEAD").is_file():
        return
    try:
        subprocess.run(["git", "config", "core.hooksPath", str(hooks_deny_dir())],
                       cwd=str(repo), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    except Exception:  # noqa: BLE001 - the -c override is the guarantee, not this
        pass


def _git(repo, *args, check=True, timeout=300):
    proc = subprocess.run(
        ["git", *git_safety_args(), *args],
        cwd=str(repo), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        env={**os.environ, **git_safety_env()},
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{proc.stderr.strip()[:400]}")
    return proc.stdout


# Ordered most-specific first: GitHub answers 401 for a private repo AND for
# one that does not exist, so the credential message is the common case and
# must not be reported as "not found" only.
_CLONE_FAILURES = [
    (("could not read username", "authentication failed", "invalid username or password",
      "terminal prompts disabled", "no such identity", "permission denied (publickey)"),
     "this repository is private, or does not exist. Chainwatch clones "
     "anonymously and can only scan PUBLIC repositories - it never "
     "authenticates (CHARTER rule 5). Check the URL, or use a local path to a "
     "clone you already have."),
    (("repository not found", "not found", "does not appear to be a git repository",
      "could not read from remote repository"),
     "this repository does not exist at that URL, or it is private. "
     "Chainwatch only scans PUBLIC repositories."),
    (("could not resolve host", "failed to connect", "connection timed out",
      "network is unreachable", "operation timed out", "ssl certificate problem"),
     "the network could not reach that host. This is an environment failure, "
     "not a result about the repository - nothing was analysed."),
    (("disk quota", "no space left"),
     "the machine ran out of disk space while cloning. Nothing was analysed."),
]


def classify_clone_failure(stderr: str) -> str:
    """A sentence a first-time user can act on, from git's stderr.

    The old callers reported `stderr[:400]`, and on a failed clone the first
    400 characters are the "Cloning into '...'" progress line - the sentence
    that says WHY is further down and got cut. Worse, "0 findings because the
    clone failed" and "0 findings because the code is clean" are the same
    screen unless the reason survives.

    An unrecognised failure is passed through VERBATIM rather than replaced by
    a guess. A wrong explanation is worse than a raw one.
    """
    low = (stderr or "").lower()
    for needles, message in _CLONE_FAILURES:
        if any(n in low for n in needles):
            return message
    tail = " ".join((stderr or "").split())
    return tail[-400:] if tail else "git failed without writing a reason"


def clone_public(url: str, dest, timeout: int = 1800, on_progress=None) -> Path:
    """Anonymous, read-only clone of a PUBLIC repository into `dest/<name>`.

    One implementation for both front ends, for the same reason `scan()` is one
    implementation of a scan: the CLI and the web app disagreeing about what a
    clone means is how one of them ends up without the safety flags.

    Full history, never shallow - trajectory is the product and a shallow clone
    has no trajectory. Reuses an existing clone rather than re-fetching.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    target = dest / name
    if (target / ".git").exists():
        harden_repo(target)
        return target
    if on_progress:
        on_progress(f"cloning {url} (full history, anonymous, read-only)")
    proc = subprocess.run(
        ["git", *git_safety_args(), "clone", url, str(target)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        env={**os.environ, **git_safety_env()},
    )
    if proc.returncode != 0:
        raise RuntimeError(f"clone failed: {classify_clone_failure(proc.stderr)}")
    harden_repo(target)
    return target


def sol_commits(repo, limit: int, pathspec: str = "**/*.sol") -> list[str]:
    """Commits touching Solidity, newest first."""
    out = _git(repo, "log", "--format=%H", f"-{limit}", "--", pathspec)
    return out.split()


def commit_pairs(shas: list[str]) -> list[tuple[str, str]]:
    """DEPRECATED — pairs consecutive members of a filtered commit list, which
    are not necessarily git parent and child. When the previous filter step
    dropped a commit's true git parent (e.g. `git log -- **/*.sol` skips a
    commit that touched no .sol), this returns (older_ancestor, cur) instead of
    (parent, cur). Kept for backward compatibility with a scratch script only;
    new callers must use `sol_commit_pairs`.
    """
    return [(shas[i + 1], shas[i]) for i in range(len(shas) - 1)]


def sol_commit_pairs(repo, limit: int, pathspec: str = "**/*.sol") -> list[tuple[str, str]]:
    """[(first_parent, cur)] for each commit that touches `pathspec`, newest first.

    Fixes the mispairing in `commit_pairs`: each analysed commit is paired with
    its ACTUAL git first parent, not the previous member of a filter-narrowed
    list. `%P` on `git log` gives all parents; the first is the mainline
    predecessor (git's `--first-parent` convention on a merge). The `.sol` diff
    between (first_parent, cur) matches (older_ancestor, cur) for linear history
    that touched no .sol in between; on merges or when the intervening tree
    changed the build environment, first-parent is the correct N-1 side.

    A root commit (no parent) is skipped: no comparable N-1 side exists.
    """
    out = _git(repo, "log", "--format=%H %P", f"-{limit}", "--", pathspec)
    pairs: list[tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue  # root commit
        pairs.append((parts[1], parts[0]))
    return pairs


# ---------------------------------------------------------------------------
# scope: which directories hold THIS repository's own Solidity (SCAN-L1)
# ---------------------------------------------------------------------------

# Directory names that never hold a protocol's own deployable Solidity.
# Matched on any path SEGMENT: `packages/x/test/y.sol` is as much a test as
# `test/y.sol`. NEVER matched on the FILENAME - reserve-protocol ships
# `contracts/facade/FacadeTest.sol`, a deployed facade, and dropping it because
# of its name would lose real contracts silently.
NON_SOURCE_SEGMENTS = frozenset({
    "test", "tests", "testing",
    "mock", "mocks", "mocked",
    "spec", "specs", "certora", "echidna", "halmos", "fuzz", "invariant",
    "script", "scripts",
    "example", "examples", "sample", "samples", "demo",
    "audits", "audit", "docs", "doc",
    "node_modules", "lib", "libs", "vendor", "third_party", "external",
    "out", "artifacts", "cache", "coverage", "build", "typechain",
})

# Directories that hold OTHER projects rather than source: the useful root is
# one level deeper. Seen whenever a protocol ships a monorepo.
CONTAINER_SEGMENTS = frozenset({"packages", "apps", "modules", "projects"})

# Conventional source roots, preferred over a bare file count when present.
SOURCE_ROOT_NAMES = ("contracts", "src")


def _is_non_source(path: str) -> bool:
    """True when any DIRECTORY segment of `path` names a non-source location."""
    return any(seg.lower() in NON_SOURCE_SEGMENTS for seg in path.split("/")[:-1])


def detect_source_scope(repo, ref: str = "HEAD") -> dict:
    """Which directories hold this repository's own Solidity, decided from the
    tree rather than from a default someone typed into a form.

    The web app shipped `root_dir` pre-filled with `contracts`; morpho-blue
    keeps its Solidity in `src/`, so every diff was empty, every pair counted as
    analysed, and the scan reported a clean 0 findings having compiled nothing.

    THE COUNTING ORDER IS THE WHOLE ALGORITHM. morpho-blue's `test/` holds 29
    .sol files against `src/`'s 22, so any rule that ranks directories by file
    count BEFORE removing test locations picks the tests. Non-source names are
    therefore removed first and never compete.

    Returns roots (possibly `[""]`, meaning the repository root), the exclusion
    segments that go with them, the counts behind the decision, and a `reason`
    string the UI shows the user - because a scope chosen for someone is a scope
    they are entitled to see.
    """
    try:
        out = _git(repo, "ls-tree", "-r", "--name-only", ref)
    except Exception as exc:  # noqa: BLE001 - an unreadable tree is not a crash
        return {"roots": [], "exclude_segments": sorted(NON_SOURCE_SEGMENTS),
                "total_files": 0, "source_files": 0, "excluded_files": 0,
                "counts": {}, "reason": f"could not read the tree at {ref}: {exc}"}

    paths = [p for p in out.splitlines() if p.endswith(".sol")]
    source = [p for p in paths if not _is_non_source(p)]
    base = {"exclude_segments": sorted(NON_SOURCE_SEGMENTS),
            "total_files": len(paths), "source_files": len(source),
            "excluded_files": len(paths) - len(source)}

    if not paths:
        return {**base, "roots": [], "counts": {},
                "reason": "no Solidity files are tracked at this revision"}
    if not source:
        return {**base, "roots": [], "counts": {},
                "reason": (f"all {len(paths)} tracked Solidity files sit under "
                           f"test, mock or vendor directories - this repository "
                           f"has no source tree to walk")}

    def root_of(path: str) -> str:
        segs = path.split("/")
        if len(segs) == 1:
            return ""                                  # .sol at the repo root
        if segs[0].lower() in CONTAINER_SEGMENTS and len(segs) > 2:
            return "/".join(segs[:2])                  # packages/<project>
        return segs[0]

    counts: dict[str, int] = {}
    for p in source:
        counts[root_of(p)] = counts.get(root_of(p), 0) + 1

    named = [r for r in counts if r.split("/")[-1].lower() in SOURCE_ROOT_NAMES]
    if named:
        roots = sorted(named, key=lambda r: (-counts[r], r))
        picked = sum(counts[r] for r in roots)
        reason = (f"{'/, '.join(roots)}/ is a conventional Solidity source "
                  f"directory: {picked} contract{'' if picked == 1 else 's'} of "
                  f"{len(paths)} tracked .sol files")
    else:
        roots = sorted(counts, key=lambda r: (-counts[r], r))
        shown = ", ".join((r + "/") if r else "the repository root" for r in roots)
        picked = sum(counts[r] for r in roots)
        reason = (f"no contracts/ or src/ directory is present; {shown} "
                  f"hold{'s' if len(roots) == 1 else ''} this repository's "
                  f"{picked} non-test .sol files of {len(paths)} tracked")
    if base["excluded_files"]:
        reason += (f". {base['excluded_files']} file"
                   f"{'' if base['excluded_files'] == 1 else 's'} under test, "
                   f"mock or vendor directories are excluded")
    return {**base, "roots": roots, "counts": counts, "reason": reason}


def changed_sol(repo, prev: str, cur: str, root: str = "",
                roots: list | None = None,
                exclude_segments=None) -> dict:
    """{"modified": [...], "added": [...], "deleted": [...]} for .sol paths.

    Only `modified` yields a comparable pair: an added file has no N-1 side and a
    deleted one has no N side, so neither can carry a regression.

    Two modes, deliberately not blended:

      `root`  - an EXPLICIT instruction. Honoured exactly: the diff is limited
                to that pathspec and nothing else is filtered out. An explicit
                root must keep meaning what it has always meant, or every pinned
                scan silently changes result (tests/test_realworld_reserve.py
                pins `contracts`, and reserve keeps mocks underneath it).

      `roots` + `exclude_segments` - AUTO mode, from `detect_source_scope`.
                Test, mock and vendor directories are dropped here and only
                here.
    """
    args = ["diff", "--name-status", prev, cur]
    pathspecs = [root] if root else [r for r in (roots or []) if r]
    if pathspecs:
        args += ["--", *pathspecs]
    out = _git(repo, *args)

    drop = frozenset(s.lower() for s in exclude_segments) if exclude_segments else None
    res = {"modified": [], "added": [], "deleted": []}
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status, path = parts[0], parts[-1]
        if not path.endswith(".sol"):
            continue
        if not root and drop and any(
                seg.lower() in drop for seg in path.split("/")[:-1]):
            continue
        if status.startswith("M"):
            res["modified"].append(path)
        elif status.startswith("A"):
            res["added"].append(path)
        elif status.startswith("D"):
            res["deleted"].append(path)
    return res


def file_at(repo, sha: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "show", f"{sha}:{path}"], cwd=str(repo), capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    return proc.stdout if proc.returncode == 0 else None


# ---------------------------------------------------------------------------
# scratch worktrees
# ---------------------------------------------------------------------------


def mirror_clone(source, dest) -> Path:
    """A bare clone of `source` inside OUR scratch, so the target is never written to.

    Finding WALK-L6: `git worktree add` creates administrative entries inside
    the repository it is run against. Run against the user's repository, that is
    a write to a target Chainwatch promised only to read — and it fails outright
    when the target is mounted read-only. Cloning first moves every worktree,
    every checkout and every piece of bookkeeping into a repository WE own; the
    user's repository is then only ever the source of a clone and a fetch, both
    of which read it and nothing else.

    `--local` is used when possible: for a source on the same filesystem git
    hardlinks the object store instead of copying it, which is fast and still
    only ever READS the source (git never rewrites an existing object file). If
    hardlinking is impossible — a different filesystem, a bind mount — git falls
    back to copying on its own.

    Refreshed on reuse so a repeat scan sees commits added since, and the
    refresh is a plain `fetch`, which is also read-only on the source.
    """
    source, dest = Path(source), Path(dest)
    if (dest / "HEAD").is_file() or (dest / ".git").exists():
        # REPAIR BEFORE USE (WALK-L9). A mirror left by an earlier version may
        # already carry a target-supplied `core.hooksPath`; reuse is the moment
        # to clear it, not merely to override it.
        harden_repo(dest)
        try:
            _git(dest, "fetch", "--quiet", "--prune", "origin",
                 "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*",
                 timeout=600)
        except Exception:  # noqa: BLE001 - a stale mirror still analyses fine
            pass
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, **git_safety_env()}
    proc = subprocess.run(["git", *git_safety_args(), "clone", "--bare", "--local",
                           "--quiet", str(source), str(dest)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800, env=env)
    if proc.returncode != 0:
        proc = subprocess.run(["git", *git_safety_args(), "clone", "--bare",
                               "--quiet", str(source), str(dest)],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800, env=env)
        if proc.returncode != 0:
            raise RuntimeError(
                f"could not clone {source} into scratch: {proc.stderr[:300]}")
    harden_repo(dest)
    # A bare clone's HEAD follows the source's default branch; make sure the
    # source's CURRENT HEAD commit is reachable, since a caller may be scanning
    # a detached or non-default checkout.
    try:
        head = _git(source, "rev-parse", "HEAD").strip()
        _git(dest, "cat-file", "-e", f"{head}^{{commit}}")
    except Exception:  # noqa: BLE001
        try:
            _git(dest, "fetch", "--quiet", str(source),
                 f"+{head}:refs/chainwatch/source-head", timeout=600)
        except Exception:  # noqa: BLE001
            pass
    return dest


class Worktree:
    """A scratch checkout of the target repo, reused across commits.

    Reusing one directory per slot (rather than one per commit) is what keeps a
    walk affordable: the installed dependency tree and any build cache survive
    each checkout, because both live on gitignored paths.
    """

    def __init__(self, repo, path):
        self.repo = Path(repo)
        self.path = Path(path)
        self.sha: str | None = None
        if not (self.path / ".git").exists():
            _git(self.repo, "worktree", "add", "--detach", str(self.path), "HEAD",
                 timeout=600)

    def checkout(self, sha: str) -> None:
        if self.sha == sha:
            return
        _git(self.path, "checkout", "--detach", "--force", sha, timeout=600)
        self.sha = sha

    def remove(self) -> None:
        _git(self.repo, "worktree", "remove", "--force", str(self.path), check=False,
             timeout=600)


# ---------------------------------------------------------------------------
# dependency-system detection
# ---------------------------------------------------------------------------


@dataclass
class EnvSpec:
    """What a build needs at one commit, read from the checked-out tree."""

    root: Path
    node_manager: str | None = None      # "yarn" | "npm" | "pnpm"
    # "berry" | "classic" when node_manager == "yarn", else None. Decided from
    # files at THIS commit, because a repo can migrate across its own history
    # and the two lines take incompatible script guards (WALK-L9).
    yarn_flavor: str | None = None
    lockfile: str | None = None
    has_submodules: bool = False
    has_foundry: bool = False
    has_remappings_txt: bool = False
    solc_pin: str | None = None
    packages: list = field(default_factory=list)

    @property
    def key(self) -> str:
        """Cache key: the resolved dependency set, NOT the commit.

        Consecutive commits almost always declare identical dependencies - across
        reserve-protocol's 30-commit window there is exactly ONE distinct
        yarn.lock - so keying on lockfile content collapses 30 installs into 1.
        """
        h = hashlib.sha256()
        for name in ("package.json", "yarn.lock", "package-lock.json",
                     "pnpm-lock.yaml", "foundry.toml", ".gitmodules",
                     "remappings.txt", ".yarnrc.yml"):
            f = self.root / name
            h.update(name.encode())
            h.update(f.read_bytes() if f.is_file() else b"")
        h.update((self.solc_pin or "").encode())
        # The flavour selects a DIFFERENT install command, so two checkouts with
        # byte-identical manifests but different flavours are different installs
        # and must not share a cache entry (WALK-L9).
        h.update((self.yarn_flavor or "").encode())
        return h.hexdigest()[:16]


_SOLC_IN_CONFIG = re.compile(r"version:\s*['\"](\d+\.\d+\.\d+)['\"]")
_SOLC_IN_TOML = re.compile(r"solc(?:_version)?\s*=\s*['\"]?v?(\d+\.\d+\.\d+)")


def detect_env(root) -> EnvSpec:
    root = Path(root)
    spec = EnvSpec(root=root)
    if (root / "package.json").is_file():
        if (root / "yarn.lock").is_file():
            spec.node_manager, spec.lockfile = "yarn", "yarn.lock"
            spec.yarn_flavor = yarn_flavor(root)
        elif (root / "pnpm-lock.yaml").is_file():
            spec.node_manager, spec.lockfile = "pnpm", "pnpm-lock.yaml"
        else:
            spec.node_manager = "npm"
            spec.lockfile = "package-lock.json" if (root / "package-lock.json").is_file() else None
    spec.has_submodules = (root / ".gitmodules").is_file()
    spec.has_foundry = (root / "foundry.toml").is_file()
    spec.has_remappings_txt = (root / "remappings.txt").is_file()

    for cfg in ("hardhat.config.ts", "hardhat.config.js"):
        f = root / cfg
        if f.is_file():
            m = _SOLC_IN_CONFIG.search(f.read_text(encoding="utf-8", errors="ignore"))
            if m:
                spec.solc_pin = m.group(1)
                break
    if not spec.solc_pin and spec.has_foundry:
        m = _SOLC_IN_TOML.search((root / "foundry.toml").read_text(encoding="utf-8", errors="ignore"))
        if m:
            spec.solc_pin = m.group(1)
    return spec


# ---------------------------------------------------------------------------
# install, cached, scripts disabled
# ---------------------------------------------------------------------------


def _link_dir(link: Path, target: Path) -> bool:
    """Point `link` at `target` without copying (junction on Windows).

    Returns whether `link` resolves to a real directory afterward - the only
    fact that matters to a caller deciding whether to trust it (11-L2:
    `subprocess.run`'s returncode was previously never checked, so a failed
    `mklink` - e.g. a stale directory ENTRY already occupying `link`, which
    `mklink` refuses to overwrite - looked identical to success).
    """
    if link.exists():
        return True
    if link.is_symlink():
        return False   # a link exists but does not resolve: caller must clear it first
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        link.symlink_to(target, target_is_directory=True)
    return link.exists()


INSTALL_CMDS = {
    "npm": [["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"]],
    "pnpm": [["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"]],
}

# Yarn is split out because its two major lines take DIFFERENT, MUTUALLY
# EXCLUSIVE guard flags, and the old code guessed by ordering (WALK-L9).
#
# The old comment claimed "`--mode=skip-build` is Berry syntax and yarn 1
# rejects it". It does not. Measured, yarn 1.22.22, clean two-file project:
#
#     $ YARN_ENABLE_SCRIPTS=0 yarn install --immutable --mode=skip-build
#     [4/4] Building fresh packages...
#     $ node -e "...writeFileSync('PREPARE_RAN','yes')"
#     Done in 0.17s.                          <- exit 0
#
# yarn 1 ignores unknown flags, EXITS 0 - so the guarded fallback beneath it
# never ran - and executes `prepare`. `YARN_ENABLE_SCRIPTS` is a Berry setting
# that yarn 1 does not read. The result was that every yarn-1 target with a
# `prepare` or `postinstall` script ran its code on the scanning machine.
YARN_CMDS = {
    # yarn 1: `--ignore-scripts` is a real flag it obeys.
    "classic": [["yarn", "install", "--frozen-lockfile", "--ignore-scripts"],
                ["yarn", "install", "--ignore-scripts"]],
    # Berry: `--ignore-scripts` is not a Berry option and passing it fails the
    # install outright; `--mode=skip-build` plus YARN_ENABLE_SCRIPTS=0 is the
    # guard Berry actually honours.
    "berry": [["yarn", "install", "--immutable", "--mode=skip-build"],
              ["yarn", "install", "--mode=skip-build"]],
}

# Berry markers, read from FILES ONLY. Deliberately not `yarn --version`: a
# Berry project ships its own yarn under `.yarn/releases/` and points
# `yarnPath` at it, so running the binary inside a target checkout is itself
# executing target code - the exact thing this function exists to prevent.
_BERRY_LOCK = re.compile(r"^\s*__metadata:", re.M)
_PM_YARN = re.compile(r'"packageManager"\s*:\s*"yarn@(\d+)')


def yarn_flavor(root) -> str:
    """"berry" | "classic" - which yarn line this checkout expects.

    Ambiguity resolves to "classic", and that direction is chosen on purpose.
    Guessing classic against a real Berry project passes `--ignore-scripts`,
    which Berry REJECTS: the install fails, the pair is skipped with a cause,
    and coverage drops. Guessing berry against a real yarn 1 project passes
    flags yarn 1 ignores while running scripts - it succeeds, silently, having
    executed target code. One error costs coverage; the other costs the
    charter. Fail toward the one that is merely expensive.
    """
    root = Path(root)
    if (root / ".yarnrc.yml").is_file():
        return "berry"
    if (root / ".yarn" / "releases").is_dir():
        return "berry"
    pkg = root / "package.json"
    if pkg.is_file():
        m = _PM_YARN.search(pkg.read_text(encoding="utf-8", errors="ignore"))
        if m and int(m.group(1)) >= 2:
            return "berry"
    lock = root / "yarn.lock"
    if lock.is_file():
        head = lock.read_text(encoding="utf-8", errors="ignore")[:4000]
        if _BERRY_LOCK.search(head):
            return "berry"
    return "classic"


def install_commands(manager: str, flavor: str | None = None) -> list[list[str]]:
    """The install command list for one package manager, in fallback order.

    Split out from the dict so the yarn choice is a FUNCTION OF THE DETECTED
    FLAVOUR rather than of which command happens to fail first, and so a test
    can assert the guard flag directly instead of inferring it from behaviour.
    """
    if manager == "yarn":
        return [list(c) for c in YARN_CMDS[flavor or "classic"]]
    return [list(c) for c in INSTALL_CMDS.get(manager, [])]

# CHARTER rule 5 (never execute a target repository's code) enforced through the
# ENVIRONMENT as well as the command line, because the command line is
# version-dependent and the environment is not (finding HIST-L3).
#
# Yarn Berry has no `--ignore-scripts` flag; it reads `enableScripts`, which
# defaults to TRUE and is true in every target checked, so `YARN_ENABLE_SCRIPTS=0`
# states the intent outright no matter what a repo's .yarnrc.yml says.
#
# WHAT THIS LAYER CANNOT DO, stated because believing otherwise is what caused
# WALK-L9: `YARN_ENABLE_SCRIPTS` is a BERRY setting. Yarn 1 does not read it,
# and there is no yarn-1 environment variable that disables lifecycle scripts.
# For yarn 1 the command-line `--ignore-scripts` is the ONLY guard that works,
# which is why `install_commands` selects on a statically detected flavour
# instead of leaving the outcome to fallback ordering. The env layer is real
# defence in depth for Berry, npm and pnpm; for yarn 1 it is decoration, and
# the earlier code mistook it for a floor.
INSTALL_ENV = {
    "yarn": {"YARN_ENABLE_SCRIPTS": "0", "npm_config_ignore_scripts": "true"},
    "npm": {"npm_config_ignore_scripts": "true"},
    "pnpm": {"npm_config_ignore_scripts": "true"},
}

_REGISTRY_GONE = ("404 Not Found", "ETARGET", "no matching version",
                  "Couldn't find package", "not found in the registry")


def install(spec: EnvSpec, cache_root, timeout: int = 900) -> tuple[bool, str, str]:
    """Materialise `spec`'s dependencies into its worktree. (ok, cause, detail).

    Cached on EnvSpec.key: the first commit of a dependency set pays the install,
    every later commit with the same set gets a directory link and pays nothing.
    """
    cache_root = Path(cache_root)
    cache_root.mkdir(parents=True, exist_ok=True)
    detail = ""

    if spec.has_submodules:
        try:
            _git(spec.root, "submodule", "update", "--init", "--recursive",
                 timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return False, CAUSE_DEP_MISSING, f"submodule update failed: {exc}"[:300]

    if spec.node_manager is None:
        return True, "", "no node dependency system declared"

    cached = cache_root / spec.key / "node_modules"
    marker = cache_root / spec.key / MARKER
    link = spec.root / "node_modules"
    # A CACHE HIT REQUIRES THE COMPLETION MARKER, not merely a directory.
    # Finding HIST-L4: `cached.is_dir()` alone accepts a partially-installed
    # tree - one npm run that exited 0 without fetching a git dependency, or an
    # install interrupted between `shutil.move` and completion - and then
    # returns "cache hit" forever, because nothing ever re-checks it. That is
    # cache POISONING: one transient failure is baked in permanently, and every
    # later run reports success while compiling against a tree that is missing
    # packages. Measured cost: reserve-protocol's entry held 900 packages and
    # was missing 3, one of which every ActFacet compile needs.
    if cached.is_dir():
        # 11-L2: a STALE directory entry can already occupy `link` - most
        # commonly a DANGLING junction left by an earlier run whose cache
        # target has since been cleared. `mklink` refuses to create a
        # junction where a directory entry already exists (even a broken
        # one), and that failure was never checked, so `_link_dir` silently
        # did nothing and this branch went on to report "cache hit" with
        # `node_modules` resolving to nothing. Clear any stale entry FIRST -
        # `_unlink_node_modules` never touches a genuine directory, so this
        # cannot destroy a real, working install - then verify the link
        # actually resolves before trusting it, the same "verify before
        # trusting" principle HIST-L4 already applies to the cache itself.
        _unlink_node_modules(link)
        if not _link_dir(link, cached):
            return (False, CAUSE_DEP_MISSING,
                    f"cache entry {spec.key} exists but linking {link} to it "
                    f"failed (mklink error not further diagnosable from here)")
        if marker.is_file():
            return True, "", f"cache hit {spec.key}"
        # Unverified entry: from before this check existed, or an install that
        # died between the move and the marker. Verify it IN PLACE rather than
        # deleting it - a dependency tree can cost minutes to rebuild and may
        # not be rebuildable at all offline, so destroying one to re-derive a
        # boolean is the wrong trade.
        missing = _missing_imported_packages(spec.root)
        if not missing:
            _write_marker(cache_root / spec.key, spec)
            return True, "", f"cache hit {spec.key} (verified retroactively)"
        _unlink_node_modules(link)
        return (False, CAUSE_DEP_MISSING,
                f"cached dependency tree is incomplete, missing: "
                f"{', '.join(sorted(missing))}. Delete "
                f"{(cache_root / spec.key).as_posix()} to force a reinstall."[:300])

    # A LINK LEFT BY AN EARLIER RUN MUST GO BEFORE ANY INSTALLER RUNS.
    # Finding HIST-L5: `_link_dir` points <worktree>/node_modules at the cache,
    # and that junction survives into the next install attempt, where the
    # installer tries to create the directory it is standing on:
    #     ENOTDIR: not a directory, mkdir '...\prev\node_modules'
    # Yarn Berry fails the whole link step on it. The install then "fails" for
    # a reason that has nothing to do with the repository, and - before the
    # marker existed - could leave a half-populated tree behind that was cached
    # and trusted forever (HIST-L4). Removing the link first makes the install
    # start from the state a human would have.
    _unlink_node_modules(link)

    env = {**os.environ, **INSTALL_ENV.get(spec.node_manager, {})}
    for cmd in install_commands(spec.node_manager, spec.yarn_flavor):
        try:
            proc = subprocess.run(cmd, cwd=str(spec.root), capture_output=True,
                                  text=True, encoding="utf-8", errors="replace",
                                  timeout=timeout, env=env,
                                  shell=(os.name == "nt"))
        except subprocess.TimeoutExpired:
            return False, CAUSE_TIMEOUT, f"{' '.join(cmd)} exceeded {timeout}s"
        detail = (proc.stdout + proc.stderr)[-600:]
        # DEP-2. Node 17+ ships OpenSSL 3, which withdrew the legacy hash
        # provider that older JS toolchains (yarn classic, old webpack) still
        # reach for. The installer dies with ERR_OSSL_EVP_UNSUPPORTED - a
        # property of the HOST's Node, not of the repository, and the reason
        # historically-important targets like compound-v2 and aave-v2 skipped
        # every pair as `dep-missing`. Retried ONCE with the legacy provider
        # re-enabled, which is the documented remedy for exactly this error.
        #
        # Scoped to the measured signature rather than applied always: the flag
        # weakens a crypto policy, so it is opt-in per failure, never a default.
        # It also cannot affect analysis - it only lets the dependency tree
        # materialise; every rule still reads the same sources afterwards.
        if proc.returncode != 0 and _needs_legacy_openssl(detail):
            legacy = {**env, "NODE_OPTIONS": (
                env.get("NODE_OPTIONS", "") + " --openssl-legacy-provider").strip()}
            try:
                proc = subprocess.run(cmd, cwd=str(spec.root), capture_output=True,
                                      text=True, encoding="utf-8", errors="replace",
                                      timeout=timeout, env=legacy,
                                      shell=(os.name == "nt"))
                detail = (proc.stdout + proc.stderr)[-600:]
            except subprocess.TimeoutExpired:
                return (False, CAUSE_TIMEOUT,
                        f"{' '.join(cmd)} exceeded {timeout}s "
                        f"(retry with --openssl-legacy-provider)")
        # WALK-L9, third layer. `spec.root` is a linked worktree, so a `git
        # config` run inside it writes to the SHARED config of the scratch
        # mirror - which is exactly how `husky install` armed the target's
        # hooks for every later checkout. The command-line override in
        # `git_safety_args` already makes that inert, but leaving a poisoned
        # value in a file we own is not something to discover twice.
        harden_repo(spec.root)
        if proc.returncode == 0:
            break
        if any(m in detail for m in _REGISTRY_GONE):
            return False, CAUSE_DEP_GONE, detail[-300:]
    else:
        return False, CAUSE_DEP_MISSING, detail[-300:]

    # VERIFY BEFORE CACHING (finding HIST-L4). An installer can exit 0 having
    # skipped a package - a git dependency it could not fetch, most commonly -
    # and caching that tree makes the failure permanent. Check the packages the
    # repo's Solidity actually IMPORTS, not every declared dependency: those are
    # the ones compilation needs, and requiring the rest would turn a working
    # tree into a skip over an unrelated devDependency.
    missing = _missing_imported_packages(spec.root)
    if missing:
        return (False, CAUSE_DEP_MISSING,
                f"install completed but these imported packages are absent: "
                f"{', '.join(sorted(missing))}"[:300])

    if link.is_dir() and not link.is_symlink():
        (cache_root / spec.key).mkdir(parents=True, exist_ok=True)
        shutil.move(str(link), str(cached))
        if not _link_dir(link, cached):
            return (False, CAUSE_DEP_MISSING,
                    f"install succeeded but linking {link} back to the cache "
                    f"({spec.key}) failed after moving it there")
    # The marker is written LAST, so an install interrupted anywhere before this
    # point leaves an unmarked entry that the next run verifies instead of
    # trusting.
    _write_marker(cache_root / spec.key, spec)
    return True, "", f"installed {spec.key}"


def _unlink_node_modules(link: Path) -> None:
    """Remove a node_modules LINK, never a real directory.

    Deliberately refuses to touch a genuine directory: this runs before an
    install, and deleting a real dependency tree because it might be stale is
    exactly the destructive shortcut HIST-L4's fix exists to avoid. A junction
    is removed with `Path.unlink`-equivalent semantics on Windows (`rmdir` on
    the reparse point), which does not follow into the target.

    11-L2: the early guard used to read `link.exists()`, which FOLLOWS the
    link - so a DANGLING junction (its target deleted out from under it, e.g.
    an earlier run's cache entry that was later cleared) reports `exists()`
    False and `is_symlink()` False on Windows (a junction is not a Python
    symlink), and this function did nothing. The stale directory ENTRY stayed
    on disk, `mklink` later refused to overwrite it (`Cannot create a file
    when that file already exists`, returncode 1, previously never checked -
    see `_link_dir`), and node_modules silently resolved to nothing. Measured
    directly: a deliberately-dangled junction reproduces exactly this.
    `os.path.lexists` does NOT follow the link, so it sees the entry either
    way - a real directory, a working link, or a dangling one - which is what
    this guard needs to decide whether there is anything to remove at all.
    """
    try:
        if not os.path.lexists(link) and not link.is_symlink():
            return
        if link.is_symlink():
            link.unlink()
            return
        if os.name == "nt":
            # A junction reports is_dir() True; distinguish by reparse attribute.
            import stat as _stat

            st = os.lstat(link)
            if st.st_file_attributes & _stat.FILE_ATTRIBUTE_REPARSE_POINT:
                os.rmdir(link)  # removes the junction only
    except OSError:
        pass


def _write_marker(entry: Path, spec: "EnvSpec") -> None:
    try:
        entry.mkdir(parents=True, exist_ok=True)
        (entry / MARKER).write_text(
            json.dumps({"key": spec.key, "manager": spec.node_manager,
                        "verified_imports": sorted(imported_packages(spec.root))}),
            encoding="utf-8")
    except OSError:
        pass  # an unmarked entry is merely re-verified next time; never wrong


def _remappings_txt_lines(root) -> list[str]:
    """Explicit remapping lines from remappings.txt, comments/blanks dropped."""
    rf = Path(root) / "remappings.txt"
    if not rf.is_file():
        return []
    out = []
    for line in rf.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            out.append(s)
    return out


def _remap_resolves(root, pkg: str, remap_lines) -> bool:
    """Does some remapping route this import prefix to a directory that EXISTS?

    A Foundry project maps `@1inch/solidity-utils/` -> `lib/solidity-utils/` in
    remappings.txt (or via forge's lib auto-remapping). The literal
    `lib/@1inch/solidity-utils` check is blind to that and reported a present
    dependency as missing, skipping the whole pair the compiler could have built
    (measured on 1inch/cross-chain-swap). This follows the remapping the way solc
    does: longest matching LHS, target directory must exist.
    """
    root = Path(root)
    key = pkg.rstrip("/") + "/"
    for line in remap_lines:
        lhs, _, rhs = line.partition("=")
        lhs, rhs = lhs.strip(), rhs.strip()
        if not lhs or not rhs or not key.startswith(lhs):
            continue
        remainder = key[len(lhs):]
        base = Path(rhs) if os.path.isabs(rhs) else (root / rhs)
        cand = (base / remainder) if remainder else base
        if Path(str(cand).rstrip("/")).is_dir():
            return True
    return False


def _missing_imported_packages(root) -> set:
    """Imported package prefixes that are not present on disk after an install.

    Scoped to the repo's OWN Solidity (lib/ submodule internals excluded): the
    pre-flight gate decides whether the analysed sources can build, and a
    transitive import buried inside a dependency is the compiler's business, not
    a reason to skip every file in the pair. Remapping-aware, because a present
    dependency reached through a remap is present (finding COMP-L2).
    """
    root = Path(root)
    remap_lines = _remappings_txt_lines(root) + _foundry_lib_remaps(root)
    missing = set()
    for pkg in imported_packages(root, exclude_deps=True):
        if (root / pkg).is_dir():
            continue  # repo-root-relative import, not a package
        if any((root / base / Path(pkg)).is_dir() for base in ("node_modules", "lib")):
            continue
        if _remap_resolves(root, pkg, remap_lines):
            continue
        missing.add(pkg)
    return missing


# ---------------------------------------------------------------------------
# remappings + compiler, derived from the reconstructed tree
# ---------------------------------------------------------------------------

_IMPORT = re.compile(r'import\s+(?:[^"\';]*?from\s*)?["\']([^"\']+)["\']')


def imported_packages(root, contracts_dir: str = "", exclude_deps: bool = False) -> set:
    """Non-relative import prefixes appearing in the repo's own Solidity.

    Remapping every directory under node_modules is not viable - reserve's tree
    yields 971 entries and overflows the Windows command line (WinError 206).
    Only packages the Solidity actually imports are needed: 8, in that repo.

    `exclude_deps` also drops `lib/` (Foundry submodule) trees, so the caller
    sees only what the REPO'S OWN sources import - used by the pre-flight skip
    gate, which must not require a dependency's own transitive imports.
    """
    root = Path(root)
    search = root / contracts_dir if contracts_dir else root
    pkgs = set()
    for f in search.rglob("*.sol"):
        if "node_modules" in f.parts:
            continue
        if exclude_deps and "lib" in f.parts:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in _IMPORT.finditer(text):
            p = m.group(1)
            if p.startswith("."):
                continue
            parts = p.split("/")
            pkgs.add("/".join(parts[:2]) if p.startswith("@") else parts[0])
    return pkgs


def derive_remaps(root, contracts_dir: str = "", absolute: bool = False) -> list[str]:
    """Remappings for the packages this tree's Solidity imports.

    `absolute=True` emits fully-qualified targets, which a walker NEEDS: the two
    sides of a pair live in two different worktrees, so a relative remapping
    would resolve against whichever cwd happens to be current and silently point
    one side at the other side's dependencies.

    The trailing slash on both sides is load-bearing. solc does a literal prefix
    substitution, so dropping it turns `@openzeppelin/contracts/` +
    `token/ERC20/IERC20.sol` into `...contractstoken/ERC20/IERC20.sol` and every
    import fails as "File not found" - which looks exactly like a missing
    dependency and misclassifies a working environment as unreconstructable.
    """
    root = Path(root)
    out = []
    for pkg in sorted(imported_packages(root, contracts_dir)):
        for base in ("node_modules", "lib"):
            pkg_dir = root / base / Path(pkg)
            if pkg_dir.is_dir():
                # RESOLVE THE LINK (finding WALK-L4). `install()` materialises a
                # cached dependency set as an NTFS junction at
                # <worktree>/node_modules, and solc's import read callback
                # cannot traverse it on older compilers: solc 0.5.17 reports
                # `Source "..." not found: Unknown exception in read callback`
                # for a file that demonstrably exists, which reads like a
                # missing dependency and silently costs the whole file. Handing
                # solc the junction's TARGET compiles the identical sources.
                # Only meaningful for `absolute` (a relative remap is resolved
                # by solc against its own cwd, junction and all).
                real = pkg_dir.resolve() if absolute else pkg_dir
                target = f"{real.as_posix()}/" if absolute else f"{base}/{pkg}/"
                out.append(f"{pkg}/={target}")
                break
        else:
            # Repo-root-relative import (`import "contracts/interfaces/IAsset.sol"`).
            # Hardhat resolves these implicitly from the project root; bare solc
            # does not, so the import fails as "File not found" and the whole
            # file comparison is lost. A self-mapping to the in-repo directory
            # is what makes bare solc agree with Hardhat. Only emitted when the
            # directory actually exists in this checkout, so it cannot mask a
            # genuinely missing dependency.
            src_dir = root / Path(pkg)
            if src_dir.is_dir():
                target = f"{src_dir.as_posix()}/" if absolute else f"{pkg}/"
                out.append(f"{pkg}/={target}")
    # Foundry lib/ auto-remapping, BEFORE remappings.txt so an explicit entry
    # still wins. A submodule-based (Foundry) dependency graph resolves the way
    # `forge remappings` would; a wrong target can only make solc report "file
    # not found" (honest under-coverage), never a mis-compiled AST.
    out.extend(_foundry_lib_remaps(root, absolute))
    if (root / "remappings.txt").is_file():
        for line in (root / "remappings.txt").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                out.append(_absolutize_remap(line.strip(), root) if absolute
                           else line.strip())
    return out


def _absolutize_remap(entry: str, root) -> str:
    """Re-root ONE `prefix=target` remapping onto `root` (finding DEP-1).

    A `remappings.txt` is appended last on purpose, so an explicit entry beats a
    derived one - solc takes the LAST matching remapping for a prefix. But these
    files almost always hold checkout-relative targets
    (`@1inch/solidity-utils/=node_modules/@1inch/solidity-utils/`), and appending
    those verbatim silently DEFEATED the whole point of `absolute=True`: the
    relative duplicate overrode the absolute one this function had just derived,
    and solc then resolved `node_modules/...` against its own cwd. Slither is
    invoked without a cwd, so that cwd is Chainwatch's own root - where no such
    directory exists - and every import failed as "not found" on a dependency
    tree that was correctly installed the whole time.

    MEASURED on 1inch/swap-vm: 0 of 1160 rule invocations survived, and the
    error reproduces byte-for-byte by running the derived remap list from
    Chainwatch's root instead of the worktree. 1inch/aqua lost 27 of 38 files
    the same way.

    Both intents are preserved rather than traded off: the explicit entry still
    wins (its prefix mapping is kept exactly), and it becomes cwd-independent
    (its target is resolved against the checkout it came from). The junction is
    resolved for the same reason the derived branch resolves it (WALK-L4).
    An already-absolute target is returned untouched.
    """
    prefix, _, target = entry.partition("=")
    if not target or Path(target).is_absolute():
        return entry
    trailing = "/" if target.endswith(("/", "\\")) else ""
    try:
        real = (Path(root) / target).resolve()
    except OSError:  # unresolvable path: keep the original rather than guess
        return entry
    return f"{prefix}={real.as_posix()}{trailing}"


_MAX_LIB_DEPTH = 4


def _foundry_lib_remaps(root, absolute: bool = False) -> list[str]:
    """Foundry-style auto-remappings for each `lib/<sub>` submodule, INCLUDING
    nested ones, using solc's context-dependent remapping syntax.

    For every submodule, map BOTH its package.json `name` and its bare directory
    name to the submodule's source directory (`src/`, then `contracts/`, else the
    submodule root) - which is what `forge remappings` generates and how a
    Foundry project's imports (`@openzeppelin/contracts/...`, `forge-std/...`)
    resolve without an explicit remappings.txt entry. Additive: emits nothing
    when `lib/` is absent, so npm/Hardhat repos are unaffected.

    NESTED SUBMODULES (finding COMP-L2, reopened and fixed 2026-08-27). This
    used to walk only the TOP-level `lib/`, and COMP-L2 was recorded as an
    unfixable charter boundary on the reasoning that "bare solc holds one flat
    remapping set" and only `forge` (which CHARTER rule 3 forbids installing)
    could resolve per-subtree contexts. **That reasoning was wrong.** solc has
    long accepted `context:prefix=target`, which restricts a remapping to
    imports made from files under `context` - exactly the mechanism forge itself
    emits. Measured directly, on a nested tree where root and submodule pin
    DIFFERENT versions of the same dependency:

        flat     lib/A/src/A.sol  "dep/src/D.sol" -> lib/dep/src/D.sol
        context  lib/A/src/A.sol  "dep/src/D.sol" -> lib/A/lib/dep/src/D.sol

    Note what the flat row actually shows: not a failure to compile, but a
    SILENT resolution to the wrong dependency. COMP-L2 was filed as a coverage
    ceiling; it was also, undetected, a correctness hazard - a rule could read
    the wrong version of a dependency and compare against it.

    A nested remapping is emitted only when its target directory actually holds
    Solidity: an uninitialised git submodule leaves an EMPTY `lib/<sub>/lib/<x>`
    behind, and remapping onto it would break imports that currently resolve
    (accidentally but usefully) through the root-level copy.
    """
    root = Path(root)
    out: list[str] = []

    def has_sol(d: Path) -> bool:
        try:
            return any(d.rglob("*.sol"))
        except OSError:
            return False

    def walk(base: Path, depth: int) -> None:
        libdir = base / "lib"
        if depth > _MAX_LIB_DEPTH or not libdir.is_dir():
            return
        # Root-level remappings stay unscoped, byte-identical to before. Only a
        # NESTED submodule gets a context, so every existing repository's flat
        # remapping set is unchanged unless it actually has nested libs.
        if base == root:
            context = ""
        else:
            ctx = (base.resolve().as_posix() if absolute
                   else base.relative_to(root).as_posix())
            # solc's remapping grammar is `context:prefix=target`, so a context
            # containing a colon is unparseable - which is exactly what a
            # Windows absolute path is (`C:/...`). MEASURED: solc then takes
            # `C` as the context, and since context matching is a plain string
            # prefix, `C` matches every source unit on that drive. The observed
            # result was a silently WRONG resolution, not an error.
            #
            # Emitting nothing here is a no-op: resolution falls back to the
            # unscoped root-level remapping, i.e. exactly the pre-fix behaviour.
            # Full Windows support needs `--base-path <root>` with relative
            # remappings (verified working: it makes source unit names
            # root-relative so a relative context matches), which is a change to
            # how Slither is invoked, not to what this function emits - tracked
            # in LIMITATIONS.md under COMP-L2.
            if ":" in ctx:
                for sub in sorted(p for p in libdir.iterdir() if p.is_dir()):
                    walk(sub, depth + 1)
                return
            context = f"{ctx}/:"
        for sub in sorted(p for p in libdir.iterdir() if p.is_dir()):
            srcdir = sub
            for cand in ("src", "contracts"):
                if (sub / cand).is_dir():
                    srcdir = sub / cand
                    break
            if context and not has_sol(srcdir):
                walk(sub, depth + 1)   # still descend; just do not remap onto nothing
                continue
            target = (f"{srcdir.resolve().as_posix()}/" if absolute
                      else f"{srcdir.relative_to(root).as_posix()}/")
            names = {sub.name}
            pj = sub / "package.json"
            if pj.is_file():
                try:
                    nm = json.loads(
                        pj.read_text(encoding="utf-8", errors="ignore")).get("name")
                    if nm:
                        names.add(nm)
                except (ValueError, OSError):
                    pass
            for nm in sorted(names):
                out.append(f"{context}{nm}/={target}")
            walk(sub, depth + 1)

    walk(root, 0)
    return out


def pragma_of(text: str) -> str | None:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("pragma") and "solidity" in s:
            body = s[len("pragma"):].strip()
            if body.startswith("solidity"):
                body = body[len("solidity"):].strip()
            return body.split(";", 1)[0].strip()
    return None


def solc_available(version: str | None) -> bool:
    if not version:
        return True
    try:
        from solc_select.solc_select import installed_versions

        return version in installed_versions()
    except Exception:  # noqa: BLE001
        return False


# Versions this PROCESS has already tried to install and failed on. Without it,
# a walk over history that pins one absent version N times would re-attempt the
# same doomed download N times - 26 times for 0.8.17 on the Reserve stress set.
# Successes need no memo: solc_available() sees them immediately afterwards.
_INSTALL_FAILED: dict[str, str] = {}


def ensure_solc(version: str | None) -> tuple[bool, str]:
    """Make `version` available, installing it if necessary.

    Returns (available, reason) where reason is one of `no-pin`, `cache-hit`,
    `installed`, `install-failed: ...`, `install-failed-earlier: ...` — the
    caller logs it, so a coverage report can always explain WHY a comparison
    was or was not attempted (finding HIST-L2).

    THE GUARD IS NOT AN OPTIMISATION. `solc_available()` is checked first
    because `install_artifacts` calls `get_available_versions()`
    unconditionally at the top of its body, BEFORE its own
    already-installed check — so calling it on a cache hit still costs a
    network round-trip for the release list. On a 25-pair walk that is dozens
    of pointless fetches, and it would make an offline run fail on versions
    that are already present on disk.

    SAFETY (CHARTER rule 5). This runs no code from the analysed repository.
    solc-select fetches a compiler binary from `binaries.soliditylang.org`
    (the official Solidity distribution) and verifies it against the published
    sha256 AND keccak256 checksums, raising on mismatch. There is no lifecycle
    script and no target-supplied payload, so the HIST-L3 problem - `npm`/`yarn`
    executing a TARGET's postinstall - has no analogue here. The target repo
    influences only WHICH version string is requested, and `install_artifacts`
    refuses any version absent from the official release list.
    """
    if not version:
        return True, "no-pin"
    if solc_available(version):
        return True, "cache-hit"
    if version in _INSTALL_FAILED:
        return False, f"install-failed-earlier: {_INSTALL_FAILED[version]}"
    try:
        from solc_select.solc_select import install_artifacts

        ok = install_artifacts([version], silent=True)
        if not ok:
            # install_artifacts returns False (rather than raising) when the
            # version is not in the official release list.
            _INSTALL_FAILED[version] = "not an available solc release"
            return False, f"install-failed: {_INSTALL_FAILED[version]}"
    except Exception as exc:  # noqa: BLE001 - network, disk, checksum mismatch
        _INSTALL_FAILED[version] = f"{type(exc).__name__}: {exc}"[:160]
        return False, f"install-failed: {_INSTALL_FAILED[version]}"

    # Trust the filesystem, not the return value: confirm it is really there.
    if solc_available(version):
        return True, "installed"
    _INSTALL_FAILED[version] = "install reported success but version still absent"
    return False, f"install-failed: {_INSTALL_FAILED[version]}"


# A leading bare `=` is part of the exact-pin spelling, not an operator:
# `pragma solidity =0.7.6;` pins as tightly as `pragma solidity 0.7.6;`.
# Uniswap v3-core/periphery use that form throughout, and without the `=?`
# neither auto-install (B3) nor the compile fast path would engage for them.
# `>=` and `<=` do NOT match, because the digits cannot follow their first
# character — those stay ranges and keep the retry fallback.
_EXACT_PIN = re.compile(r"^\s*=?\s*(\d+\.\d+\.\d+)\s*$")


def exact_pin(pragma_expr: str | None) -> str | None:
    """The version an EXACT pin names, whether or not it is installed.

    Split out from `unsatisfiable_exact_pin` so a caller can distinguish "this
    file has no exact pin" from "it has one and that one is already present" —
    the two cases that function deliberately collapses into None. The auto-
    provision path needs them apart, because it must be able to LOG a cache hit
    rather than silently take the same branch as a caret range.
    """
    m = _EXACT_PIN.match(pragma_expr or "")
    return m.group(1) if m else None


def unsatisfiable_exact_pin(pragma_expr: str | None) -> str | None:
    """The version this file REQUIRES and that is not installed, or None.

    SUPERSEDED AND CURRENTLY UNCALLED. The HIST-L2 pre-flight in `src/scan.py`
    now uses `exact_pin()` + `ensure_solc()` instead, because an absent pinned
    compiler is no longer a reason to skip — it is a reason to fetch. This is
    kept because the reasoning below is what the auto-provision path inherited
    (only an EXACT pin is decidable without implementing semver), and because
    LIMITATIONS.md §HIST-L2 refers to it by name. Delete it only together with
    that provenance, not as a stray tidy-up.

    Pre-flight for finding HIST-L2. Deliberately narrow: it only judges an
    EXACT pin (`pragma solidity 0.8.19;`), because that is the one case where
    satisfiability is decidable without implementing semver — no other compiler
    can satisfy it, so if that exact version is absent the compile is doomed
    before it starts. Anything with a caret, a range, or an operator returns
    None and takes the normal path, where `_shared.solc_candidates` tries the
    installed versions and solc itself arbitrates.

    Measured worth (25-pair Reserve stress run): 57 of 76 file comparisons were
    exact pins on two absent versions, and each one paid nine failed rule
    invocations before reporting an error that named the wrong compiler.
    """
    version = exact_pin(pragma_expr)
    if version is None:
        return None
    return None if solc_available(version) else version


# ---------------------------------------------------------------------------
# classification of a compile failure
# ---------------------------------------------------------------------------


def classify(error: str, spec: EnvSpec) -> str:
    e = error or ""
    if "not found: File not found" in e or "Source \"" in e and "not found" in e:
        return CAUSE_REMAPPING if (spec.root / "node_modules").exists() else CAUSE_DEP_MISSING
    if "requires different compiler version" in e or "Invalid solc version" in e:
        return CAUSE_SOLC_ABSENT
    if "TimeoutExpired" in e or "timed out" in e:
        return CAUSE_TIMEOUT
    if "Error" in e or "ParserError" in e or "TypeError" in e:
        return CAUSE_COMPILE
    return CAUSE_UNKNOWN
