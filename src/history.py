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

HIST-L1 reporting invariant: `walk()` returns per-pair outcomes with an explicit
cause for every non-analyzed pair. A caller that reports detections without also
reporting the analyzable/skipped ratio is reporting a broken result - "0
detections" is meaningless without coverage.

SECURITY: dependency installs run with lifecycle scripts DISABLED (npm
--ignore-scripts, yarn --mode=skip-build, pnpm --ignore-scripts). Installing a
historical dependency set means fetching arbitrary third-party code; executing
its postinstall hooks is a remote-code-execution surface and is not something a
static analyser needs. Native modules will not build as a result. If a project
genuinely requires scripts to produce a compilable tree, `install()` records
NEEDS_SCRIPTS rather than silently enabling them - that is a human decision, per
project.
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
CAUSE_TIMEOUT = "timeout"                    # install/build exceeded its cap
CAUSE_COMPILE = "compile-error"              # source itself does not compile
CAUSE_UNKNOWN = "unknown"

# Written into a cache entry only after its install has been VERIFIED complete.
# Its absence is what makes an unfinished or poisoned entry a cache miss rather
# than a permanent silent wrong answer (finding HIST-L4).
MARKER = ".chainwatch-install-ok"

# ---------------------------------------------------------------------------
# git: read-only history access
# ---------------------------------------------------------------------------


def _git(repo, *args, check=True, timeout=300):
    proc = subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, timeout=timeout
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{proc.stderr.strip()[:400]}")
    return proc.stdout


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


def changed_sol(repo, prev: str, cur: str, root: str = "") -> dict:
    """{"modified": [...], "added": [...], "deleted": [...]} for .sol paths.

    Only `modified` yields a comparable pair: an added file has no N-1 side and a
    deleted one has no N side, so neither can carry a regression.
    """
    args = ["diff", "--name-status", prev, cur]
    if root:
        args += ["--", root]
    out = _git(repo, *args)
    res = {"modified": [], "added": [], "deleted": []}
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status, path = parts[0], parts[-1]
        if not path.endswith(".sol"):
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
        ["git", "show", f"{sha}:{path}"], cwd=str(repo), capture_output=True, text=True
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
        try:
            _git(dest, "fetch", "--quiet", "--prune", "origin",
                 "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*",
                 timeout=600)
        except Exception:  # noqa: BLE001 - a stale mirror still analyses fine
            pass
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(["git", "clone", "--bare", "--local", "--quiet",
                           str(source), str(dest)],
                          capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        proc = subprocess.run(["git", "clone", "--bare", "--quiet",
                               str(source), str(dest)],
                              capture_output=True, text=True, timeout=1800)
        if proc.returncode != 0:
            raise RuntimeError(
                f"could not clone {source} into scratch: {proc.stderr[:300]}")
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
                     "remappings.txt"):
            f = self.root / name
            h.update(name.encode())
            h.update(f.read_bytes() if f.is_file() else b"")
        h.update((self.solc_pin or "").encode())
        return h.hexdigest()[:16]


_SOLC_IN_CONFIG = re.compile(r"version:\s*['\"](\d+\.\d+\.\d+)['\"]")
_SOLC_IN_TOML = re.compile(r"solc(?:_version)?\s*=\s*['\"]?v?(\d+\.\d+\.\d+)")


def detect_env(root) -> EnvSpec:
    root = Path(root)
    spec = EnvSpec(root=root)
    if (root / "package.json").is_file():
        if (root / "yarn.lock").is_file():
            spec.node_manager, spec.lockfile = "yarn", "yarn.lock"
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


def _link_dir(link: Path, target: Path) -> None:
    """Point `link` at `target` without copying (junction on Windows)."""
    if link.exists() or link.is_symlink():
        return
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    else:
        link.symlink_to(target, target_is_directory=True)


INSTALL_CMDS = {
    # Lifecycle scripts disabled in every one of these - see module docstring.
    # The yarn list is ordered Berry-first, then yarn 1: `--mode=skip-build` is
    # Berry syntax and yarn 1 rejects it, `--ignore-scripts` is yarn 1 syntax
    # and Berry rejects it, so whichever runs, the other is a no-op failure.
    "yarn": [["yarn", "install", "--immutable", "--mode=skip-build"],
             ["yarn", "install", "--frozen-lockfile", "--ignore-scripts"]],
    "npm": [["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"]],
    "pnpm": [["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"]],
}

# CHARTER rule 5 (never execute a target repository's code) enforced through the
# ENVIRONMENT as well as the command line, because the command line is
# version-dependent and the environment is not (finding HIST-L3).
#
# Yarn Berry has no `--ignore-scripts` flag; it reads `enableScripts`, which
# defaults to TRUE and is true in every target checked. Today the guarantee
# rests entirely on `--mode=skip-build` being the command that happens to run
# first - i.e. on a fallback ordering, which is exactly the kind of accidental
# safety this project has been burned by. `YARN_ENABLE_SCRIPTS=0` states it
# outright and holds no matter which command wins or what a repo's .yarnrc.yml
# says. npm's `--ignore-scripts` gets the same treatment via npm_config_*.
INSTALL_ENV = {
    "yarn": {"YARN_ENABLE_SCRIPTS": "0"},
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
        _link_dir(link, cached)
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
    for cmd in INSTALL_CMDS[spec.node_manager]:
        try:
            proc = subprocess.run(cmd, cwd=str(spec.root), capture_output=True,
                                  text=True, timeout=timeout, env=env,
                                  shell=(os.name == "nt"))
        except subprocess.TimeoutExpired:
            return False, CAUSE_TIMEOUT, f"{' '.join(cmd)} exceeded {timeout}s"
        detail = (proc.stdout + proc.stderr)[-600:]
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
        _link_dir(link, cached)
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
    """
    try:
        if not link.exists() and not link.is_symlink():
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


def _missing_imported_packages(root) -> set:
    """Imported package prefixes that are not present on disk after an install."""
    root = Path(root)
    missing = set()
    for pkg in imported_packages(root):
        if (root / pkg).is_dir():
            continue  # repo-root-relative import, not a package
        if not any((root / base / Path(pkg)).is_dir() for base in ("node_modules", "lib")):
            missing.add(pkg)
    return missing


# ---------------------------------------------------------------------------
# remappings + compiler, derived from the reconstructed tree
# ---------------------------------------------------------------------------

_IMPORT = re.compile(r'import\s+(?:[^"\';]*?from\s*)?["\']([^"\']+)["\']')


def imported_packages(root, contracts_dir: str = "") -> set:
    """Non-relative import prefixes appearing in the repo's own Solidity.

    Remapping every directory under node_modules is not viable - reserve's tree
    yields 971 entries and overflows the Windows command line (WinError 206).
    Only packages the Solidity actually imports are needed: 8, in that repo.
    """
    root = Path(root)
    search = root / contracts_dir if contracts_dir else root
    pkgs = set()
    for f in search.rglob("*.sol"):
        if "node_modules" in f.parts:
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
    if (root / "remappings.txt").is_file():
        for line in (root / "remappings.txt").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                out.append(line.strip())
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


_EXACT_PIN = re.compile(r"^\s*(\d+\.\d+\.\d+)\s*$")


def unsatisfiable_exact_pin(pragma_expr: str | None) -> str | None:
    """The version this file REQUIRES and that is not installed, or None.

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
    m = _EXACT_PIN.match(pragma_expr or "")
    if not m:
        return None
    version = m.group(1)
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
