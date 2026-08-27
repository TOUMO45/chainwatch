"""Soldeer dependency resolution (DEP-3), read-only, no forge/soldeer executed.

Foundry's newer package manager. A project using it declares dependencies in
`foundry.toml`'s `[dependencies]` table, in two shapes:

    forge-std = "1.9.6"                                    # registry-hosted
    pendle-core-v2 = { version = "1.0.0",                  # git-pinned
                       git = "https://github.com/...",
                       rev = "d3dafee2..." }

Chainwatch's own `history.detect_env`/`install()` never recognised either
shape (`package.json` is empty for a pure-Foundry+Soldeer project, so npm
correctly installs nothing) - measured on `term-structure/termmax-contract-v2`
(DEP-3), which reported `0/12 dep-missing` for this exact reason.

NEITHER SHAPE NEEDS THE forge OR soldeer BINARY. CHARTER rule 3 forbids
installing forge (WALK-L9: a Foundry post-install script class RCE
vulnerability, the reason this project never runs `forge install`), and this
module never does:

  * Registry-hosted: `api.soldeer.xyz` is a plain JSON API - list a package's
    revisions, find the pinned version, download its `url` (a public S3 zip)
    and extract it. No different in trust model from an npm tarball fetch,
    and strictly SAFER: a zip extraction runs no code at all, where an npm
    install runs lifecycle scripts unless explicitly disabled.
  * Git-pinned: a plain `git clone` + `checkout <rev>`, through the same
    `history._git` this project already trusts for the target repository
    itself - read-only, no different from resolving any other git dependency.

DIRECTORY NAMING is not guessed: Soldeer's own convention, confirmed against
a real project's ALREADY-COMMITTED `remappings.txt`
(term-structure/termmax-contract-v2), is `dependencies/<toml-key>-<version>/`
- derivable directly from `foundry.toml` alone, so a project's remappings.txt
does not need to exist or be trusted for this to work, though when present it
is what the target's own build already expects to resolve against.
"""

from __future__ import annotations

import shutil
import tomllib
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Optional

SOLDEER_API = "https://api.soldeer.xyz/api/v1"
DEFAULT_TIMEOUT = 30


def has_soldeer_dependencies(root: Path) -> bool:
    """True iff `root/foundry.toml` declares a non-empty `[dependencies]`."""
    return bool(_read_dependencies(root))


def _read_dependencies(root: Path) -> dict:
    f = Path(root) / "foundry.toml"
    if not f.is_file():
        return {}
    try:
        data = tomllib.loads(f.read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - a malformed toml is not fatal here
        return {}
    return data.get("dependencies") or {}


def dependency_dir_name(key: str, entry) -> Optional[str]:
    """`dependencies/<name>/` for one `[dependencies]` entry, Soldeer's own
    convention: `<toml-key>-<version>`. `None` if no version is stated at all
    (Soldeer requires one; a malformed entry is skipped, not guessed at)."""
    version = entry if isinstance(entry, str) else (entry or {}).get("version")
    if not version:
        return None
    return f"{key}-{version}"


def install_soldeer_dependencies(root: Path, *, timeout: int = DEFAULT_TIMEOUT,
                                 on_event=None) -> tuple[bool, str]:
    """Populate `root/dependencies/` for every entry in `foundry.toml`.

    Returns (ok, detail). Best-effort per package: one dependency that cannot
    be resolved (deleted upstream, registry hiccup) is reported by name rather
    than aborting every other package that WOULD have resolved - the same
    "one broken thing must not hide the others" principle `_run_rule` already
    applies to individual rules.
    """
    deps = _read_dependencies(root)
    if not deps:
        return False, "no [dependencies] in foundry.toml"

    def emit(msg: str) -> None:
        if on_event:
            try:
                on_event({"kind": "env", "message": msg})
            except Exception:  # noqa: BLE001
                pass

    depdir = Path(root) / "dependencies"
    depdir.mkdir(exist_ok=True)
    failures: list[str] = []

    for key, entry in deps.items():
        target_name = dependency_dir_name(key, entry)
        if not target_name:
            failures.append(f"{key}: no version declared")
            continue
        target = depdir / target_name
        if target.is_dir() and any(target.iterdir()):
            continue  # already resolved (a prior commit's install, cache reuse)

        if isinstance(entry, dict) and entry.get("git"):
            emit(f"soldeer: cloning {key} ({entry['git']} @ {entry.get('rev', '?')[:12]})")
            ok, why = _resolve_git(entry["git"], entry.get("rev"), target, timeout)
        else:
            version = entry if isinstance(entry, str) else entry.get("version")
            emit(f"soldeer: fetching {key}@{version} from the Soldeer registry")
            ok, why = _resolve_registry(key, version, target, timeout)

        if not ok:
            failures.append(f"{key}: {why}")

    if failures:
        return False, "; ".join(failures)[:500]
    return True, f"resolved {len(deps)} soldeer dependencies"


def _resolve_registry(project_name: str, version: str, target: Path,
                      timeout: int) -> tuple[bool, str]:
    try:
        import requests
    except ImportError:  # pragma: no cover
        return False, "requests not installed"

    try:
        r = requests.get(f"{SOLDEER_API}/revision",
                         params={"project_name": project_name, "revision": version},
                         timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"[:150]
    if r.status_code != 200:
        return False, f"registry lookup HTTP {r.status_code}"

    try:
        revisions = r.json().get("data") or []
    except Exception as exc:  # noqa: BLE001
        return False, f"unparseable registry response: {exc}"

    match = next((rv for rv in revisions if rv.get("version") == version), None)
    if match is None:
        return False, (f"version {version} not found on Soldeer "
                       f"({len(revisions)} other revision(s) exist)")
    url = match.get("url")
    if not url:
        return False, "registry entry has no download url"

    try:
        archive = requests.get(url, timeout=max(timeout, 60))
    except Exception as exc:  # noqa: BLE001
        return False, f"download failed: {type(exc).__name__}: {exc}"[:150]
    if archive.status_code != 200:
        return False, f"download HTTP {archive.status_code}"

    return _extract_zip(archive.content, target)


def _extract_zip(data: bytes, target: Path) -> tuple[bool, str]:
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            # Zip-slip guard: refuse any entry that would extract outside
            # `target`. A registry entry is normally trustworthy, but this
            # project never assumes a downloaded archive is safe by default.
            for name in zf.namelist():
                dest = (target / name).resolve()
                if not str(dest).startswith(str(target.resolve())):
                    return False, f"refused unsafe archive path: {name}"
            target.mkdir(parents=True, exist_ok=True)
            zf.extractall(target)
    except zipfile.BadZipFile:
        return False, "downloaded archive is not a valid zip"
    except Exception as exc:  # noqa: BLE001
        return False, f"extraction failed: {type(exc).__name__}: {exc}"[:150]
    return True, "extracted"


def _resolve_git(url: str, rev: Optional[str], target: Path,
                 timeout: int) -> tuple[bool, str]:
    """One commit, not the repository. MEASURED reason this matters: a
    git-pinned Soldeer dependency can point at a project whose full history is
    enormous relative to the one commit actually needed (termmax-v2 pins
    `@chainlink-contracts` at smartcontractkit/chainlink, a large monorepo - a
    full, unbounded `git clone` of it made an early version of this function
    hang past any reasonable per-dependency budget). A shallow, rev-targeted
    fetch avoids downloading history nothing here will ever read.

    `git fetch --depth 1 origin <rev>` works for an exact commit SHA on
    GitHub (and most modern git hosts) even when that SHA is not a branch
    tip, because GitHub advertises arbitrary reachable objects for fetch. If
    the host refuses (older git servers, `uploadpack.allowReachableSHA1InWant`
    disabled), this fails cleanly and is reported - it does not silently fall
    back to a full clone, which would reintroduce the exact cost this exists
    to avoid.
    """
    from . import history as H

    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)
    try:
        H._git(target, "init", "--quiet", timeout=timeout)
        H._git(target, "remote", "add", "origin", url, timeout=timeout)
        want = rev or "HEAD"
        H._git(target, "fetch", "--quiet", "--depth", "1", "origin", want,
              timeout=timeout * 4)
        H._git(target, "checkout", "--quiet", "--detach", "FETCH_HEAD",
              timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(target, ignore_errors=True)
        return False, f"{type(exc).__name__}: {exc}"[:200]
    # A cloned dependency's OWN .git must not linger: it is not the target
    # under analysis, but leaving real git metadata inside `dependencies/`
    # is unnecessary attack surface and unnecessary disk for no benefit.
    shutil.rmtree(target / ".git", ignore_errors=True)
    # SEC-L1, same reasoning as history.Worktree.checkout: `url`/`rev` here
    # come from the TARGET repository's own foundry.toml - equally untrusted
    # as the target itself (WALK-L9's own governing principle extends to
    # anything the target's build config directs Chainwatch to fetch). A
    # symlink in this vendored tree is read through the exact same
    # unsandboxed compiler path as one in the target's own tree.
    H._strip_symlinks(target)
    return True, "fetched (shallow, one commit)"
