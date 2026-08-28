"""Dependency-aware compilation for the next-gen pipeline on REAL repositories.

The Phase 1-5 modules compile self-contained sources. Real protocol code imports
OpenZeppelin, Solmate, forge-std, ... so a self-contained compile returns
`measurable=False` and the pipeline degrades to UNKNOWN. This module bridges
that gap by reusing the CLASSIC engine's own machinery - `src/history.py`
(mirror clone, per-commit worktree, env reconstruction) and
`src/rules/_shared.py` (compile with the right solc + remappings) - so a
next-gen analysis of a real commit sees exactly what the classic scanner sees.

    RepoContext(repo_path)            mirror-clone once, reuse worktrees
      .compiled(sha, rel_path)       -> Slither, with dependencies resolved
      .source_at(sha, rel_path)      -> file text at that commit
      .flatten(sha, rel_path)        -> a self-contained source bundle (forge
                                        flatten via the execground toolchain,
                                        else a best-effort Python flatten)
      .build_context(sha, ...)       -> a buildenv.BuildContext for §19
      .close()                       remove the scratch worktrees

Read-only on the target, always (CHARTER rule 5): every git operation runs
against the mirror clone in Chainwatch's own scratch, never the path the caller
passed.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import history as H
from ..rules import _shared, _storage

_SCRATCH = Path(tempfile.gettempdir()) / "chainwatch-nextgen"


@dataclass
class CheckoutInfo:
    path: Path
    solc_pin: Optional[str]
    node_manager: Optional[str]
    deps_ok: bool
    deps_detail: str


class RepoContext:
    def __init__(self, repo_path, *, scratch: Optional[Path] = None) -> None:
        src = Path(repo_path).resolve()
        if not (src / ".git").exists():
            raise ValueError(f"{src} is not a git working tree")
        key = hashlib.sha256(str(src).encode()).hexdigest()[:16]
        base = Path(scratch) if scratch else _SCRATCH
        self.origin = H.mirror_clone(src, base / "mirror" / key)
        self._wt_root = base / "wt" / key
        self._cache = base / "cache"
        self._worktrees: dict[str, H.Worktree] = {}
        self._info: dict[str, CheckoutInfo] = {}

    # -- checkout + env -------------------------------------------------- #

    def _worktree(self, slot: str) -> H.Worktree:
        if slot in self._worktrees:
            return self._worktrees[slot]
        path = self._wt_root / slot
        # A previous run may have left the directory (Windows `git worktree
        # remove` can fail to delete a linked node_modules). Prune stale
        # registrations, then reuse a valid checkout or clear a broken one.
        try:
            H._git(self.origin, "worktree", "prune", check=False, timeout=60)
        except Exception:  # noqa: BLE001
            pass
        if path.exists() and not (path / ".git").exists():
            shutil.rmtree(path, ignore_errors=True)
        try:
            self._worktrees[slot] = H.Worktree(self.origin, path)
        except Exception:  # noqa: BLE001 - retry once with a forced add
            shutil.rmtree(path, ignore_errors=True)
            try:
                H._git(self.origin, "worktree", "prune", check=False, timeout=60)
                subprocess.run(["git", *H.git_safety_args(), "worktree", "add",
                                "--detach", "--force", str(path), "HEAD"],
                               cwd=str(self.origin), capture_output=True,
                               text=True, timeout=600)
            except Exception:  # noqa: BLE001
                pass
            self._worktrees[slot] = H.Worktree(self.origin, path)
        return self._worktrees[slot]

    def checkout(self, sha: str, *, slot: Optional[str] = None) -> CheckoutInfo:
        slot = slot or _slot_for(sha)
        wt = self._worktree(slot)
        try:
            wt.checkout(sha)          # includes SEC-L1 symlink strip
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"checkout {sha[:12]} failed: {exc}") from exc

        spec = H.detect_env(wt.path)
        deps_ok, cause, detail = True, "", "no node dependency system declared"
        try:
            deps_ok, cause, detail = H.install(spec, self._cache)
        except Exception as exc:  # noqa: BLE001
            deps_ok, detail = False, f"install raised: {type(exc).__name__}: {exc}"
        _apply_build_config(spec)

        info = CheckoutInfo(wt.path, spec.solc_pin, spec.node_manager,
                            deps_ok, (cause + ": " + detail).strip(": "))
        self._info[sha] = info
        return info

    # -- reads ------------------------------------------------------------ #

    def source_at(self, sha: str, rel_path: str) -> Optional[str]:
        try:
            return H.file_at(self.origin, sha, rel_path)
        except Exception:  # noqa: BLE001
            return None

    def compiled(self, sha: str, rel_path: str):
        """A `Slither` object for `rel_path` at `sha`, dependencies resolved.
        Raises on failure (the caller treats that as `measurable=False`)."""
        info = self.checkout(sha)
        target = info.path / rel_path
        if not target.is_file():
            raise FileNotFoundError(f"{rel_path} absent at {sha[:12]}")
        _shared.reset_caches()
        _storage.reset_caches()
        return _shared.parse(target)

    def flatten(self, sha: str, rel_path: str, *, toolchain=None) -> Optional[str]:
        """A self-contained source bundle for the reproducer. Tries
        `forge flatten` in the execground toolchain first (handles remappings,
        pragma spans), then a naive recursive-import inliner."""
        info = self.checkout(sha)
        target = info.path / rel_path
        if not target.is_file():
            return None

        flat = _forge_flatten(info.path, rel_path, toolchain)
        if flat:
            return flat
        return _python_flatten(target, info.path)

    def build_context(self, sha: str, *, target_file: str = "",
                      deployed_solc: Optional[str] = None,
                      deployed_optimizer: Optional[bool] = None,
                      deployed_runs: Optional[int] = None,
                      deployed_evm: Optional[str] = None):
        """A `buildenv.BuildContext` for §19: the commit's own compiler
        (config pin, else an exact pragma) + any known deployed settings."""
        from . import buildenv as BE
        info = self._info.get(sha) or self.checkout(sha)
        rel = target_file or self._first_sol(sha) or ""
        txt = None
        try:
            txt = H.file_at(self.origin, sha, rel) if rel else None
        except Exception:  # noqa: BLE001
            txt = None
        pragma = _pragma_of(txt) if txt else None
        # what we actually compiled with: a config pin, or the exact pragma
        # (which `_shared._compile_attempt` selects via `exact_pin_installed`),
        # or the ambient SOLC_VERSION.
        exact = _exact_from_pragma(pragma)
        analysis_solc = info.solc_pin or exact or os.environ.get("SOLC_VERSION")
        return BE.BuildContext(
            pragma_expr=pragma,
            pinned_solc=info.solc_pin or exact,
            analysis_solc=analysis_solc,
            deployed_solc=deployed_solc,
            deployed_optimizer=deployed_optimizer,
            deployed_runs=deployed_runs,
            deployed_evm=deployed_evm)

    def _first_sol(self, sha: str) -> Optional[str]:
        try:
            out = H._git(self.origin, "ls-tree", "-r", "--name-only", sha)
        except Exception:  # noqa: BLE001
            return None
        for line in out.splitlines():
            if line.endswith(".sol") and "/test" not in line.lower():
                return line
        return None

    # -- lifecycle ------------------------------------------------------- #

    def close(self) -> None:
        for wt in self._worktrees.values():
            try:
                wt.remove()
            except Exception:  # noqa: BLE001
                pass
        self._worktrees.clear()

    def __enter__(self) -> "RepoContext":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --------------------------------------------------------------------------- #

def _slot_for(sha: str) -> str:
    return "c-" + hashlib.sha256(sha.encode()).hexdigest()[:8]


def _apply_build_config(spec: "H.EnvSpec") -> list[str]:
    """Bind one checkout to its remappings + compiler pin. Mirrors
    `src/scan.py::_apply_build_config` (kept in sync deliberately - a next-gen
    compile must see the same environment the classic rules see)."""
    remaps = H.derive_remaps(spec.root, absolute=True)
    _shared.register_root(spec.root, remaps)
    _shared.REMAPS = list(remaps)
    _storage.REMAPPINGS = list(remaps)
    _storage.PROJECT_ROOT = Path(spec.root)
    if spec.solc_pin:
        os.environ["SOLC_VERSION"] = spec.solc_pin
    return remaps


_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")
_IMPORT = re.compile(r'^\s*import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']',
                     re.M)
_SPDX = re.compile(r"^\s*//\s*SPDX-License-Identifier:.*$", re.M)


def _pragma_of(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    m = _PRAGMA.search(text)
    return m.group(1).strip() if m else None


def _exact_from_pragma(expr: Optional[str]) -> Optional[str]:
    """`0.5.17` / `=0.5.17` -> "0.5.17"; a caret / range -> None."""
    if not expr:
        return None
    e = expr.strip().lstrip("=").strip()
    if any(t in e for t in ("^", "~", ">", "<", " - ", "||", "x", "*")):
        return None
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", e)
    return e if m else None


def _forge_flatten(root: Path, rel_path: str, toolchain) -> Optional[str]:
    try:
        from .execground import foundry as F
    except Exception:  # noqa: BLE001
        return None
    tc = toolchain or F.resolve()
    if tc is None:
        return None
    # copy the worktree into the toolchain filesystem only if remote (WSL);
    # for native, run in place.
    if tc.kind == "native":
        r = tc.run(["forge", "flatten", rel_path], cwd=str(root), timeout=180)
        return r.stdout if r.ok and "pragma solidity" in r.stdout else None
    # WSL: the worktree is under /mnt/... already visible; translate the path
    lin = F._win_to_wsl(str(root))
    r = tc.run(["forge", "flatten", rel_path], cwd=lin, timeout=180)
    return r.stdout if r.ok and "pragma solidity" in r.stdout else None


def _python_flatten(entry: Path, root: Path, *, _seen: Optional[set] = None,
                    _top: bool = True) -> str:
    """Naive recursive import inliner: resolve relative + node_modules imports,
    concatenate dependencies first, strip every nested pragma/SPDX, and emit a
    single pragma + SPDX at the head. Best effort - `forge flatten` is
    preferred; this is the fallback when no toolchain is present."""
    _seen = _seen if _seen is not None else set()
    entry = entry.resolve()
    if entry in _seen or not entry.is_file():
        return ""
    _seen.add(entry)
    text = entry.read_text(encoding="utf-8", errors="replace")
    head_pragma = _pragma_of(text) or "^0.8.0"

    parts: list[str] = []
    for m in _IMPORT.finditer(text):
        dep = _resolve_import(m.group(1), entry.parent, root)
        if dep and dep.is_file():
            parts.append(_python_flatten(dep, root, _seen=_seen, _top=False))
    body = _PRAGMA.sub("", _SPDX.sub("", _IMPORT.sub("", text)))
    parts.append(body)
    flat = "\n".join(p for p in parts if p.strip())

    if _top:
        return (f"// SPDX-License-Identifier: MIXED\npragma solidity "
                f"{head_pragma};\n{flat}")
    return flat


def _resolve_import(spec: str, from_dir: Path, root: Path) -> Optional[Path]:
    if spec.startswith("."):
        return (from_dir / spec).resolve()
    for base in (root / "node_modules", root / "lib", root):
        cand = (base / spec)
        if cand.is_file():
            return cand
    # remapping-style: try stripping the first path segment against lib/
    parts = spec.split("/", 1)
    if len(parts) == 2:
        cand = root / "lib" / parts[0] / "src" / parts[1]
        if cand.is_file():
            return cand
    return None
