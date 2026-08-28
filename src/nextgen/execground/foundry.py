"""Foundry toolchain adapter - native `forge`/`anvil`, or WSL.

On the Linux / Cloud Run target, `forge` is on PATH and used directly. On the
Windows dev host it lives in WSL (`kali-linux`, `~/.foundry/bin`), reached
through `wsl.exe`. Both are exercised the same way: this module hands back a
`Toolchain` whose `.run(argv, cwd)` returns a `RunResult`, or `None` when no
toolchain is reachable.

DISCOVERY, in order:
  1. `CHAINWATCH_FORGE` env var - an explicit path to a `forge` binary
  2. `forge` on PATH (native)
  3. WSL: `wsl.exe -d <distro> -- test -x ~/.foundry/bin/forge`

Nothing here can broadcast a transaction: the only subcommands used are
`forge build` and `forge test` (which may fork, locally). `anvil` is started
only bound to loopback for a local fork.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Optional

_WSL_DISTRO = os.environ.get("CHAINWATCH_WSL_DISTRO", "kali-linux")
_WSL_FOUNDRY_BIN = os.environ.get(
    "CHAINWATCH_WSL_FOUNDRY", "/home/kali/.foundry/bin")
_DEFAULT_TIMEOUT = 240


@dataclass
class RunResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    argv: list[str] = field(default_factory=list)
    timed_out: bool = False

    def as_dict(self) -> dict:
        return {"ok": self.ok, "returncode": self.returncode,
                "timed_out": self.timed_out,
                "stdout_tail": self.stdout[-4000:], "stderr_tail": self.stderr[-2000:]}


def _win_to_wsl(p: str) -> str:
    """C:\\a\\b  ->  /mnt/c/a/b  (leave already-posix paths untouched)."""
    p = str(p)
    if len(p) >= 2 and p[1] == ":" and p[0].isalpha():
        drive = p[0].lower()
        rest = p[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    return p.replace("\\", "/")


class Toolchain:
    """A resolved Foundry toolchain. `kind` is 'native' or 'wsl'."""

    def __init__(self, kind: str, forge: str, *, distro: str = "",
                 bin_dir: str = "") -> None:
        self.kind = kind
        self.forge = forge
        self.distro = distro
        self.bin_dir = bin_dir

    # -- description ---------------------------------------------------------- #

    def describe(self) -> str:
        if self.kind == "native":
            return f"native forge at {self.forge}"
        return f"WSL forge ({self.distro}:{self.bin_dir})"

    def version(self) -> str:
        r = self.run(["forge", "--version"], cwd=None, timeout=30)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "?"

    # -- execution --------------------------------------------------------- #

    def run(self, argv: list[str], cwd: Optional[str],
            timeout: int = _DEFAULT_TIMEOUT, env_extra: Optional[dict] = None
            ) -> RunResult:
        """Run a forge/anvil/cast/bash argv. `cwd` is a path in the toolchain's
        own filesystem view (a Linux path for WSL, any path for native)."""
        if self.kind == "native":
            return self._run_native(argv, cwd, timeout, env_extra)
        return self._run_wsl(argv, cwd, timeout, env_extra)

    def _run_native(self, argv, cwd, timeout, env_extra) -> RunResult:
        exe = self.bin_dir or str(Path(self.forge).parent)
        env = {**os.environ, "PATH": exe + os.pathsep + os.environ.get("PATH", "")}
        if env_extra:
            env.update(env_extra)
        try:
            p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=timeout, env=env)
            return RunResult(p.returncode == 0, p.returncode, p.stdout, p.stderr,
                             argv)
        except subprocess.TimeoutExpired as e:
            return RunResult(False, -1, e.stdout or "", e.stderr or "", argv,
                             timed_out=True)

    def _run_wsl(self, argv, cwd, timeout, env_extra) -> RunResult:
        # Build a small shell script; run it via `wsl --exec /bin/bash script`.
        lines = ["#!/usr/bin/env bash", "set -o pipefail",
                 f'export PATH="{self.bin_dir}:/usr/local/bin:/usr/bin:/bin"']
        for k, v in (env_extra or {}).items():
            lines.append(f'export {k}={_sh_quote(str(v))}')
        if cwd:
            lines.append(f'cd {_sh_quote(cwd)} || exit 97')
        lines.append(" ".join(_sh_quote(a) for a in argv))
        script = "\n".join(lines) + "\n"

        host_dir = Path(tempfile.gettempdir()) / "chainwatch-execground"
        host_dir.mkdir(parents=True, exist_ok=True)
        host_sh = host_dir / f"run-{uuid.uuid4().hex}.sh"
        host_sh.write_text(script, encoding="utf-8", newline="\n")
        try:
            cmd = ["wsl.exe", "-d", self.distro, "--exec", "/bin/bash",
                   _win_to_wsl(str(host_sh))]
            p = subprocess.run(cmd, capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=timeout)
            return RunResult(p.returncode == 0, p.returncode, p.stdout, p.stderr,
                             argv)
        except subprocess.TimeoutExpired as e:
            return RunResult(False, -1, e.stdout or "", e.stderr or "", argv,
                             timed_out=True)
        finally:
            try:
                host_sh.unlink()
            except OSError:
                pass

    # -- filesystem helpers for WSL ------------------------------------------ #

    def make_tempdir(self, prefix: str = "cw-repro-") -> Optional[str]:
        """A fresh working dir in the toolchain's filesystem. Returns a path in
        that filesystem's view (Linux path for WSL)."""
        if self.kind == "native":
            return tempfile.mkdtemp(prefix=prefix)
        name = f"/tmp/{prefix}{uuid.uuid4().hex}"
        r = self.run(["mkdir", "-p", name], cwd=None, timeout=20)
        return name if r.ok else None

    def write_file(self, path_in_tc: str, content: str) -> bool:
        """Write `content` to `path_in_tc` (a path in the toolchain filesystem)."""
        if self.kind == "native":
            try:
                Path(path_in_tc).parent.mkdir(parents=True, exist_ok=True)
                Path(path_in_tc).write_text(content, encoding="utf-8", newline="\n")
                return True
            except OSError:
                return False
        # WSL: pipe via base64 to avoid every quoting hazard
        import base64
        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        script = (f'mkdir -p "$(dirname {_sh_quote(path_in_tc)})" && '
                  f'echo {b64} | base64 -d > {_sh_quote(path_in_tc)}')
        r = self._run_wsl(["bash", "-c", script], None, 30, None)
        return r.ok

    def read_file(self, path_in_tc: str) -> Optional[str]:
        r = self.run(["cat", path_in_tc], cwd=None, timeout=20)
        return r.stdout if r.ok else None

    def rmtree(self, path_in_tc: str) -> None:
        self.run(["rm", "-rf", path_in_tc], cwd=None, timeout=20)


def _sh_quote(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


_CACHED: Optional["Toolchain"] = None
_PROBED = False


def resolve(*, force: bool = False) -> Optional[Toolchain]:
    """The best available Foundry toolchain, or None. Cached."""
    global _CACHED, _PROBED
    if _PROBED and not force:
        return _CACHED
    _PROBED = True
    _CACHED = _resolve_uncached()
    return _CACHED


def _resolve_uncached() -> Optional[Toolchain]:
    explicit = os.environ.get("CHAINWATCH_FORGE")
    if explicit and Path(explicit).exists():
        return Toolchain("native", explicit,
                         bin_dir=str(Path(explicit).parent))

    native = shutil.which("forge")
    if native:
        return Toolchain("native", native, bin_dir=str(Path(native).parent))

    # WSL
    if shutil.which("wsl.exe") or shutil.which("wsl"):
        wsl = shutil.which("wsl.exe") or shutil.which("wsl")
        probe = f"{_WSL_FOUNDRY_BIN}/forge"
        try:
            p = subprocess.run([wsl, "-d", _WSL_DISTRO, "--exec",
                                "/bin/bash", "-c", f'test -x {_sh_quote(probe)}'],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=30)
            if p.returncode == 0:
                return Toolchain("wsl", probe, distro=_WSL_DISTRO,
                                 bin_dir=_WSL_FOUNDRY_BIN)
        except Exception:  # noqa: BLE001
            return None
    return None


def available() -> bool:
    return resolve() is not None


def status() -> dict:
    tc = resolve()
    if tc is None:
        return {"available": False,
                "reason": "no `forge` on PATH, no CHAINWATCH_FORGE, and no "
                          "usable WSL Foundry install"}
    return {"available": True, "kind": tc.kind, "describe": tc.describe(),
            "version": tc.version()}
