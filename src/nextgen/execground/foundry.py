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
import random
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
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


# --------------------------------------------------------------------------- #
# AnvilFork - an isolated local fork for the Counterfactual Twin (Phase 6) and
# for deep-trace enrichment. Never broadcasts: it IS a local node.
# --------------------------------------------------------------------------- #

def _free_port() -> int:
    for _ in range(20):
        p = random.randint(8600, 8999)
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return 8545


class AnvilError(RuntimeError):
    pass


# A JSON-RPC pass-through that answers `anvil_nodeInfo` / `anvil_metadata` with
# a clean "method not found" so `anvil --fork-url` starts against providers
# (Alchemy, ...) whose proxy returns a fatal HTTP 400 for those probes.
_RPC_SHIM = r'''#!/usr/bin/env python3
import json, sys, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
UP = sys.argv[1]; PORT = int(sys.argv[2])
_NF = {"anvil_nodeInfo", "anvil_metadata"}
def _shim(o):
    m = o.get("method")
    if m in _NF:
        return {"jsonrpc": "2.0", "id": o.get("id"),
                "error": {"code": -32601, "message": "method " + str(m) + " not found"}}
    return None
def _up(data):
    last = None
    for i in range(5):
        try:
            r = urllib.request.Request(UP, data=data,
                                       headers={"content-type": "application/json"})
            return urllib.request.urlopen(r, timeout=45).read()
        except Exception as e:
            last = e; time.sleep(0.4 * (i + 1))
    raise last
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("content-length", 0) or 0)
        raw = self.rfile.read(n)
        try:
            req = json.loads(raw)
        except Exception:
            self.send_response(400); self.end_headers(); return
        try:
            if isinstance(req, list):
                out, passthru = [], []
                for o in req:
                    s = _shim(o)
                    (out if s else passthru).append(s if s else o)
                if passthru:
                    out += json.loads(_up(json.dumps(passthru).encode()))
                payload = json.dumps(out).encode()
            else:
                s = _shim(req)
                payload = json.dumps(s).encode() if s is not None else _up(raw)
        except Exception as e:
            payload = json.dumps({"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32603,
                                            "message": "shim upstream: " + str(e)[:120]}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
'''


class AnvilFork:
    """`with AnvilFork(tc, fork_url=..., fork_block=N) as fork: fork.rpc_url`.

    Starts `anvil --fork-url <url> [--fork-block-number N] --host 0.0.0.0
    --port <p>` (detached in WSL, or a subprocess natively), waits until it
    answers `eth_blockNumber`, and kills it on exit. `--host 0.0.0.0` so a
    Windows caller reaches it over WSL2 localhost forwarding.
    """

    def __init__(self, tc: "Toolchain", *, fork_url: str,
                 fork_block: Optional[int] = None, port: Optional[int] = None,
                 chain_id: Optional[int] = None, timeout: int = 100,
                 extra_args: Optional[list] = None) -> None:
        self.tc = tc
        self.fork_url = fork_url
        self.fork_block = fork_block
        self.port = port or _free_port()
        self.chain_id = chain_id
        self.timeout = timeout
        self.extra_args = list(extra_args or [])
        self.rpc_url = f"http://127.0.0.1:{self.port}"
        self._proc: Optional[subprocess.Popen] = None
        self._wsl_pidfile: Optional[str] = None
        self._wsl_shim_pidfile: Optional[str] = None
        self._shim_port: Optional[int] = None
        self._log: str = ""

    # -- lifecycle --------------------------------------------------------- #

    def __enter__(self) -> "AnvilFork":
        if self.tc.kind == "native":
            argv = ["anvil", "--fork-url", self.fork_url, "--host", "0.0.0.0",
                    "--port", str(self.port), "--silent", "--no-rate-limit"]
            if self.fork_block is not None:
                argv += ["--fork-block-number", str(self.fork_block)]
            if self.chain_id is not None:
                argv += ["--chain-id", str(self.chain_id)]
            argv += self.extra_args
            exe = self.tc.bin_dir or str(Path(self.tc.forge).parent)
            env = {**os.environ,
                   "PATH": exe + os.pathsep + os.environ.get("PATH", "")}
            self._proc = subprocess.Popen(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=env)
        else:
            self._start_wsl()

        self._wait_ready()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def _start_wsl(self) -> None:
        """WSL path: launch a tiny JSON-RPC shim (so `anvil --fork-url` starts
        against providers whose proxy rejects anvil's `anvil_nodeInfo` /
        `anvil_metadata` probes with HTTP 400 - e.g. Alchemy), then anvil
        against the shim. Both are `nohup`-detached; killed by pid on exit.
        Windows reaches anvil at 127.0.0.1:<port> via WSL2 localhost forwarding.
        """
        shim_port = _free_port()
        pidfile = f"/tmp/cw-anvil-{self.port}.pid"
        shim_pidfile = f"/tmp/cw-shim-{shim_port}.pid"
        logfile = f"/tmp/cw-anvil-{self.port}.log"
        shimfile = f"/tmp/cw-rpcshim-{shim_port}.py"
        self._wsl_pidfile = pidfile
        self._wsl_shim_pidfile = shim_pidfile
        self._shim_port = shim_port

        anvil = ["anvil", "--fork-url", f"http://127.0.0.1:{shim_port}",
                 "--host", "0.0.0.0", "--port", str(self.port), "--silent"]
        if self.fork_block is not None:
            anvil += ["--fork-block-number", str(self.fork_block)]
        if self.chain_id is not None:
            anvil += ["--chain-id", str(self.chain_id)]
        anvil += self.extra_args

        import base64
        shim_b64 = base64.b64encode(_RPC_SHIM.encode()).decode()
        # The launcher must NOT return while the fork is in use: `wsl.exe
        # --exec` reaps the whole session (nohup included) when its command
        # exits. So it ends in `wait`, and we keep the Popen alive - killing it
        # tears the WSL session down, taking anvil + shim with it.
        script = "\n".join([
            "#!/usr/bin/env bash",
            f'export PATH="{self.tc.bin_dir}:/usr/local/bin:/usr/bin:/bin"',
            f"rm -f {pidfile} {shim_pidfile}",
            f"echo {shim_b64} | base64 -d > {shimfile}",
            f"python3 {shimfile} {_sh_quote(self.fork_url)} {shim_port} "
            f"> /tmp/cw-shim-{shim_port}.log 2>&1 &",
            "SHIM_PID=$!",
            f"echo $SHIM_PID > {shim_pidfile}",
            "sleep 1.5",
            f"{' '.join(_sh_quote(a) for a in anvil)} > {logfile} 2>&1 &",
            "ANVIL_PID=$!",
            f"echo $ANVIL_PID > {pidfile}",
            'trap "kill $SHIM_PID $ANVIL_PID 2>/dev/null" EXIT',
            "wait $ANVIL_PID",
        ]) + "\n"
        host_dir = Path(tempfile.gettempdir()) / "chainwatch-execground"
        host_dir.mkdir(parents=True, exist_ok=True)
        self._host_sh = host_dir / f"anvil-{self.port}-{uuid.uuid4().hex}.sh"
        self._host_sh.write_text(script, encoding="utf-8", newline="\n")
        self._proc = subprocess.Popen(
            ["wsl.exe", "-d", self.tc.distro, "--exec", "/bin/bash",
             _win_to_wsl(str(self._host_sh))],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _wait_ready(self) -> None:
        deadline = time.time() + self.timeout
        payload = json.dumps({"jsonrpc": "2.0", "id": 1,
                              "method": "eth_blockNumber", "params": []}).encode()
        last = ""
        while time.time() < deadline:
            try:
                req = urllib.request.Request(
                    self.rpc_url, data=payload,
                    headers={"content-type": "application/json"})
                with urllib.request.urlopen(req, timeout=4) as r:
                    body = json.load(r)
                if body.get("result"):
                    return
            except Exception as e:  # noqa: BLE001
                last = f"{type(e).__name__}: {e}"
            time.sleep(1.0)
        self.stop()
        raise AnvilError(f"anvil fork did not become ready on {self.rpc_url} "
                         f"within {self.timeout}s ({last}); "
                         f"log tail: {self._log_tail()}")

    def _log_tail(self) -> str:
        if self.tc.kind != "wsl":
            return ""
        parts = []
        r = self.tc.run(["tail", "-c", "1200", f"/tmp/cw-anvil-{self.port}.log"],
                        cwd=None, timeout=15)
        parts.append("anvil: " + (r.stdout or "").strip()[-1200:])
        sp = getattr(self, "_shim_port", None)
        if sp:
            r2 = self.tc.run(["tail", "-c", "600", f"/tmp/cw-shim-{sp}.log"],
                             cwd=None, timeout=15)
            if (r2.stdout or "").strip():
                parts.append("shim: " + r2.stdout.strip()[-600:])
        return " | ".join(parts)

    def stop(self) -> None:
        # tear down the launcher process (native anvil, or the persistent
        # `wsl.exe` whose EXIT trap kills anvil + shim).
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=8)
            except Exception:  # noqa: BLE001
                self._proc.kill()
        self._proc = None
        try:
            if getattr(self, "_host_sh", None):
                self._host_sh.unlink()
        except OSError:
            pass
        if self.tc.kind == "native":
            return
        # WSL: kill anvil + the shim by recorded pid, then name-based backstops.
        for pf in (self._wsl_pidfile, getattr(self, "_wsl_shim_pidfile", None)):
            if not pf:
                continue
            pid = (self.tc.read_file(pf) or "").strip()
            if pid:
                self.tc.run(["kill", pid], cwd=None, timeout=15)
        self.tc.run(["pkill", "-f", f"anvil.*--port {self.port}"], cwd=None,
                    timeout=15)
        sp = getattr(self, "_shim_port", None)
        if sp:
            self.tc.run(["pkill", "-f", f"cw-rpcshim-{sp}"], cwd=None, timeout=15)


def anvil_available() -> bool:
    tc = resolve()
    if tc is None:
        return False
    r = tc.run(["anvil", "--version"], cwd=None, timeout=30)
    return r.ok and "anvil" in (r.stdout + r.stderr).lower()
