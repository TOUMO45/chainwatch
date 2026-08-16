"""Chainwatch web app - the researcher-facing front end.

    python -m uvicorn webapp.server:app --port 8000
    (or simply: python webapp/server.py)

It is a thin shell over `src/scan.py`: the browser starts a scan, watches it
progress over Server-Sent Events, and then reads the same report dict the CLI
prints. There is deliberately no analysis logic here - a second implementation
of "what counts as a finding" is exactly how a UI starts disagreeing with its
engine.

BINDS TO 127.0.0.1 BY DEFAULT. A scan installs the target repository's
dependencies (with lifecycle scripts disabled, per src/history.install) and
reads its git history, so the endpoint that starts one is not something to
expose to a network. `--host` exists for containers; use it deliberately.

READ-ONLY, ALWAYS (CHARTER rule 5): every route either reads the target
repository through git, or reads chain state through eth_* calls. No route
writes to a repository, and none can construct a transaction.
"""

from __future__ import annotations

import asyncio
import json
import queue
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from sse_starlette.sse import EventSourceResponse  # noqa: E402

from src.scan import RULE_ORDER, RULE_TITLES, ScanOptions, scan  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
CLONES = ROOT / ".webapp-clones"

from chainwatch import CLONE_SCHEMES  # noqa: E402  (one definition, two callers)

app = FastAPI(title="Chainwatch", docs_url=None, redoc_url=None)


@app.middleware("http")
async def no_store(request, call_next):
    """Never let a browser cache the UI. This is a local tool that is edited
    while it runs; a stale app.js against a newer API is a debugging trap that
    costs more than the bytes saved."""
    response = await call_next(request)
    if request.url.path.startswith("/static") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-store, must-revalidate"
    return response


# --------------------------------------------------------------------------- state


@dataclass
class Job:
    id: str
    repo: str
    status: str = "queued"          # queued | cloning | running | done | error | cancelled
    started: float = field(default_factory=time.time)
    finished: Optional[float] = None
    error: str = ""
    report: Optional[dict] = None
    events: list[dict] = field(default_factory=list)
    q: "queue.Queue[dict]" = field(default_factory=queue.Queue)
    stop: threading.Event = field(default_factory=threading.Event)
    repo_path: Optional[Path] = None
    # Capability 12: one entry per finding the user asked a dossier for.
    # {finding_id: {status, markdown, error_message, log:[...]}}
    reports: dict = field(default_factory=dict)

    def push(self, ev: dict) -> None:
        self.events.append(ev)
        self.q.put(ev)

    def brief(self) -> dict:
        return {
            "id": self.id,
            "repo": self.repo,
            "status": self.status,
            "started": self.started,
            "finished": self.finished,
            "error": self.error,
            "summary": (self.report or {}).get("summary"),
        }


JOBS: dict[str, Job] = {}
# One scan at a time: two concurrent scans would fight over the scratch
# worktrees and over the process-wide compiler/remap configuration.
_RUN_LOCK = threading.Lock()


class ScanRequest(BaseModel):
    repo: str
    limit: int = 30
    root_dir: str = ""
    address: Optional[str] = None
    rpc_url: Optional[str] = None
    rules: Optional[list[str]] = None
    check_head_survival: bool = True
    # Explicit "prev:cur" commit pairs instead of walking recent history. This
    # is what makes a demo (or a re-check of a previously root-caused case)
    # reproducible rather than dependent on whatever the repo's tip happens to
    # be. Mirrors ScanOptions.explicit_pairs exactly.
    pairs: Optional[list[str]] = None


# --------------------------------------------------------------------------- helpers


def _clone(url: str, job: Job) -> Path:
    CLONES.mkdir(parents=True, exist_ok=True)
    name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    target = CLONES / name
    if (target / ".git").exists():
        job.push({"kind": "info", "message": f"reusing existing clone at {target}"})
        return target
    job.status = "cloning"
    job.push({"kind": "info", "message": f"cloning {url} (full history, read-only)"})
    proc = subprocess.run(["git", "clone", url, str(target)],
                          capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        raise RuntimeError(f"clone failed: {proc.stderr[:400]}")
    return target


def _run_job(job: Job, req: ScanRequest) -> None:
    with _RUN_LOCK:
        try:
            repo = req.repo.strip()
            if repo.startswith(CLONE_SCHEMES):
                path = _clone(repo, job)
            else:
                path = Path(repo).expanduser()
                if not path.is_absolute():
                    path = (ROOT / path).resolve()
            if not (path / ".git").exists():
                raise RuntimeError(f"{path} is not a git working tree")
            job.repo_path = path
            job.status = "running"

            opts = ScanOptions(
                repo=path,
                limit=req.limit,
                root_dir=req.root_dir,
                address=req.address or None,
                rpc_url=req.rpc_url or None,
                rules=req.rules or None,
                check_head_survival=req.check_head_survival,
                explicit_pairs=[tuple(p.split(":", 1)) for p in (req.pairs or [])
                                if ":" in p] or None,
            )
            job.report = scan(opts, on_event=job.push, should_stop=job.stop.is_set)
            # Stable per-finding handles, computed by the agent layer rather than
            # the engine: the report format is ground truth and should not grow a
            # field because a front end wants a button target.
            from agent.store import finding_id as _fid

            for f in job.report.get("findings", []):
                f["finding_id"] = _fid(f)
            job.status = "cancelled" if job.stop.is_set() else "done"
        except Exception as exc:  # noqa: BLE001 - surfaced to the browser, not swallowed
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.push({"kind": "error", "message": job.error})
        finally:
            job.finished = time.time()
            job.push({"kind": "closed", "status": job.status})


# --------------------------------------------------------------------------- routes


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    if any(j.status in ("queued", "cloning", "running") for j in JOBS.values()):
        raise HTTPException(409, "a scan is already running; cancel it first")
    job = Job(id=uuid.uuid4().hex[:12], repo=req.repo)
    JOBS[job.id] = job
    threading.Thread(target=_run_job, args=(job, req), daemon=True).start()
    return {"id": job.id}


@app.get("/api/scans")
def list_scans():
    return {"scans": [j.brief() for j in
                      sorted(JOBS.values(), key=lambda j: -j.started)]}


@app.get("/api/scan/{job_id}")
def get_scan(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "no such scan")
    return {**job.brief(), "report": job.report}


@app.post("/api/scan/{job_id}/cancel")
def cancel_scan(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "no such scan")
    job.stop.set()
    return {"ok": True, "status": job.status}


@app.get("/api/scan/{job_id}/events")
async def scan_events(job_id: str):
    """SSE stream. Replays everything already emitted, then follows live, so a
    browser that connects late (or reconnects) still sees the whole run."""
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "no such scan")

    async def gen():
        sent = 0
        while True:
            while sent < len(job.events):
                yield {"data": json.dumps(job.events[sent])}
                sent += 1
            if job.status in ("done", "error", "cancelled") and sent >= len(job.events):
                yield {"data": json.dumps({"kind": "closed", "status": job.status})}
                return
            await asyncio.sleep(0.25)

    return EventSourceResponse(gen())


@app.get("/api/scan/{job_id}/diff")
def get_diff(job_id: str, file: str, prev: str, cur: str, context: int = 6):
    """The actual `git diff` for one finding's file at its regression commit.

    This is the evidence a researcher reads: not our description of the change,
    the change. Read-only `git diff` against the analysed repository.
    """
    job = JOBS.get(job_id)
    if not job or not job.repo_path:
        raise HTTPException(404, "no such scan")
    try:
        proc = subprocess.run(
            ["git", "diff", f"-U{max(0, min(context, 40))}", prev, cur, "--", file],
            cwd=str(job.repo_path), capture_output=True, text=True, timeout=120,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"git diff failed: {exc}")
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr[:400])
    return {"diff": proc.stdout}


@app.get("/api/scan/{job_id}/source")
def get_source(job_id: str, file: str, rev: str, start: int = 1, end: int = 0):
    """A slice of one file at one revision - the function the rule fired on,
    read straight out of git."""
    job = JOBS.get(job_id)
    if not job or not job.repo_path:
        raise HTTPException(404, "no such scan")
    proc = subprocess.run(["git", "show", f"{rev}:{file}"],
                          cwd=str(job.repo_path), capture_output=True, text=True,
                          timeout=120)
    if proc.returncode != 0:
        raise HTTPException(404, proc.stderr[:300])
    lines = proc.stdout.splitlines()
    lo = max(1, start)
    hi = end if end and end >= lo else min(len(lines), lo + 60)
    return {"start": lo, "end": min(hi, len(lines)),
            "lines": lines[lo - 1: min(hi, len(lines))]}


@app.get("/api/rules")
def rules():
    return {"order": RULE_ORDER, "titles": RULE_TITLES}


# ----------------------------------------------------- capability 12: dossiers


@app.get("/api/agent")
def agent_status():
    """Whether the report layer is usable. The engine never needs a key; only
    this does, and the UI must be able to say so rather than fail obscurely."""
    from agent import runner as R

    return {"available": R.api_key_present(), "model": R.DEFAULT_MODEL,
            "rpm_budget": R.DEFAULT_RPM}


def _run_report(job: Job, finding_id: str) -> None:
    """Draft one dossier in the background. Rate limiting lives in the runner,
    so a free-tier pause shows up as progress rather than a stalled request."""
    from agent import FindingStore
    from agent import runner as R

    slot = job.reports[finding_id]
    try:
        store = FindingStore(job.report or {})
        def on_event(ev):
            kind = ev.get("kind")
            if kind == "tool":
                slot["log"].append(f"tool: {ev['tool']}")
            elif kind == "throttle":
                slot["log"].append(f"pacing {ev['seconds']}s to stay inside the "
                                   f"free-tier rate limit")
            elif kind == "retry":
                slot["log"].append(f"{ev['reason']}; server asked for "
                                   f"{ev['seconds']}s, waiting")
            elif kind == "error":
                slot["log"].append(f"error: {ev['message']}")

        res = R.generate_report_sync(store, finding_id, ROOT / "reports",
                                     on_event=on_event)
        slot["status"] = res["status"]
        slot["markdown"] = res.get("markdown", "")
        slot["error_message"] = res.get("error_message", "")
        slot["violations"] = res.get("violations", [])
        slot["verified"] = res.get("verified")
        slot["path"] = res.get("path")
    except Exception as exc:  # noqa: BLE001
        slot["status"] = "error"
        slot["error_message"] = f"{type(exc).__name__}: {exc}"[:400]


@app.post("/api/scan/{job_id}/report/{finding_id}")
def start_report(job_id: str, finding_id: str):
    job = JOBS.get(job_id)
    if not job or not job.report:
        raise HTTPException(404, "no such scan")
    if not any(f.get("finding_id") == finding_id
               for f in job.report.get("findings", [])):
        raise HTTPException(404, "no such finding in this scan")
    existing = job.reports.get(finding_id)
    if existing and existing["status"] == "running":
        return {"status": "running"}
    job.reports[finding_id] = {"status": "running", "markdown": "",
                               "error_message": "", "log": [], "violations": []}
    threading.Thread(target=_run_report, args=(job, finding_id),
                     daemon=True).start()
    return {"status": "running"}


@app.get("/api/scan/{job_id}/report/{finding_id}")
def get_report(job_id: str, finding_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "no such scan")
    slot = job.reports.get(finding_id)
    if not slot:
        return {"status": "none"}
    return slot


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
def healthz():
    return JSONResponse({"ok": True})


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


if __name__ == "__main__":
    import argparse

    import uvicorn

    ap = argparse.ArgumentParser(description="Chainwatch web app")
    ap.add_argument("--host", default="127.0.0.1",
                    help="default 127.0.0.1; change only deliberately (see module docstring)")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    print(f"Chainwatch UI -> http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
