"""Capability 21 - the unattended sweep: many repositories, nobody watching.

Everything else in Chainwatch is started by a human who then reads the answer.
This is the path where no one is present: a schedule fires, a list of
repositories is walked end to end, and the results are recorded for someone to
read later. That changes exactly one requirement, and it is the one this module
is built around:

    A FAILING TARGET MUST NOT END THE SWEEP.

An interactive scan may fail loudly - the human is right there. An unattended
one may not: a repository that will not clone, will not install, or blows up in
a rule takes down the other nineteen with it if the failure escapes. So every
target is wrapped, every failure is RECORDED WITH ITS REASON, and the sweep
continues. A sweep of twenty repos where three failed is a result; a sweep that
died on repo four is not.

That is the same instinct as the coverage invariant in `scan.py`: what could
NOT be done is part of the report, not an absence in it. `totals` therefore
carries `failed` next to `ok`, and a reader who ignores it is misreading the
sweep exactly as a reader who ignores coverage is misreading a scan.

NOTHING HERE DECIDES ANYTHING. It calls `scan.scan` and, optionally, the ADK
orchestration - both of which end at the same gate function they always do. The
sweep counts verdicts; it does not produce them.
"""

from __future__ import annotations

import hashlib
import tempfile
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import funnel as FUNNEL
from .history import clone_public
from .scan import ScanOptions, scan

SCHEMA = "chainwatch.sweep.v1"

CLONE_SCHEMES = ("http://", "https://", "git@", "ssh://", "git://", "file://")


@dataclass
class SweepTarget:
    """One repository to walk. `address` is optional and usually absent - a
    sweep over public repos has no deployed address, which is precisely why a
    sweep produces UNKNOWN/CANDIDATE rows and not CONFIRMED ones."""

    repo: str
    root: str = ""
    address: str = ""
    limit: int = 15
    rules: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, line: str) -> Optional["SweepTarget"]:
        """`repo[,root[,address[,limit]]]`, `#` comments, blanks ignored."""
        line = line.split("#", 1)[0].strip()
        if not line:
            return None
        parts = [p.strip() for p in line.split(",")]
        t = cls(repo=parts[0])
        if len(parts) > 1 and parts[1]:
            t.root = parts[1]
        if len(parts) > 2 and parts[2]:
            t.address = parts[2]
        if len(parts) > 3 and parts[3]:
            try:
                t.limit = int(parts[3])
            except ValueError:
                pass
        return t


def load_targets(path) -> list[SweepTarget]:
    text = Path(path).read_text(encoding="utf-8")
    out = []
    for line in text.splitlines():
        t = SweepTarget.parse(line)
        if t:
            out.append(t)
    return out


def _resolve(repo: str, workdir: Path) -> Path:
    if repo.startswith(CLONE_SCHEMES):
        return Path(clone_public(repo, workdir))
    p = Path(repo).resolve()
    if not (p / ".git").exists():
        raise RuntimeError(f"{p} is not a git working tree")
    return p


def run_one(target: SweepTarget, *, workdir: Optional[Path] = None,
            use_agent: bool = False,
            on_event: Optional[Callable[[dict], None]] = None) -> dict:
    """Scan one target. Returns a row; NEVER raises.

    The bare `except` is deliberate and is the module's whole point - see the
    docstring. The traceback is kept (truncated) so an unattended failure is
    still diagnosable the next morning.
    """
    started = time.time()
    row = {"repo": target.repo, "ok": False, "error": "", "head": "",
           "summary": {}, "funnel_summary": {}, "agent": {}, "seconds": 0.0}
    workdir = workdir or Path(tempfile.gettempdir()) / "chainwatch-sweep"
    try:
        path = _resolve(target.repo, workdir)
        opts = ScanOptions(
            repo=path, limit=target.limit, root_dir=target.root,
            address=target.address or None,
            rules=list(target.rules) or None,
        )
        rep = scan(opts, on_event=None)
        row["head"] = rep.get("head") or ""
        row["summary"] = rep.get("summary") or {}
        row["funnel_summary"] = (rep.get("funnel") or {}).get("summary", {})
        row["ok"] = True

        if use_agent:
            # Imported here: a sweep with no agent must not require ADK to be
            # installed at all.
            from agent import orchestrator as ORCH
            run = ORCH.run(rep, use_llm=True, limit=5)
            row["agent"] = {
                "model": run["model"], "llm": run["llm"],
                "verdicts_unchanged": run["verdicts_unchanged"],
                "turns": len(run["turns"]),
                "dropped_proposals": len(run["hunter_dropped"]),
            }
    except Exception as exc:  # noqa: BLE001 - see the module docstring
        row["error"] = f"{type(exc).__name__}: {exc}"[:300]
        row["traceback"] = traceback.format_exc()[-1200:]
    row["seconds"] = round(time.time() - started, 1)
    if on_event:
        try:
            on_event({"kind": "target", **{k: row[k] for k in
                                           ("repo", "ok", "error", "seconds")}})
        except Exception:  # noqa: BLE001
            pass
    return row


def run_sweep(targets: list[SweepTarget], *, use_agent: bool = False,
              workdir: Optional[Path] = None,
              on_event: Optional[Callable[[dict], None]] = None) -> dict:
    """Walk every target. One record, whatever happened to the individuals."""
    started = time.time()
    rows = [run_one(t, workdir=workdir, use_agent=use_agent, on_event=on_event)
            for t in targets]

    totals = {"repos": len(rows), "ok": 0, "failed": 0, "findings": 0,
              "confirmed": 0, "candidates": 0, "resolvable": 0, "killed": 0}
    for r in rows:
        if r["ok"]:
            totals["ok"] += 1
        else:
            totals["failed"] += 1
        s = r.get("summary") or {}
        totals["findings"] += int(s.get("findings") or 0)
        totals["confirmed"] += int(s.get("confirmed") or 0)
        totals["candidates"] += int(s.get("candidates") or 0)
        fs = r.get("funnel_summary") or {}
        totals["resolvable"] += int(fs.get("resolvable") or 0)
        totals["killed"] += int(fs.get("killed") or 0)

    finished = time.time()
    sweep_id = hashlib.sha256(
        f"{started}|{[t.repo for t in targets]}".encode("utf-8")).hexdigest()[:24]
    return {
        "schema": SCHEMA,
        "sweep_id": sweep_id,
        "started_at": started,
        "finished_at": finished,
        "seconds": round(finished - started, 1),
        "targets": [asdict(t) for t in targets],
        "results": rows,
        "totals": totals,
        "used_agent": use_agent,
    }


def summarize_text(sweep: dict) -> str:
    """A one-screen digest, for a log nobody was watching when it was written."""
    t = sweep["totals"]
    lines = [
        f"SWEEP {sweep['sweep_id']}  {t['repos']} repo(s) in {sweep['seconds']}s",
        f"  {t['ok']} completed, {t['failed']} failed "
        f"(a failed target is recorded, never fatal)",
        f"  {t['findings']} finding(s): {t['confirmed']} CONFIRMED, "
        f"{t['candidates']} CANDIDATE",
        f"  funnel: {t['resolvable']} resolvable, {t['killed']} killed",
    ]
    for r in sweep["results"]:
        if r["ok"]:
            s = r["summary"]
            lines.append(f"    ok    {r['repo']}  "
                         f"{s.get('findings', 0)} finding(s), "
                         f"{s.get('coverage_pct', 0)}% coverage, {r['seconds']}s")
        else:
            lines.append(f"    FAIL  {r['repo']}  {r['error']}")
    return "\n".join(lines)


def verify(sweep: dict) -> int:
    """Every funnel summary a sweep reports must come from verified traces.

    The sweep stores summaries rather than whole traces (a twenty-repo sweep of
    full traces is a large document), so this checks the shape it DOES keep:
    `resolvable + killed` must equal the trace count the same summary reports.
    A sweep whose own arithmetic disagrees is not a sweep worth reading.
    """
    checked = 0
    for r in sweep.get("results") or []:
        fs = r.get("funnel_summary") or {}
        if not fs:
            continue
        if fs.get("resolvable", 0) + fs.get("killed", 0) != fs.get("traces", 0):
            raise FUNNEL.TraceDivergence(
                f"{r['repo']}: funnel summary does not add up: {fs}")
        checked += 1
    return checked
