"""Running the reporting agent — the one place the model is actually called.

Both front ends (CLI and web app) go through `generate_report` / `generate_all`,
so there is a single implementation of what "generate a report" means, exactly
as `src/scan.py` is the single implementation of what a scan means.

RATE LIMITING IS PART OF THE PRODUCT, NOT THE TEST HARNESS. The Gemini free
tier allows 15 generate_content requests per minute per model, and one finding
costs roughly five to eight of them (get_finding, get_diff, draft_report,
verify_report, save_report, plus the model's own turns). A demo that fires two
findings back to back therefore hits 429 in the middle of the second one. This
module paces at the granularity that actually matters — the individual MODEL
REQUEST, via ADK's `before_model_callback` — rather than sleeping between
findings and hoping. When a 429 arrives anyway, the server's own `retryDelay`
is honoured rather than a guessed backoff.

Upgrading to a paid tier is a CONFIG CHANGE, not an architecture change: raise
`RateLimiter(max_requests=...)` (or pass `--rpm`) and nothing else moves.

THE AGENT NEVER DECIDES ANYTHING. It is handed a finished finding record and
may only call the six reader tools. Verdicts, evidence fields and the report's
framing are all produced by code before the model sees them.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from collections import deque
from pathlib import Path
from typing import Callable, Optional

from .store import FindingStore
from . import tools as T

# Chosen from the model list this project's key can actually reach; see
# AGENT-DESIGN.md §1. `gemini-2.5-flash` returns 404 for new keys.
DEFAULT_MODEL = "gemini-3.5-flash-lite"

# Free tier is 15 requests/minute/model. Sit under it: a burst that lands
# exactly on the boundary still 429s, and a visibly stalled demo is worse than
# a slightly slower one.
DEFAULT_RPM = 12

INSTRUCTION = """You write evidence dossiers for Chainwatch, a git-history
regression detector for Solidity contracts.

For the finding id you are given, in this order:
  1. get_finding(finding_id)  - the complete evidence record.
  2. get_diff(finding_id)     - the actual change. Read it before writing.
  3. draft_report(finding_id) - the fixed header, the facts already rendered by
     code, and the empty prose slots you must fill.
  4. Write prose for every slot. Do NOT restate commit hashes, addresses, line
     numbers or file paths - they are rendered for you and will be re-rendered
     from the record.
  5. verify_report(finding_id, slots_json) with your slot map. Fix anything it
     reports and verify again.
  6. save_report(finding_id, slots_json) with the same slot map.
  7. explain_impact(finding_id) - a SECOND slot set over the SAME record, for a
     plain-language impact narration. Fill its slots, then
     verify_impact(finding_id, slots_json) and fix anything it reports.
     This step EXPLAINS the finding the engine already produced. It cannot
     create a finding, promote a CANDIDATE, or change any verdict field; if the
     evidence looks thin to you, say so in the slots - the verdict is not
     yours to move.

Report only what the tools told you. Never assert that a CANDIDATE finding is
confirmed, exploitable, or a vulnerability - explain instead which evidence is
missing and what would settle it. Never produce exploit code or a
proof-of-concept."""


class RateLimiter:
    """Sliding-window limiter over model requests. Async-safe."""

    def __init__(self, max_requests: int = DEFAULT_RPM, window: float = 60.0):
        self.max_requests = max(1, int(max_requests))
        self.window = window
        self._hits: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self, on_wait: Optional[Callable[[float], None]] = None) -> float:
        async with self._lock:
            waited = 0.0
            while True:
                now = time.monotonic()
                while self._hits and now - self._hits[0] >= self.window:
                    self._hits.popleft()
                if len(self._hits) < self.max_requests:
                    self._hits.append(now)
                    return waited
                sleep_for = self.window - (now - self._hits[0]) + 0.05
                if on_wait:
                    on_wait(sleep_for)
                waited += sleep_for
                await asyncio.sleep(sleep_for)


_RETRY_DELAY = re.compile(r"'retryDelay':\s*'(\d+(?:\.\d+)?)s'")


def _retry_delay_from(exc: BaseException, default: float = 12.0) -> float:
    """The delay the SERVER asked for, not one we invented."""
    m = _RETRY_DELAY.search(str(exc))
    if m:
        try:
            return min(90.0, float(m.group(1)) + 1.0)
        except ValueError:
            pass
    return default


def _is_rate_limited(exc: BaseException) -> bool:
    s = str(exc)
    return "RESOURCE_EXHAUSTED" in s or "429" in s


def _is_overloaded(exc: BaseException) -> bool:
    s = str(exc)
    return "UNAVAILABLE" in s or "503" in s


def api_key_present() -> bool:
    """True iff a Gemini key is configured. The engine never needs one; only
    this layer does, and the front ends must be able to say so plainly."""
    _load_env()
    return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))


def _load_env() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    except Exception:  # noqa: BLE001
        pass
    if not os.environ.get("GOOGLE_API_KEY") and os.environ.get("GEMINI_API_KEY"):
        # ADK reads GOOGLE_API_KEY; accept either name from .env.
        os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]


async def generate_report(
    store: FindingStore,
    finding_id: str,
    out_dir: Path,
    model: str = DEFAULT_MODEL,
    limiter: Optional[RateLimiter] = None,
    on_event: Optional[Callable[[dict], None]] = None,
    max_attempts: int = 3,
) -> dict:
    """Draft, verify and save the dossier for ONE finding.

    Returns {status, finding_id, path, markdown, tool_calls, verified, waited}.
    Never raises for an API condition: a rate limit, an overloaded model or a
    missing key come back as a status the caller can render.
    """
    _load_env()
    if not api_key_present():
        return {"status": "error", "finding_id": finding_id,
                "error_message": "no GEMINI_API_KEY configured; the deterministic "
                                 "engine does not need one, this report layer does"}

    facts = store.facts(finding_id)
    if not facts.get("verdict"):
        return {"status": "error", "finding_id": finding_id,
                "error_message": f"no finding with id {finding_id}"}

    limiter = limiter or RateLimiter()
    waited_total = 0.0

    def emit(kind: str, **kw):
        if on_event:
            try:
                on_event({"kind": kind, "finding_id": finding_id, **kw})
            except Exception:  # noqa: BLE001
                pass

    from google.adk.agents import LlmAgent
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    # ADK invokes this by KEYWORD (callback_context=, llm_request=), so the
    # signature must accept keywords rather than positional args. Returning
    # None is what lets the model call proceed; returning a response here would
    # short-circuit it.
    async def pace(callback_context=None, llm_request=None, **_kw):
        nonlocal waited_total
        w = await limiter.acquire(
            on_wait=lambda s: emit("throttle", seconds=round(s, 1)))
        waited_total += w
        return None

    T.bind(store, out_dir=out_dir)
    agent = LlmAgent(name="chainwatch_reporter", model=model, tools=T.ALL_TOOLS,
                     instruction=INSTRUCTION, before_model_callback=pace)
    runner = InMemoryRunner(agent=agent, app_name="chainwatch")

    calls: list[str] = []
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        calls = []
        try:
            session = await runner.session_service.create_session(
                app_name="chainwatch", user_id="cw")
            msg = types.Content(role="user", parts=[types.Part(
                text=f"Write the dossier for finding {finding_id}.")])
            async for ev in runner.run_async(user_id="cw", session_id=session.id,
                                             new_message=msg):
                if getattr(ev, "content", None) and ev.content.parts:
                    for p in ev.content.parts:
                        fc = getattr(p, "function_call", None)
                        if fc is not None:
                            calls.append(fc.name)
                            emit("tool", tool=fc.name)
                err = getattr(ev, "error_code", None)
                if err:
                    raise RuntimeError(f"{err}: {getattr(ev, 'error_message', '')}")
            break
        except Exception as exc:  # noqa: BLE001
            last_error = f"{type(exc).__name__}: {exc}"[:400]
            if attempt < max_attempts and (_is_rate_limited(exc) or _is_overloaded(exc)):
                delay = _retry_delay_from(exc)
                emit("retry", attempt=attempt, seconds=round(delay, 1),
                     reason="rate-limited" if _is_rate_limited(exc) else "overloaded")
                waited_total += delay
                await asyncio.sleep(delay)
                continue
            emit("error", message=last_error)
            return {"status": "error", "finding_id": finding_id,
                    "error_message": last_error, "tool_calls": calls,
                    "waited": round(waited_total, 1)}

    # The saved artifact is the source of truth: save_report re-assembles from
    # the finding record and refuses to write anything the gate rejects, so a
    # file on disk IS a verified file.
    path = _saved_path(out_dir, facts, finding_id)
    if not path or not path.is_file():
        emit("error", message="the agent did not save a report")
        return {"status": "error", "finding_id": finding_id,
                "error_message": "the agent completed without saving a report "
                                 f"(tools called: {', '.join(calls) or 'none'})",
                "tool_calls": calls, "waited": round(waited_total, 1)}

    markdown = path.read_text(encoding="utf-8")
    # Re-verify independently of the tool that wrote it. Cheap, and it means a
    # future change to save_report cannot quietly stop enforcing the gate.
    from .verify import verify as _verify

    check = _verify(markdown, facts)
    emit("done", path=str(path), verified=check["ok"],
         violations=check["violation_count"])
    return {"status": "success" if check["ok"] else "error",
            "finding_id": finding_id, "path": str(path), "markdown": markdown,
            "tool_calls": calls, "verified": check["ok"],
            "violations": check["violations"], "waited": round(waited_total, 1),
            "error_message": "" if check["ok"] else "saved report failed re-verification"}


def _saved_path(out_dir: Path, facts: dict, finding_id: str) -> Optional[Path]:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{facts.get('contract')}_{finding_id}")
    p = Path(out_dir) / f"{safe}.md"
    return p if p.is_file() else None


async def generate_all(store: FindingStore, out_dir: Path,
                       finding_ids: Optional[list[str]] = None,
                       model: str = DEFAULT_MODEL, rpm: int = DEFAULT_RPM,
                       on_event: Optional[Callable[[dict], None]] = None) -> list[dict]:
    """Every finding, through one shared limiter so the budget is global."""
    limiter = RateLimiter(max_requests=rpm)
    out = []
    for fid in (finding_ids or store.ids()):
        out.append(await generate_report(store, fid, out_dir, model=model,
                                         limiter=limiter, on_event=on_event))
    return out


def generate_report_sync(store: FindingStore, finding_id: str, out_dir: Path,
                         **kw) -> dict:
    return asyncio.run(generate_report(store, finding_id, out_dir, **kw))


def generate_all_sync(store: FindingStore, out_dir: Path, **kw) -> list[dict]:
    return asyncio.run(generate_all(store, out_dir, **kw))
