"""Capability 20 - the ADK multi-agent layer, and the boundary it cannot cross.

Four roles run over a scan that the deterministic engine has ALREADY finished:

    Hunter      (LLM)  proposes which engine candidates deserve deeper evidence
                       work, and states each one's security invariant in a
                       sentence.
    Skeptic     (LLM)  proposes disproof challenges against each candidate.
    Reproducer  (LLM)  drafts a reproduction plan from FOUR fields and nothing
                       else - contract, function, invariant statement,
                       objective.
    Gatekeeper  (CODE) runs the gate function and decides. Not a model. Never
                       a model.

WHY THIS IS SAFE, STRUCTURALLY AND NOT BY POLICY
------------------------------------------------
The engine runs FIRST and its verdicts are captured before a single token is
generated. At the end, `run()` recomputes the verdicts and compares them to
that snapshot; a difference raises `VerdictDrift` and the run fails. So the
question "can the agent layer change a verdict?" is not answered by reading the
prompts - it is answered by a comparison that happens on every run, in
production, not only in a test.

Three narrower constraints follow the same pattern:

  * A Hunter proposal naming a finding the engine never produced is DROPPED,
    and the drop is recorded in the turn log. The model cannot introduce a
    candidate, which is the sharp edge of "the LLM cannot create a finding".
  * A Skeptic challenge is only ever an INPUT. Each one is matched against the
    deterministic checks the engine can actually run; a challenge that names no
    such check is recorded UNRESOLVED and fails nothing. `apply_skeptic` still
    reads gate values, exactly as before, and the Skeptic still cannot pass a
    gate - only fail one.
  * The Reproducer receives a `ReproducerBrief`: a frozen dataclass with
    exactly four fields. Blinding is a property of the TYPE, so there is no
    code path that could pass the hunter's write-up along even by mistake.

Every turn - input, output, and what the gate function said afterwards - is
logged, returned in the result, and persisted to Firestore (`agent_runs`) when
a project is configured. The log is also the funnel's trace data.

WHAT THIS MODULE DOES NOT DO
----------------------------
It does not re-analyse. It never imports a rule, never compiles anything, never
touches a chain. It reads a finished report, exactly as `agent/runner.py` does,
for exactly the same reason.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from .runner import DEFAULT_MODEL, DEFAULT_RPM, RateLimiter, _load_env

HUNTER = "hunter"
SKEPTIC = "skeptic"
REPRODUCER = "reproducer"
GATEKEEPER = "gatekeeper"

ROLES = (HUNTER, SKEPTIC, REPRODUCER, GATEKEEPER)


class VerdictDrift(RuntimeError):
    """The verdicts after the agent layer ran are not the verdicts the engine
    produced before it. Always a bug in the boundary; never a data condition,
    and never something to reconcile - the engine is right by construction."""


# --------------------------------------------------------------------------- #
# The blinded brief. Four fields. This type IS the blinding.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ReproducerBrief:
    """Everything the Reproducer agent is allowed to know.

    Deliberately a frozen dataclass rather than a dict: a dict would let a
    later caller add "just one more field" - the detail text, the diff, the
    hunter's reasoning - and nothing would complain. Adding a field here is a
    visible edit to a type whose docstring says what it is for, and
    `tests/test_agent_orchestrator.py` asserts the field set.
    """

    contract: str
    function: str
    invariant_statement: str
    objective: str

    def as_prompt(self) -> str:
        return (f"contract: {self.contract}\n"
                f"function: {self.function}\n"
                f"invariant: {self.invariant_statement}\n"
                f"objective: {self.objective}")


def brief_for(finding: dict) -> ReproducerBrief:
    """Build the brief from a finding record, naming every field taken.

    The invariant statement is composed from the rule's own pre/post evidence -
    machine text, not the hunter's prose. `detail` is NOT read here and must
    not be: it is the write-up.
    """
    ev = finding.get("evidence") or {}
    pre, post = ev.get("pre_state") or "", ev.get("post_state") or ""
    statement = (f"the property recorded as {pre} must still hold; at this "
                 f"commit the code records {post}") if (pre and post) else (
        f"rule {finding.get('rule_id', '?')}'s security property must hold for "
        f"{finding.get('contract', '?')}.{finding.get('function') or '?'}")
    return ReproducerBrief(
        contract=str(finding.get("contract") or ""),
        function=str(finding.get("function") or ""),
        invariant_statement=statement,
        objective="call_succeeds_without_authorization",
    )


# --------------------------------------------------------------------------- #
# Turn log.
# --------------------------------------------------------------------------- #

@dataclass
class AgentTurn:
    agent: str
    finding_id: str
    input: dict = field(default_factory=dict)
    output: dict = field(default_factory=dict)
    gate_outcome: str = ""
    note: str = ""
    at: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Model access. One place, so "did a model run at all" is one boolean.
# --------------------------------------------------------------------------- #

def model_available() -> bool:
    # Through `runner._load_env`, so both entry points read the key the same
    # way (including the GEMINI_API_KEY -> GOOGLE_API_KEY alias ADK needs).
    _load_env()
    return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))


_JSON_BLOCK = re.compile(r"\{.*\}|\[.*\]", re.S)


def _parse_json(text: str) -> Any:
    """Parse a model's JSON answer, tolerating fences and surrounding prose.

    Returns None when nothing parses. A model that answers unparseably is
    treated as a model that ABSTAINED - never as a reason to fall back to some
    other opinion about the candidate.
    """
    if not text:
        return None
    m = _JSON_BLOCK.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:  # noqa: BLE001
        return None


async def _ask(instruction: str, prompt: str, *, model: str,
               limiter: RateLimiter, name: str) -> str:
    """One ADK LlmAgent turn. Returns the model's text, or "" on any failure.

    Failure is not fatal anywhere in this module: the agent layer is additive,
    and a scan whose narration failed is still a complete scan.
    """
    from google.adk.agents import LlmAgent
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    async def pace(callback_context=None, llm_request=None, **_kw):
        await limiter.acquire()
        return None

    agent = LlmAgent(name=name, model=model, instruction=instruction,
                     before_model_callback=pace)
    runner = InMemoryRunner(agent=agent, app_name="chainwatch-agent")
    session = await runner.session_service.create_session(
        app_name="chainwatch-agent", user_id="cw")
    msg = types.Content(role="user", parts=[types.Part(text=prompt)])
    out: list[str] = []
    async for ev in runner.run_async(user_id="cw", session_id=session.id,
                                     new_message=msg):
        if getattr(ev, "content", None) and ev.content.parts:
            for p in ev.content.parts:
                if getattr(p, "text", None):
                    out.append(p.text)
    return "".join(out)


HUNTER_INSTRUCTION = """You triage findings a deterministic Solidity regression
engine has ALREADY produced. You do not find bugs and you cannot create one:
every id you name must be an id you were given.

Answer with JSON only:
[{"finding_id": "...", "invariant": "one sentence naming the security property
that regressed", "worth_deeper_evidence": true|false, "why": "one sentence"}]

Include every finding you were given, exactly once. Never claim a CANDIDATE is
confirmed or exploitable - the verdict was decided before you saw it and is not
yours to move. Never write exploit code."""

SKEPTIC_INSTRUCTION = """You try to DISPROVE a finding a deterministic Solidity
regression engine produced. Your challenges are INPUTS to a mechanical checker,
not conclusions: naming a challenge does not fail anything.

Answer with JSON only:
[{"check": "one of compensating_control, deployment_relevance,
bytecode_provenance, build_environment, path_reachability, live_regression,
state_possible, not_duplicate, economic_feasibility, or other",
"claim": "the specific reason this candidate might NOT be a real, live
regression"}]

Prefer checks from that list - a challenge outside it cannot be mechanically
resolved and will be recorded as unresolved. Be concrete and adversarial. Never
write exploit code."""

REPRODUCER_INSTRUCTION = """You draft a plan to reproduce a violation of ONE
stated invariant, using ONLY the four fields you are given. You have not seen -
and must not guess at - any analyst's write-up, diff, commit, or verdict.

Answer with JSON only:
{"setup": ["..."], "action": "the single call that should violate the
invariant", "assertion": "what would prove the violation", "unknowns":
["what you would need that you were not given"]}

If four fields are not enough to plan a reproduction, say so in "unknowns"
rather than inventing context. Never write exploit code - describe a test."""


# --------------------------------------------------------------------------- #
# The Gatekeeper. Deterministic. The only thing here that decides anything.
# --------------------------------------------------------------------------- #

def gatekeeper(report: dict) -> dict:
    """Read the verdicts the engine recorded, and the funnel derived from them.

    Not a re-computation from raw evidence and deliberately so: `verdict.classify`
    already ran inside the scan. This reads what it decided and derives the
    funnel view, which itself re-verifies every verdict against its own gate
    states. Nothing in this function can produce a verdict the engine did not.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src import funnel as FUNNEL

    # Ids come from the FUNNEL, not from `store.finding_id`, on purpose. Both
    # are stable, but a reader comparing the CLI's resolution queue against
    # this run's turn log must see the SAME handle for the same finding -
    # `1-FeeManager-setFee-dac6083a` in one place and `91dda8837dc2` in the
    # other is two ids for one thing, which is a bug in the product even
    # though neither is wrong. The store's hash stays internal to the
    # reporting agent, which is the only thing that indexes by it.
    findings = report.get("findings") or []
    traces = [FUNNEL.from_classic_finding(f, repo=str(report.get("repo") or ""),
                                          commit_pair=(f.get("parent") or "",
                                                       f.get("commit") or ""))
              for f in findings]
    FUNNEL.verify_all(traces)
    verdicts = {t["finding_id"]: f.get("verdict")
                for f, t in zip(findings, traces)}
    return {
        "verdicts": verdicts,
        "traces": traces,
        "summary": FUNNEL.summarize(traces),
        "resolution_queue": [t["finding_id"]
                             for t in FUNNEL.resolution_queue(traces)],
    }


# --------------------------------------------------------------------------- #
# The orchestration.
# --------------------------------------------------------------------------- #

def run(report: dict, *, model: str = DEFAULT_MODEL, use_llm: bool = True,
        rpm: Optional[int] = None, limit: int = 10,
        on_event: Optional[Callable[[dict], None]] = None) -> dict:
    """Run the four roles over a finished scan report.

    `use_llm=False` runs the same orchestration with every model turn ABSTAINED.
    That is not a test stub bolted on the side: it is the path taken whenever no
    API key is configured, and it must produce byte-identical verdicts to the
    LLM path. If it did not, the model would be deciding something.
    """
    return asyncio.run(run_async(report, model=model, use_llm=use_llm,
                                 rpm=rpm, limit=limit, on_event=on_event))


async def run_async(report: dict, *, model: str = DEFAULT_MODEL,
                    use_llm: bool = True, rpm: Optional[int] = None,
                    limit: int = 10,
                    on_event: Optional[Callable[[dict], None]] = None) -> dict:
    from src import funnel as FUNNEL

    def _fid(f: dict) -> str:
        """The same handle the funnel and the CLI queue use - see `gatekeeper`."""
        return FUNNEL.from_classic_finding(f)["finding_id"]

    def emit(kind: str, **kw):
        if on_event:
            try:
                on_event({"kind": kind, **kw})
            except Exception:  # noqa: BLE001
                pass

    findings = list(report.get("findings") or [])[:limit]
    limiter = RateLimiter(max_requests=rpm or DEFAULT_RPM)
    live = bool(use_llm and model_available() and findings)
    turns: list[AgentTurn] = []

    # ------------------------------------------------------------------ #
    # 0. The engine's answer, captured BEFORE any token is generated. This
    #    snapshot is what the drift check at the end compares against.
    # ------------------------------------------------------------------ #
    before = gatekeeper(report)
    emit("gatekeeper", phase="before", verdicts=before["verdicts"])

    # A list, not a set, so the payload the model sees is in a stable order
    # run to run - an unattended sweep that reshuffles its prompt every night
    # is needlessly hard to diff.
    by_id = {_fid(f): f for f in findings}
    ordered_ids = sorted(by_id)
    engine_ids = set(ordered_ids)

    # ------------------------------------------------------------------ #
    # 1. Hunter. Proposals are FILTERED against the engine's own id set.
    # ------------------------------------------------------------------ #
    proposals: dict[str, dict] = {}
    dropped: list[str] = []
    hunter_payload = [{
        "finding_id": fid,
        "rule_id": by_id[fid].get("rule_id"),
        "contract": by_id[fid].get("contract"),
        "function": by_id[fid].get("function"),
        "verdict": by_id[fid].get("verdict"),
        "detail": (by_id[fid].get("detail") or "")[:400],
        "missing_evidence": [k for k, v in (by_id[fid].get("evidence") or {}).items()
                             if v in (None, "", [], {})],
    } for fid in ordered_ids]

    raw = ""
    if live and hunter_payload:
        emit("agent", agent=HUNTER, n=len(hunter_payload))
        raw = await _safe_ask(HUNTER_INSTRUCTION, json.dumps(hunter_payload),
                              model=model, limiter=limiter, name="cw_hunter")
    parsed = _parse_json(raw) or []
    if isinstance(parsed, dict):
        parsed = [parsed]
    for item in parsed:
        if not isinstance(item, dict):
            continue
        fid = str(item.get("finding_id") or "")
        if fid not in engine_ids:
            # The sharp edge: a model naming a candidate the engine never
            # produced does not get one. It gets recorded as a drop.
            dropped.append(fid)
            continue
        proposals[fid] = item
    turns.append(AgentTurn(
        agent=HUNTER, finding_id="*",
        input={"findings": len(hunter_payload), "llm": live},
        output={"proposals": len(proposals), "dropped": dropped},
        gate_outcome="no gate - the Hunter proposes only",
        note=("model abstained or was not configured" if not proposals
              else f"{len(dropped)} proposal(s) dropped: not engine findings")))
    emit("agent_done", agent=HUNTER, proposals=len(proposals),
         dropped=len(dropped))

    # ------------------------------------------------------------------ #
    # 2. Skeptic. Challenges are INPUTS, matched to checks the engine can run.
    # ------------------------------------------------------------------ #
    from src.nextgen.adversarial import skeptic as SK

    # The engine's OWN check->gate map, read rather than restated: if a check
    # is added or removed there, the set of challenges this layer can resolve
    # moves with it instead of silently drifting.
    known_checks = set(SK._GATE_FOR)

    for fid in ordered_ids:
        f = by_id[fid]
        payload = {
            "rule_id": f.get("rule_id"), "contract": f.get("contract"),
            "function": f.get("function"), "verdict": f.get("verdict"),
            "detail": (f.get("detail") or "")[:400],
            "liveness": f.get("liveness"),
            "survives_to_head": f.get("survives_to_head"),
        }
        raw = ""
        if live:
            raw = await _safe_ask(SKEPTIC_INSTRUCTION, json.dumps(payload),
                                  model=model, limiter=limiter,
                                  name="cw_skeptic")
        items = _parse_json(raw) or []
        if isinstance(items, dict):
            items = [items]
        challenges = []
        for item in items:
            if not isinstance(item, dict):
                continue
            check = str(item.get("check") or "other")
            challenges.append({
                "check": check,
                "claim": str(item.get("claim") or "")[:400],
                # A challenge naming no mechanical check cannot fail anything.
                # Saying so in the record is the whole point.
                "resolvable": check in known_checks,
                "outcome": "PENDING" if check in known_checks else "UNRESOLVED",
            })
        turns.append(AgentTurn(
            agent=SKEPTIC, finding_id=fid,
            input={"fields": sorted(payload), "llm": live},
            output={"challenges": challenges},
            gate_outcome="input only - a challenge cannot fail a gate; "
                         "gates.apply_skeptic reads gate values, not this text",
            note=f"{sum(1 for c in challenges if not c['resolvable'])} "
                 f"unresolvable challenge(s)"))
    emit("agent_done", agent=SKEPTIC, findings=len(engine_ids))

    # ------------------------------------------------------------------ #
    # 3. Reproducer. Four fields in, a plan out. Blinded by the type.
    # ------------------------------------------------------------------ #
    for fid in ordered_ids:
        b = brief_for(by_id[fid])
        raw = ""
        if live:
            raw = await _safe_ask(REPRODUCER_INSTRUCTION, b.as_prompt(),
                                  model=model, limiter=limiter,
                                  name="cw_reproducer")
        plan = _parse_json(raw) or {}
        turns.append(AgentTurn(
            agent=REPRODUCER, finding_id=fid,
            input=asdict(b),
            output={"plan": plan},
            gate_outcome="proposes a plan; the `reproducer` gate is set only "
                         "by an actual run (gates.apply_reproducer)",
            note="blinded: four fields, no write-up, no diff, no verdict"))
    emit("agent_done", agent=REPRODUCER, findings=len(engine_ids))

    # ------------------------------------------------------------------ #
    # 4. Gatekeeper, again - and the drift check that makes the boundary real.
    # ------------------------------------------------------------------ #
    after = gatekeeper(report)
    if after["verdicts"] != before["verdicts"]:
        raise VerdictDrift(
            f"verdicts changed while the agent layer ran: "
            f"{before['verdicts']} -> {after['verdicts']}")
    turns.append(AgentTurn(
        agent=GATEKEEPER, finding_id="*",
        input={"gate_model": "classic-6", "findings": len(engine_ids)},
        output={"verdicts": after["verdicts"], "summary": after["summary"]},
        gate_outcome="verdicts recomputed and byte-identical to the engine's",
        note="deterministic; no model in this path"))
    emit("gatekeeper", phase="after", verdicts=after["verdicts"],
         identical=True)

    return {
        "schema": "chainwatch.agentrun.v1",
        "model": model if live else "",
        "llm": live,
        "repo": report.get("repo"),
        "head": report.get("head"),
        "findings": len(engine_ids),
        "verdicts": after["verdicts"],
        "verdicts_unchanged": True,
        "hunter_proposals": proposals,
        "hunter_dropped": dropped,
        "funnel": {
            "schema": (report.get("funnel") or {}).get("schema", ""),
            "summary": after["summary"],
            "traces": after["traces"],
            "resolution_queue": after["resolution_queue"],
        },
        "turns": [t.as_dict() for t in turns],
        "finished_at": time.time(),
    }


async def _safe_ask(instruction: str, prompt: str, *, model: str,
                    limiter: RateLimiter, name: str) -> str:
    try:
        return await _ask(instruction, prompt, model=model, limiter=limiter,
                          name=name)
    except Exception:  # noqa: BLE001 - narration never fails a scan
        return ""
