"""Capability 19 - the funnel trace: where every candidate actually stopped.

A scan that reports "0 CONFIRMED" tells a reader nothing about WHY. Did every
candidate get disproved, or did they all die one gate short of a deployed
address nobody supplied? Those are opposite situations and the classic report
could not tell them apart. This module is that missing view.

WHAT THIS IS
------------
A derived, read-only projection of evidence that OTHER modules already
established. For each candidate it records:

    gate_states            every gate and its result, verbatim
    kill_gate              the first gate that FAILED, if any
    blocking_gates         the gates that are unresolved and block CONFIRMED
    distance_to_confirmed  how many unresolved gates stand in the way
    evidence_requests      per unresolved gate, the deterministic input that
                           would let that gate actually run

WHAT THIS IS NOT (the load-bearing constraint)
----------------------------------------------
It never decides anything. There is no promotion path here and no new verdict
logic: `verify()` RECOMPUTES the stored verdict from the stored gate states by
calling the engine's own gate function, and raises if the two disagree. The
funnel can therefore only ever agree with the engine or fail loudly - it cannot
quietly become a second opinion about what CONFIRMED means. That is the same
discipline `deepen.py` states for deepening steps ("a step may tell you what to
run; it may not run it and decide the answer") and `corpus.py` states for the
cache, applied to instrumentation.

`distance_to_confirmed` is a COUNT OF UNRESOLVED GATES, not a score and not a
probability. Distance 1 does not mean "probably real"; it means exactly one
mechanical check has not been run yet. Ranking by it orders work, not truth.

TWO GATE MODELS, ONE SCHEMA
---------------------------
The classic regression engine judges six evidence fields (`verdict.classify`);
the next-gen pipeline judges thirteen gates (`nextgen.state.classify`). They
are deliberately different and stay different. Rather than flatten them into a
lossy common model, a trace carries its `gate_model` and `verify()` dispatches
to whichever gate function owns that trace. A reader always knows which
rulebook produced a number.
"""

from __future__ import annotations

import platform
import sys
import time
from typing import Any, Iterable, Optional

from . import deepen as DEEPEN
from . import verdict as V
from .nextgen import state as S

SCHEMA = "chainwatch.funnel.v1"

CLASSIC_6 = "classic-6"
NEXTGEN_13 = "nextgen-13"

# Engines that can emit a trace. `engine` is recorded, never inferred later.
ENGINE_REGRESSION = "regression"
ENGINE_NEXTGEN = "nextgen"
ENGINE_TWIN = "twin"
ENGINE_DEEPHUNT = "deephunt"

PASS = S.PASS
FAIL = S.FAIL
PENDING = S.PENDING


# --------------------------------------------------------------------------- #
# The classic six-field model, restated as gates.
#
# These names are NOT new evidence. Each one is a direct reading of a field
# `verdict.classify` already looks at, in the order that function looks at
# them, so the two cannot drift: `_classic_classify` below reproduces
# `verdict.classify`'s answer from these gates alone, and a test asserts the
# equivalence over every shape a Finding can take.
# --------------------------------------------------------------------------- #

CLASSIC_GATES: tuple[str, ...] = (
    "regression_commit",
    "pre_state",
    "post_state",
    "reachability",
    "no_compensating_control",
    "liveness",
    "rule_ceiling",
    "liveness_live",
    "survives_to_head",
)

# `verdict.classify` records no downgrade reason when `survives_to_head` is
# None - an unestablished survival fact is carried by the `reachability`
# evidence field instead (`_reachability` returns None unless survival is
# True), so an unknown here is never the sole thing between a finding and
# CONFIRMED. Modelling it as blocking would make this module disagree with the
# engine on a shape the engine deliberately allows.
_CLASSIC_NONBLOCKING_WHEN_PENDING = frozenset({"survives_to_head"})


def _classic_gates(f: dict) -> dict[str, str]:
    """Read a classic finding dict into the gate vocabulary above."""
    ev = dict(f.get("evidence") or {})
    gates: dict[str, str] = {}
    for name in ("regression_commit", "pre_state", "post_state", "reachability",
                 "no_compensating_control", "liveness"):
        val = ev.get(name)
        gates[name] = PASS if val not in (None, "", [], {}) else PENDING

    gates["rule_ceiling"] = (
        FAIL if f.get("severity_hint") == V.CANDIDATE else PASS)

    live = f.get("liveness")
    if not live:
        gates["liveness_live"] = PENDING
    elif live == V.LIVE:
        gates["liveness_live"] = PASS
    else:
        gates["liveness_live"] = FAIL

    survives = f.get("survives_to_head")
    gates["survives_to_head"] = (
        PASS if survives is True else FAIL if survives is False else PENDING)
    return gates


def _classic_classify(gates: dict[str, str]) -> str:
    """`verdict.classify`'s answer, recomputed from gates alone.

    CONFIRMED iff every gate is PASS (with the one documented exception above).
    Anything else is CANDIDATE - the classic model has no third outcome for a
    finding that was emitted at all.
    """
    for name in CLASSIC_GATES:
        result = gates.get(name, PENDING)
        if result == PASS:
            continue
        if result == PENDING and name in _CLASSIC_NONBLOCKING_WHEN_PENDING:
            continue
        return V.CANDIDATE
    return V.CONFIRMED


# --------------------------------------------------------------------------- #
# Evidence requests - what deterministic input lets a stuck gate actually run.
#
# One entry per gate that can be unresolved, naming the INPUT and the mechanism
# that consumes it. Nothing here runs anything; it is a routing table, the same
# shape as `deepen._ADDRESS_HINT` and for the same reason.
# --------------------------------------------------------------------------- #

_NEXTGEN_REQUESTS: dict[str, dict[str, Any]] = {
    "regression_commit": {
        "needs": ["repo", "defining_path", "head"],
        "how": "walk the property timeline over this file's history "
               "(timemachine) so a REMOVED event can be attributed to a commit",
    },
    "build_environment": {
        "needs": ["dependency_manifest"],
        "how": "resolve the commit's dependencies (npm / Foundry / Soldeer) so "
               "both sides compile; an unresolved import set leaves the "
               "environment unproven",
    },
    "security_invariant": {
        "needs": ["before_slither", "after_slither"],
        "how": "compile both sides so the validated invariant sets can be "
               "diffed",
    },
    "reachable_path": {
        "needs": ["after_slither"],
        "how": "compile the after-side unit so the attack-path search can look "
               "for an unprivileged route to the sink",
    },
    "state_reachable": {
        "needs": ["address", "rpc_url"],
        "how": "execution evidence - a fork the reproducer can construct the "
               "required state on",
    },
    "no_compensating_control": {
        "needs": ["after_slither"],
        "how": "compile the after-side unit so the compensating-control sweep "
               "can run over its siblings",
    },
    "invariant_violated": {
        "needs": ["foundry", "rpc_url"],
        "how": "run the blinded reproducer; the violation must be OBSERVED, "
               "never argued",
    },
    "reproducer": {
        "needs": ["foundry", "source_bundle"],
        "how": "a Foundry toolchain and a self-contained flattened source so "
               "the blinded reproducer can build a test",
    },
    "bytecode_provenance": {
        "needs": ["address", "rpc_url", "build_settings"],
        "how": "compile the candidate commit and compare normalised runtime "
               "bytecode against what the address actually serves",
    },
    "target_live": {
        "needs": ["address", "rpc_url"],
        "how": "read the deployed implementation and check it is still the "
               "vulnerable one",
    },
    "independent_validation": {
        "needs": ["skeptic_inputs", "reproducer=PASS"],
        "how": "at least three Skeptic challenges with real inputs, AND a "
               "blinded reproduction that already agrees",
    },
    "not_duplicate": {
        "needs": ["corpus"],
        "how": "check the finding key against the findings corpus",
    },
    "economically_feasible": {
        "needs": ["economic_inputs"],
        "how": "supply value-at-risk and cost inputs; not applicable to "
               "non-value findings, where SKIPPED counts as PASS",
    },
}

_CLASSIC_REQUESTS: dict[str, dict[str, Any]] = {
    "regression_commit": {
        "needs": ["repo history"],
        "how": "the walker must attribute the change to a commit with a line "
               "range; a shallow or truncated history cannot",
    },
    "pre_state": {
        "needs": ["rule evidence keys"],
        "how": "the rule's emit() must record the before-side fact under the "
               "key registered in verdict.PRE_POST for this trigger",
    },
    "post_state": {
        "needs": ["rule evidence keys"],
        "how": "the rule's emit() must record the after-side fact under the "
               "key registered in verdict.PRE_POST for this trigger",
    },
    "reachability": {
        "needs": ["survives_to_head", "visibility_after", "writes_state_after"],
        "how": "the regression must still be present at HEAD and the affected "
               "function externally reachable and state-changing",
    },
    "no_compensating_control": {
        "needs": ["rule exclusion set"],
        "how": "reaching a fire means the rule's exclusion set was evaluated; "
               "an unregistered rule id yields no proof",
    },
    "liveness": {
        "needs": ["address", "rpc_url"],
        "how": "re-run with --address <deployed address>; liveness is UNKNOWN "
               "until deployed bytecode is compared",
    },
    "liveness_live": {
        "needs": ["address", "rpc_url"],
        "how": "CONFIRMED requires liveness == LIVE; PATCHED is a settled "
               "answer, not a missing one",
    },
    "survives_to_head": {
        "needs": ["head checkout"],
        "how": "the HEAD survival check must run (it is skipped by "
               "--no-head-check)",
    },
    "rule_ceiling": {
        "needs": [],
        "how": "this rule caps its trigger class at CANDIDATE by design; no "
               "evidence raises it",
    },
}


# --------------------------------------------------------------------------- #
# Severity ranking - deterministic, from the finding type. NEVER a model score.
# Lower rank sorts first.
# --------------------------------------------------------------------------- #

_SEVERITY_RANK: dict[str, int] = {
    "Access Control Security Regression": 0,
    "Control Migrated to an Unguarded Entry Point": 0,
    "Upgrade Authorization Security Regression": 1,
    "Initializer Security Regression": 1,
    "Security Regression": 2,
}
_DEFAULT_SEVERITY_RANK = 2


def severity_rank(finding_type: str) -> int:
    return _SEVERITY_RANK.get(finding_type or "", _DEFAULT_SEVERITY_RANK)


_TOOLCHAIN: Optional[dict[str, str]] = None


def toolchain_versions() -> dict[str, str]:
    """Pinned into every trace so a replay knows what produced it.

    Computed once: a scan with fifty findings builds fifty traces, and the
    toolchain does not change between them.
    """
    global _TOOLCHAIN
    if _TOOLCHAIN is None:
        out = {"python": sys.version.split()[0], "platform": platform.platform()}
        try:
            from slither import __version__ as slither_version  # type: ignore
            out["slither"] = str(slither_version)
        except Exception:  # noqa: BLE001 - slither is optional at this layer
            pass
        _TOOLCHAIN = out
    # A copy per trace: a trace is serialised and must not share mutable state
    # with every other trace in the report.
    return dict(_TOOLCHAIN)


# --------------------------------------------------------------------------- #
# Trace construction.
# --------------------------------------------------------------------------- #

def _requests_for(model: str, gates: dict[str, str],
                  blocking: Iterable[str]) -> list[dict]:
    table = _NEXTGEN_REQUESTS if model == NEXTGEN_13 else _CLASSIC_REQUESTS
    out = []
    for name in blocking:
        entry = table.get(name)
        out.append({
            "gate": name,
            "status": gates.get(name, PENDING),
            "needs": list(entry["needs"]) if entry else [],
            "how": entry["how"] if entry else
                   "no registered evidence request for this gate",
        })
    return out


def _base(*, finding_id: str, engine: str, gate_model: str,
          gate_states: dict[str, str], verdict: str, state: str,
          kill_gate: Optional[str], blocking: list[str],
          repo: str, commit_pair: Optional[tuple], rule_class: str,
          finding_type: str) -> dict:
    requests = _requests_for(gate_model, gate_states, blocking)
    # Several gates can be waiting on ONE input - `liveness` and
    # `liveness_live` are both unblocked by a single deployed address. Distance
    # counts GATES (it has to: it is a projection of the gate function), so the
    # distinct inputs are reported alongside it. A queue entry reading
    # "distance 2, needs: address, rpc_url" is one phone call, not two.
    required: list[str] = []
    for r in requests:
        for need in r["needs"]:
            if need not in required:
                required.append(need)
    return {
        "schema": SCHEMA,
        "finding_id": finding_id,
        "engine": engine,
        "gate_model": gate_model,
        "verdict": verdict,
        "state": state,
        "gate_states": dict(gate_states),
        "kill_gate": kill_gate,
        "blocking_gates": list(blocking),
        # A killed candidate has no distance: no amount of extra evidence moves
        # it, so `None` is the honest value and it sorts last in the queue.
        "distance_to_confirmed": None if kill_gate else len(blocking),
        "evidence_requests": requests,
        "required_inputs": required,
        "repo": repo,
        "commit_pair": list(commit_pair) if commit_pair else [],
        "rule_class": rule_class,
        "finding_type": finding_type,
        "severity_rank": severity_rank(finding_type),
        "toolchain_versions": toolchain_versions(),
        "recorded_at": time.time(),
    }


def from_finding_state(fs: S.FindingState, *, engine: str = ENGINE_NEXTGEN,
                       repo: str = "", commit_pair: Optional[tuple] = None,
                       rule_class: str = "", finding_type: str = "") -> dict:
    """Trace one next-gen candidate from its live `FindingState`."""
    gates = dict(fs.gates)
    fine, verdict, _ = S.classify(gates)

    kill_gate = None
    blocking: list[str] = []
    for spec in S.GATES:
        eff = S._gate_effective(spec, gates.get(spec.name, PENDING))
        if eff == FAIL:
            if kill_gate is None:
                kill_gate = spec.name
        elif eff != PASS and spec.blocks_confirm:
            blocking.append(spec.name)

    return _base(finding_id=fs.finding_id, engine=engine,
                 gate_model=NEXTGEN_13, gate_states=gates, verdict=verdict,
                 state=fine, kill_gate=kill_gate, blocking=blocking,
                 repo=repo, commit_pair=commit_pair, rule_class=rule_class,
                 finding_type=finding_type)


def from_classic_finding(f: dict, *, repo: str = "",
                         commit_pair: Optional[tuple] = None,
                         finding_id: str = "") -> dict:
    """Trace one classic regression finding from its report dict."""
    gates = _classic_gates(f)
    verdict = f.get("verdict") or _classic_classify(gates)

    kill_gate = None
    blocking: list[str] = []
    for name in CLASSIC_GATES:
        result = gates.get(name, PENDING)
        if result == FAIL:
            if kill_gate is None:
                kill_gate = name
        elif result != PASS:
            if result == PENDING and name in _CLASSIC_NONBLOCKING_WHEN_PENDING:
                continue
            blocking.append(name)

    rule_id = str(f.get("rule_id", ""))
    fid = finding_id or "-".join(
        x for x in (rule_id, f.get("contract") or "", f.get("function") or "",
                    (f.get("commit") or "")[:8]) if x)
    trace = _base(finding_id=fid, engine=ENGINE_REGRESSION,
                  gate_model=CLASSIC_6, gate_states=gates, verdict=verdict,
                  state=verdict, kill_gate=kill_gate, blocking=blocking,
                  repo=repo, commit_pair=commit_pair,
                  rule_class=f"rule {rule_id}" if rule_id else "",
                  finding_type=f.get("owasp") or "Security Regression")
    # `deepen` already routes a classic gap to the concrete thing that closes
    # it. Carry its answer verbatim rather than writing a second one.
    trace["deepen_steps"] = DEEPEN.next_steps(f)
    return trace


# --------------------------------------------------------------------------- #
# Verification - the only thing here that can fail.
# --------------------------------------------------------------------------- #

class TraceDivergence(RuntimeError):
    """A stored verdict does not match what the gate function says its own
    stored gate states imply. Always a bug, never a data condition."""


def verify(trace: dict) -> None:
    """Recompute the verdict from `gate_states` and raise on any divergence."""
    model = trace.get("gate_model")
    gates = trace.get("gate_states") or {}
    stored = trace.get("verdict")
    if model == NEXTGEN_13:
        _, recomputed, _ = S.classify(gates)
    elif model == CLASSIC_6:
        recomputed = _classic_classify(gates)
    else:
        raise TraceDivergence(f"unknown gate_model {model!r}")
    if recomputed != stored:
        raise TraceDivergence(
            f"{trace.get('finding_id')}: stored verdict {stored!r} but "
            f"{model} gate function says {recomputed!r} from {gates!r}")


def verify_all(traces: Iterable[dict]) -> int:
    n = 0
    for t in traces:
        verify(t)
        n += 1
    return n


# --------------------------------------------------------------------------- #
# The resolution queue and the funnel summary.
# --------------------------------------------------------------------------- #

def _queue_key(t: dict) -> tuple:
    d = t.get("distance_to_confirmed")
    # Killed candidates last: no evidence resolves them.
    return (0 if d is not None else 1,
            d if d is not None else 0,
            t.get("severity_rank", _DEFAULT_SEVERITY_RANK),
            t.get("finding_id") or "")


def resolution_queue(traces: Iterable[dict], *,
                     include_killed: bool = False) -> list[dict]:
    """Candidates ranked by how close they are to a decidable answer.

    distance_to_confirmed ascending, then finding-type severity, then
    finding_id for a stable order. Never a free-text or model-derived score.
    """
    rows = [t for t in traces
            if include_killed or t.get("distance_to_confirmed") is not None]
    return sorted(rows, key=_queue_key)


def _median(xs: list[int]) -> Optional[float]:
    if not xs:
        return None
    xs = sorted(xs)
    mid = len(xs) // 2
    return float(xs[mid]) if len(xs) % 2 else (xs[mid - 1] + xs[mid]) / 2.0


def summarize(traces: Iterable[dict]) -> dict:
    """Verdict distribution, kill-gate and blocking-gate histograms, median
    distance. Counting only - every number here is a count of traces."""
    traces = list(traces)
    verdicts: dict[str, int] = {}
    kill: dict[str, int] = {}
    blocking: dict[str, int] = {}
    engines: dict[str, int] = {}
    distances: list[int] = []

    for t in traces:
        verdicts[t.get("verdict", "")] = verdicts.get(t.get("verdict", ""), 0) + 1
        engines[t.get("engine", "")] = engines.get(t.get("engine", ""), 0) + 1
        kg = t.get("kill_gate")
        if kg:
            kill[kg] = kill.get(kg, 0) + 1
        for g in t.get("blocking_gates") or []:
            blocking[g] = blocking.get(g, 0) + 1
        d = t.get("distance_to_confirmed")
        if d is not None:
            distances.append(d)

    return {
        "traces": len(traces),
        "verdicts": verdicts,
        "engines": engines,
        "kill_gates": dict(sorted(kill.items(), key=lambda kv: -kv[1])),
        "blocking_gates": dict(sorted(blocking.items(), key=lambda kv: -kv[1])),
        "median_distance_to_confirmed": _median(distances),
        "resolvable": len(distances),
        "killed": len(traces) - len(distances),
    }
