"""Capability 15 - what would settle this CANDIDATE (finding DEEPEN-1).

Chainwatch already has three real deepening strategies, each aimed at one
specific evidence gap:

  * rename-following      (`scan._renamed_path_at_head`)  -> reachability
  * immutable-clone recompile (`scan._attach_liveness`)   -> liveness
  * capability 13 / 14 probes (`exposure`, `exploit_proof`) -> live exposure

Nothing routed a finding to the right one. A reader saw `missing evidence:
liveness` and had to know, from the source, which of those applied and what
input it needed. This module is that routing, made explicit.

WHAT THIS IS NOT. It gathers and NAMES evidence; it never grades. Every
function here is pure with respect to the verdict - it reads a finished
`Finding` and returns a description of what is missing and what would resolve
it. A deepening step that could promote a verdict by itself would be a second
implementation of `verdict.classify`, which is exactly the "two things that can
disagree" failure this project avoids everywhere else.

So the contract is deliberately narrow:

    a step may tell you what to run.
    it may not run it and decide the answer.

That keeps the zero-false-positive guarantee where it belongs - in
`verdict.classify`, reading evidence that deterministic code established.
"""

from __future__ import annotations

import re
from typing import Optional

# One entry per gap this project can actually close, and the concrete thing that
# closes it. Keyed on the vocabulary `verdict.classify` already emits, so the
# two cannot drift apart silently: `_UNMATCHED` below is returned for anything
# that has no registered step, which is visible rather than dropped.
_ADDRESS_HINT = ("re-run with --address <deployed address> for this contract; "
                 "liveness is UNKNOWN until deployed bytecode is compared")


def _liveness_step(f: dict) -> dict:
    live = (f.get("liveness") or "UNKNOWN").upper()
    if not f.get("address_used"):
        return {
            "gap": "liveness",
            "status": "actionable",
            "why": "no deployed address was supplied, so nothing was compared",
            "action": _ADDRESS_HINT,
            "cost": "one eth_getCode per address",
        }
    if live == "UNKNOWN":
        return {
            "gap": "liveness",
            "status": "actionable",
            "why": "deployed bytecode did not match this commit's build",
            "action": ("check the compiler settings the deployment used "
                       "(optimizer runs, solc version); if the target is an "
                       "EIP-1167 clone, pass the CLONE address rather than the "
                       "implementation so the clone fallback can engage"),
            "cost": "one recompile per candidate setting",
        }
    return {
        "gap": "liveness",
        "status": "settled-negative",
        "why": f"liveness={live}: the deployed code is not this regression",
        "action": "none - this finding is history, not a live exposure",
        "cost": "none",
    }


def _reachability_step(f: dict) -> dict:
    if f.get("survives_to_head") is False:
        return {
            "gap": "reachability",
            "status": "settled-negative",
            "why": ("the regression was repaired at HEAD"
                    + (f" ({f['fixed_at']})" if f.get("fixed_at") else "")),
            "action": ("none for current source. If the deployed target is an "
                       "immutable clone, a source fix cannot reach it - pass "
                       "that clone's address to test it separately"),
            "cost": "none",
        }
    return {
        "gap": "reachability",
        "status": "actionable",
        "why": ("the file could not be re-checked at HEAD - it is absent from "
                "its recorded path and no unambiguous rename was found"),
        "action": ("confirm the file's current location and re-run against the "
                   "branch that actually carries it (a stale default branch is "
                   "the usual cause)"),
        "cost": "one re-run",
    }


def _rule_cap_step(f: dict, reason: str) -> dict:
    return {
        "gap": "rule-ceiling",
        "status": "blocked",
        "why": reason,
        "action": ("none available. This trigger class is capped at CANDIDATE "
                   "by RULES.md itself, not by missing evidence - raising it "
                   "would be a rule change, argued in RULES.md and locked by "
                   "fixtures, never a per-finding decision"),
        "cost": "n/a",
    }


_UNMATCHED = {
    "gap": "unclassified",
    "status": "unknown",
    "why": "no deepening step is registered for this downgrade reason",
    "action": ("read the finding's own evidence block; this is a gap in "
               "src/deepen.py's routing, not necessarily in the finding"),
    "cost": "n/a",
}

_MISSING_RE = re.compile(r"^missing evidence:\s*(.+)$", re.I)


def next_steps(f: dict) -> list[dict]:
    """What would settle this finding, one entry per open gap.

    Returns [] for a CONFIRMED finding - there is nothing left to establish.
    Never mutates `f`, never returns a verdict.
    """
    if (f.get("verdict") or "").upper() != "CANDIDATE":
        return []

    steps: list[dict] = []
    seen: set[str] = set()

    def add(step: dict) -> None:
        if step["gap"] not in seen:
            seen.add(step["gap"])
            steps.append(step)

    for reason in f.get("downgrade_reasons") or []:
        m = _MISSING_RE.match(reason.strip())
        if m:
            for field in (x.strip() for x in m.group(1).split(",")):
                if field == "liveness":
                    add(_liveness_step(f))
                elif field == "reachability":
                    add(_reachability_step(f))
                else:
                    add({**_UNMATCHED, "gap": field,
                         "why": f"evidence field '{field}' is not established"})
            continue
        low = reason.lower()
        if "liveness=" in low:
            add(_liveness_step(f))
        elif "does not survive to head" in low:
            add(_reachability_step(f))
        elif "caps this trigger class" in low:
            add(_rule_cap_step(f, reason))
        else:
            add({**_UNMATCHED, "why": reason})

    return steps


def summarize(f: dict) -> Optional[str]:
    """One line for a report: the single most actionable next step, if any."""
    for step in next_steps(f):
        if step["status"] == "actionable":
            return f"{step['gap']}: {step['action']}"
    return None
