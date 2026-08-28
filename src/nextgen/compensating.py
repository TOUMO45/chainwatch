"""Compensating-control analysis (spec §11).

Detecting that a protection was removed is only half the question. Before a
"guard removed" claim stands, search for ANOTHER mechanism that provides
equivalent security - reasoning about semantic equivalence, not textual
presence. Chainwatch's classic rules already do a lot of this by construction
(`constrains_msg_sender` is transitive, so a renamed modifier or an inline
check keeps a rule quiet); this module makes the search explicit for the
next-gen pipeline and covers cases the pairwise rule does not:

  TRANSITIVE_GUARD    a function / library reachable from the target still
                      gates on msg.sender  (there was never a real regression)
  CALLER_GUARD        EVERY external entry point that reaches the target is
                      itself msg.sender-guarded (protection moved upstream)
  STATE_PRECONDITION  the target reverts unless a state var holds a value only
                      a guarded (or one-shot-init) path can set
  GLOBAL_HALT         the target inherits a pause / mutex controlled by a
                      guarded actor

A control found here FAILS the `no_compensating_control` gate -> the candidate
is REJECTED as FALSE_POSITIVE. None found -> PASS.

`slither` is needed only to call `analyze`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import state as S

TRANSITIVE_GUARD = "TRANSITIVE_GUARD"
CALLER_GUARD = "CALLER_GUARD"
STATE_PRECONDITION = "STATE_PRECONDITION"
GLOBAL_HALT = "GLOBAL_HALT"


@dataclass
class CompensatingControl:
    kind: str
    detail: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail}


@dataclass
class CompensatingReport:
    contract: str
    function: str
    controls: list[CompensatingControl] = field(default_factory=list)
    gate: str = S.PASS
    rationale: str = ""

    def as_dict(self) -> dict:
        return {"contract": self.contract, "function": self.function,
                "gate": self.gate, "rationale": self.rationale,
                "controls": [c.as_dict() for c in self.controls]}

    def render_text(self) -> str:
        lines = ["COMPENSATING-CONTROL ANALYSIS (spec §11)", "=" * 39, "",
                 f"  target: {self.contract}.{self.function}",
                 f"  gate:   {self.gate}  -  {self.rationale}", ""]
        if not self.controls:
            lines.append("  no compensating control found - the removed guard "
                         "is not replaced by an equivalent mechanism")
        for c in self.controls:
            lines.append(f"  [{c.kind}] {c.detail}")
        return "\n".join(lines)


def _find(slither_obj, contract_name: str, function_name: str):
    for c in getattr(slither_obj, "contracts_derived", slither_obj.contracts):
        if c.name != contract_name:
            continue
        for fn in c.functions:
            if fn.name == function_name:
                return c, fn
    return None, None


def _writers_of(contract, var_name: str):
    out = []
    for fn in contract.functions:
        try:
            if var_name in {getattr(v, "name", "")
                            for v in fn.all_state_variables_written()}:
                out.append(fn)
        except Exception:  # noqa: BLE001
            pass
    return out


def analyze(slither_obj, contract_name: str, function_name: str
            ) -> CompensatingReport:
    from src.rules import _shared

    rep = CompensatingReport(contract_name, function_name)
    contract, fn = _find(slither_obj, contract_name, function_name)
    if fn is None:
        rep.gate = S.GATE_UNKNOWN
        rep.rationale = "target function not found at this version"
        return rep

    # 1. TRANSITIVE_GUARD - a guard reachable from fn still gates on msg.sender.
    try:
        if _shared.constrains_msg_sender(fn, contract):
            rep.controls.append(CompensatingControl(
                TRANSITIVE_GUARD,
                "a guard reachable from the function still depends on "
                "msg.sender (renamed modifier, inline check, or a guarded "
                "internal callee) - no real regression"))
    except Exception:  # noqa: BLE001
        pass

    # 2. CALLER_GUARD - fn is internal-only and every external reacher is guarded.
    if fn.visibility not in ("external", "public"):
        reachers = []
        for other in contract.functions:
            if other is fn or other.visibility not in ("external", "public"):
                continue
            try:
                if fn in _shared.reachable(other):
                    reachers.append(other)
            except Exception:  # noqa: BLE001
                pass
        if reachers and all(_safe_guard(_shared, o, contract) for o in reachers):
            rep.controls.append(CompensatingControl(
                CALLER_GUARD,
                f"every external entry point that reaches it "
                f"({sorted(o.name for o in reachers)}) is msg.sender-guarded"))

    # 3. STATE_PRECONDITION - fn reverts unless a state var it does NOT write
    #    holds a value only a guarded / one-shot path can set.
    try:
        own_writes = {getattr(v, "name", "")
                      for v in fn.all_state_variables_written()}
        for node in _shared.guard_nodes(fn):
            for v in node.state_variables_read:
                vn = getattr(v, "name", "")
                if not vn or vn in own_writes:
                    continue
                writers = _writers_of(contract, vn)
                if not writers:
                    continue
                if all(_safe_guard(_shared, w, contract)
                       or _oneshot(_shared, w) for w in writers):
                    rep.controls.append(CompensatingControl(
                        STATE_PRECONDITION,
                        f"reverts unless `{vn}` is set, and every writer of "
                        f"`{vn}` is guarded or one-shot-init "
                        f"({sorted(w.name for w in writers)})"))
                    break
    except Exception:  # noqa: BLE001
        pass

    # 4. GLOBAL_HALT - a modifier on fn reads a bool state var whose writers
    #    are all guarded (a pause switch / mutex).
    try:
        for mod in getattr(fn, "modifiers", []):
            for node in _shared.guard_nodes(mod):
                for v in node.state_variables_read:
                    vn = getattr(v, "name", "")
                    low = vn.lower()
                    if not any(k in low for k in ("pause", "paused", "halt",
                                                  "locked", "frozen", "stopped")):
                        continue
                    writers = _writers_of(contract, vn)
                    if writers and all(_safe_guard(_shared, w, contract)
                                       for w in writers):
                        rep.controls.append(CompensatingControl(
                            GLOBAL_HALT,
                            f"inherits `{mod.name}` gating on `{vn}`, whose "
                            f"writers are all guarded"))
                        raise StopIteration
    except StopIteration:
        pass
    except Exception:  # noqa: BLE001
        pass

    if rep.controls:
        rep.gate = S.FAIL
        rep.rationale = ("a compensating control provides equivalent protection: "
                         + ", ".join(sorted({c.kind for c in rep.controls})))
    else:
        rep.gate = S.PASS
        rep.rationale = "no equivalent mechanism replaces the removed guard"
    return rep


def _safe_guard(_shared, fn, contract) -> bool:
    try:
        return _shared.constrains_msg_sender(fn, contract)
    except Exception:  # noqa: BLE001
        return False


def _oneshot(_shared, fn) -> bool:
    try:
        return _shared.has_init_guard(fn)
    except Exception:  # noqa: BLE001
        return False


def analyze_from_source(text: str, contract_name: str, function_name: str
                        ) -> CompensatingReport:
    from ._solc import slither_for_source
    return analyze(slither_for_source(text), contract_name, function_name)
