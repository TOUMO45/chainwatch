"""Concrete `PropertyProbe`s for the Security Time Machine (spec §1).

Each probe measures ONE security property from source at ONE commit, built on
the SAME Slither primitives the classic rules use (`src/rules/_shared.py`) so
the Time Machine and the rules cannot disagree about what the property is.

SCOPE LIMIT, stated plainly (this is a Phase 1 cut, not a hidden gap):
these probes compile the defining file in ISOLATION. A file whose meaning
depends on imported base contracts (an `onlyOwner` inherited from an
OpenZeppelin `Ownable` that is not resolvable standalone) will not compile
here, and the probe returns `measurable=False` for that commit rather than
guessing. Per-commit dependency reconstruction (the worktree + env machinery in
`src/scan.py`) is wired into the Time Machine in a later phase; until then a
timeline over a self-contained contract is exact, and a timeline over one with
unresolved imports is honestly partial.

`slither` / `solc` are required only to RUN a probe, never to import this
module - the timeline engine in `timemachine.py` has no such dependency.
"""

from __future__ import annotations

from typing import Callable, Optional

from . import timemachine as TM
from ._solc import slither_for_source as _slither_for  # noqa: F401  (re-export)


def _find(slither, contract_name: str, function_name: Optional[str]):
    for c in slither.contracts:
        if c.name != contract_name:
            continue
        if function_name is None:
            return c, None
        for fn in c.functions:
            if fn.name == function_name and _shared_declared(fn):
                return c, fn
        # also accept an inherited function surfaced on this contract
        for fn in c.functions:
            if fn.name == function_name:
                return c, fn
    return None, None


def _shared_declared(fn) -> bool:
    try:
        from src.rules import _shared
        return _shared.declared_in_repo(fn)
    except Exception:
        return True


class AccessControlProbe(TM.PropertyProbe):
    """'Only an authorized caller can execute `Contract.function()`'.

    `present` iff a guard reachable from the function depends on `msg.sender`
    (via a modifier or an inline require/assert), measured by
    `_shared.constrains_msg_sender` - the exact primitive Rule 1 uses.

    `value` is a stable descriptor of WHICH guards are in force, so swapping
    `onlyOwner` for `onlyRole(ADMIN)` is a MODIFIED event, not a REMOVED one.
    """

    kind = TM.ACCESS_CONTROL

    def __init__(self, path: str, contract: str, function: str):
        self.path = path
        self.contract = contract
        self.function = function
        self.paths = (path,)
        self.id = f"access-control:{path}:{contract}.{function}"
        self.title = (f"Only an authorized caller can execute "
                      f"{contract}.{function}()")

    def measure(self, get_file: Callable[[str], Optional[str]]) -> TM.Measurement:
        text = get_file(self.path)
        if text is None:
            return TM.Measurement(False, None, measurable=False,
                                  note="file absent at this commit")
        try:
            sl = _slither_for(text)
        except Exception as exc:  # noqa: BLE001 - compile failure is "unmeasurable"
            return TM.Measurement(False, None, measurable=False,
                                  note=f"did not compile in isolation: "
                                       f"{type(exc).__name__}")
        try:
            from src.rules import _shared
            c, fn = _find(sl, self.contract, self.function)
            if c is None or fn is None:
                return TM.Measurement(False, None, measurable=False,
                                      note="contract/function not found at this "
                                           "commit")
            present = _shared.constrains_msg_sender(fn, c)
            value = self._guard_descriptor(fn, c, _shared)
            return TM.Measurement(present, value, measurable=True,
                                  note="" if present else "no msg.sender guard "
                                       "reachable from the function")
        except Exception as exc:  # noqa: BLE001
            return TM.Measurement(False, None, measurable=False,
                                  note=f"probe error: {type(exc).__name__}")

    @staticmethod
    def _guard_descriptor(fn, contract, _shared) -> tuple:
        parts: set[str] = set()
        for m in getattr(fn, "modifiers", []):
            name = getattr(m, "name", None)
            if name:
                parts.add(f"modifier:{name}")
        try:
            for node in _shared.guard_nodes(fn):
                if _shared.node_depends_on_msg_sender(node, contract):
                    parts.add("inline:msg.sender-check")
        except Exception:  # noqa: BLE001
            pass
        return tuple(sorted(parts))


class InitializerOneShotProbe(TM.PropertyProbe):
    """'`Contract.function()` can be initialised at most once'.

    `present` iff the function carries a one-shot init guard (a modifier or an
    inline initialized-flag check), via `_shared.has_init_guard` - Rule 3b's
    primitive. `value` records how the guard is expressed.
    """

    kind = TM.STATE_MACHINE

    def __init__(self, path: str, contract: str, function: str = "initialize"):
        self.path = path
        self.contract = contract
        self.function = function
        self.paths = (path,)
        self.id = f"init-oneshot:{path}:{contract}.{function}"
        self.title = f"{contract}.{function}() can be initialised at most once"

    def measure(self, get_file: Callable[[str], Optional[str]]) -> TM.Measurement:
        text = get_file(self.path)
        if text is None:
            return TM.Measurement(False, None, measurable=False,
                                  note="file absent at this commit")
        try:
            sl = _slither_for(text)
        except Exception as exc:  # noqa: BLE001
            return TM.Measurement(False, None, measurable=False,
                                  note=f"did not compile in isolation: "
                                       f"{type(exc).__name__}")
        try:
            from src.rules import _shared
            c, fn = _find(sl, self.contract, self.function)
            if c is None or fn is None:
                return TM.Measurement(False, None, measurable=False,
                                      note="contract/function not found")
            present = _shared.has_init_guard(fn)
            mods = tuple(sorted(getattr(m, "name", "?")
                                for m in getattr(fn, "modifiers", [])))
            value = ("modifier-guard", mods) if mods else ("inline-or-none",)
            return TM.Measurement(present, value, measurable=True)
        except Exception as exc:  # noqa: BLE001
            return TM.Measurement(False, None, measurable=False,
                                  note=f"probe error: {type(exc).__name__}")
