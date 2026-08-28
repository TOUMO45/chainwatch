"""Infer candidate security invariants from source structure (spec §2).

Every invariant this module produces is `INFERRED` - a lead. It becomes a
security property only after `validate.py` re-checks it and finds it
un-contradicted. Nothing here decides a verdict.

The inference rules are deliberately mechanical and reuse the classic rules'
Slither primitives (`src/rules/_shared`) so a discovered invariant maps onto
the same notion of "guard" / "init state" the rules already trust:

  1. GUARDED_ACTION   externally-callable, state-changing fn with a
                      msg.sender-dependent guard  -> ACCESS_CONTROL
  2. ROLE_GATED       that guard reads a role-shaped constant             (refines 1)
  3. INITIALIZER_ONCE fn with a one-shot init guard -> STATE_MACHINE
  4. UPGRADE_AUTH     _authorizeUpgrade / upgradeTo present -> DEPLOYMENT
  5. SUPPLY_ACCOUNTING ERC20 shape (totalSupply + balances) -> ACCOUNTING
  6. REQUIRE_CONDITION each require() in an external fn's own body -> CODE (weak)

Rules for accounting solvency, nonce/replay, and event-correspondence are
sketched in the spec and land in a later phase; the framework here is open for
them (`InferenceRule` subclass + register).
"""

from __future__ import annotations

import abc
import hashlib
import re
from typing import Optional

from . import model as M

# upgrade-authorization function names - the fixed protocol API Rule 3a uses.
try:
    from src.rules.rule3a import TARGET_FUNCTIONS as _UPGRADE_FNS
except Exception:  # noqa: BLE001 - importing this module must not need slither
    _UPGRADE_FNS = {"_authorizeUpgrade", "upgradeTo", "upgradeToAndCall",
                    "changeAdmin", "changeProxyAdmin"}

_EXTERNAL = ("external", "public")
_ROLE_HINT = re.compile(r"(ROLE|_ADMIN|ADMIN_|OWNER|GOVERNANCE|MINTER|PAUSER|"
                        r"authoriz|whitelist|allowlist)", re.I)
_MAX_REQUIRES_PER_FN = 6


def _iid(*parts: str) -> str:
    raw = "|".join(str(p) for p in parts)
    return "inv-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _guard_descriptor(fn, contract) -> list[str]:
    from src.rules import _shared
    out: set[str] = set()
    for m in getattr(fn, "modifiers", []):
        n = getattr(m, "name", None)
        if n:
            out.add(f"modifier:{n}")
    try:
        for node in _shared.guard_nodes(fn):
            if _shared.node_depends_on_msg_sender(node, contract):
                out.add("inline:msg.sender")
    except Exception:  # noqa: BLE001
        pass
    return sorted(out)


def _role_vars(fn, contract) -> list[str]:
    """State vars a msg.sender guard reachable from fn compares against, that
    look role-shaped by name (constant bytes32 role ids, owner/admin vars)."""
    from src.rules import _shared
    names: set[str] = set()
    try:
        for f in _shared.reachable(fn):
            for node in _shared.guard_nodes(f):
                if not _shared.node_depends_on_msg_sender(node, contract):
                    continue
                for v in node.state_variables_read:
                    nm = getattr(v, "name", "") or ""
                    if _ROLE_HINT.search(nm):
                        names.add(nm)
    except Exception:  # noqa: BLE001
        pass
    return sorted(names)


def _writes_state(fn) -> bool:
    try:
        if fn.all_state_variables_written():
            return True
        return bool(fn.can_send_eth())
    except Exception:  # noqa: BLE001
        return False


def _implemented_functions(contract):
    for fn in contract.functions:
        if getattr(fn, "is_constructor", False):
            continue
        if not getattr(fn, "is_implemented", True):
            continue
        if getattr(fn, "is_shadowed", False):
            continue
        yield fn


# --------------------------------------------------------------------------- #
# inference rules
# --------------------------------------------------------------------------- #

class InferenceRule(abc.ABC):
    id: str = ""

    @abc.abstractmethod
    def infer(self, contract) -> list[M.CandidateInvariant]:
        raise NotImplementedError


class GuardedActionRule(InferenceRule):
    id = "GUARDED_ACTION"

    def infer(self, contract) -> list[M.CandidateInvariant]:
        from src.rules import _shared
        out: list[M.CandidateInvariant] = []
        for fn in _implemented_functions(contract):
            if fn.visibility not in _EXTERNAL or not _writes_state(fn):
                continue
            if not _shared.constrains_msg_sender(fn, contract):
                continue
            roles = _role_vars(fn, contract)
            guards = _guard_descriptor(fn, contract)
            src = M.SOURCE_ROLE if roles else M.SOURCE_GUARD
            pred = {"guards": guards}
            if roles:
                pred["roles"] = roles
            stmt = (f"only holders of {roles} may call "
                    f"{contract.name}.{fn.name}()" if roles else
                    f"only an authorized caller may call "
                    f"{contract.name}.{fn.name}()")
            # roles live in the PREDICATE (what the invariant constrains), not
            # in `variables` (which identifies a state-variable SUBJECT, e.g.
            # for accounting invariants) - otherwise shrinking a role set would
            # change the subject_key and read as REMOVED instead of WEAKENED.
            out.append(M.CandidateInvariant(
                id=_iid(contract.name, fn.full_name, src),
                kind=M.ACCESS_CONTROL, statement=stmt, source=src,
                strength=M.STRONG, contract=contract.name,
                functions=(fn.name,), predicate=pred))
        return out


class InitializerOnceRule(InferenceRule):
    id = "INITIALIZER_ONCE"

    def infer(self, contract) -> list[M.CandidateInvariant]:
        from src.rules import _shared
        out: list[M.CandidateInvariant] = []
        for fn in _implemented_functions(contract):
            name = (fn.name or "").lower()
            looks_init = name.startswith("initialize") or name.startswith("reinit") \
                or name == "init"
            if not looks_init and not _shared.has_init_guard(fn):
                continue
            if not _shared.has_init_guard(fn):
                continue
            mods = sorted(getattr(m, "name", "?")
                          for m in getattr(fn, "modifiers", []))
            out.append(M.CandidateInvariant(
                id=_iid(contract.name, fn.full_name, M.SOURCE_INIT),
                kind=M.STATE_MACHINE,
                statement=f"{contract.name}.{fn.name}() can be initialised at "
                          f"most once",
                source=M.SOURCE_INIT, strength=M.STRONG,
                contract=contract.name, functions=(fn.name,),
                predicate={"cardinality": "once", "guard": mods}))
        return out


class UpgradeAuthRule(InferenceRule):
    id = "UPGRADE_AUTH"

    def infer(self, contract) -> list[M.CandidateInvariant]:
        from src.rules import _shared
        out: list[M.CandidateInvariant] = []
        for fn in _implemented_functions(contract):
            if fn.name not in _UPGRADE_FNS:
                continue
            guards = _guard_descriptor(fn, contract)
            authorized = guards or (["internal-only"] if fn.visibility
                                    in ("internal", "private") else ["NONE"])
            out.append(M.CandidateInvariant(
                id=_iid(contract.name, fn.full_name, M.SOURCE_UPGRADE),
                kind=M.DEPLOYMENT,
                statement=f"{contract.name}'s implementation can only be "
                          f"upgraded via {fn.name}(), authorised by "
                          f"{authorized}",
                source=M.SOURCE_UPGRADE, strength=M.STRONG,
                contract=contract.name, functions=(fn.name,),
                predicate={"authorized_by": authorized}))
        return out


class SupplyAccountingRule(InferenceRule):
    id = "SUPPLY_ACCOUNTING"

    def infer(self, contract) -> list[M.CandidateInvariant]:
        names = {getattr(v, "name", "") for v in contract.state_variables}
        fn_names = {f.name for f in contract.functions}
        has_supply = "totalSupply" in fn_names or "_totalSupply" in names \
            or "totalSupply" in names
        has_balances = "_balances" in names or "balanceOf" in fn_names
        if not (has_supply and has_balances):
            return []
        mint_burn = [f for f in contract.functions
                     if f.name in ("_mint", "_burn", "mint", "burn")]
        both = False
        for f in mint_burn:
            try:
                w = {getattr(v, "name", "") for v in f.all_state_variables_written()}
            except Exception:  # noqa: BLE001
                w = set()
            if w & {"_totalSupply", "totalSupply"} and w & {"_balances"}:
                both = True
        return [M.CandidateInvariant(
            id=_iid(contract.name, "erc20", M.SOURCE_SUPPLY),
            kind=M.ACCOUNTING,
            statement=f"in {contract.name}, the sum of all balances equals "
                      f"totalSupply",
            source=M.SOURCE_SUPPLY, strength=M.MEDIUM, contract=contract.name,
            variables=("totalSupply", "_balances"),
            predicate={"relation": "sum(balanceOf) == totalSupply",
                       "paths_update_supply": both})]


class RequireConditionRule(InferenceRule):
    id = "REQUIRE_CONDITION"

    def infer(self, contract) -> list[M.CandidateInvariant]:
        from src.rules import _shared
        out: list[M.CandidateInvariant] = []
        for fn in _implemented_functions(contract):
            if fn.visibility not in _EXTERNAL:
                continue
            seen = 0
            for node in getattr(fn, "nodes", []):
                if seen >= _MAX_REQUIRES_PER_FN:
                    break
                if not node.contains_require_or_assert():
                    continue
                expr = str(getattr(node, "expression", "") or "").strip()
                if not expr:
                    continue
                # skip pure msg.sender guards - GuardedActionRule owns those
                if "msg.sender" in expr and "==" in expr and len(expr) < 60:
                    continue
                seen += 1
                out.append(M.CandidateInvariant(
                    id=_iid(contract.name, fn.full_name, "req", str(seen)),
                    kind=M.CODE,
                    statement=f"whenever {contract.name}.{fn.name}() runs, "
                              f"`{expr[:120]}` holds",
                    source=M.SOURCE_REQUIRE, strength=M.WEAK,
                    contract=contract.name, functions=(fn.name,),
                    predicate={"expr": expr[:200]}))
        return out


DEFAULT_RULES: tuple[InferenceRule, ...] = (
    GuardedActionRule(), InitializerOnceRule(), UpgradeAuthRule(),
    SupplyAccountingRule(), RequireConditionRule(),
)


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #

def discover_from_slither(slither_obj, *, version_ref: str = "",
                          rules: Optional[tuple[InferenceRule, ...]] = None
                          ) -> M.InvariantSet:
    from src.rules import _shared
    rules = rules or DEFAULT_RULES
    iset = M.InvariantSet(version_ref=version_ref)
    seen_ids: set[str] = set()
    for contract in getattr(slither_obj, "contracts_derived", slither_obj.contracts):
        try:
            src_path = str(contract.source_mapping.filename.absolute)
        except Exception:  # noqa: BLE001
            src_path = ""
        if src_path and _shared.is_test_path_segments(src_path):
            continue
        for rule in rules:
            try:
                for inv in rule.infer(contract):
                    if inv.id in seen_ids:
                        continue
                    seen_ids.add(inv.id)
                    iset.add(inv)
            except Exception:  # noqa: BLE001 - one rule failing != no result
                continue
    _dedupe_access_control(iset)
    return iset


def discover_from_source(text: str, *, version_ref: str = "") -> M.InvariantSet:
    from .._solc import slither_for_source
    return discover_from_slither(slither_for_source(text), version_ref=version_ref)


def _dedupe_access_control(iset: M.InvariantSet) -> None:
    """When both a ROLE_GATED and a plain GUARDED_ACTION invariant exist for the
    same (contract, function), keep the more specific role one."""
    by_fn: dict[tuple, list[M.CandidateInvariant]] = {}
    for inv in iset.invariants:
        if inv.kind != M.ACCESS_CONTROL:
            continue
        by_fn.setdefault((inv.contract, inv.functions), []).append(inv)
    drop: set[str] = set()
    for group in by_fn.values():
        if len(group) < 2:
            continue
        has_role = any(g.source == M.SOURCE_ROLE for g in group)
        if has_role:
            for g in group:
                if g.source == M.SOURCE_GUARD:
                    drop.add(g.id)
    if drop:
        iset.invariants = [i for i in iset.invariants if i.id not in drop]
