"""Deep security-invariant discovery - categories A-J (spec sections 4, 5).

The classic `src/nextgen/invariants/discover.py` infers six structural
invariants aimed at REGRESSIONS (guard removed, initializer relaxed, ...). Deep
Hunt needs richer, protocol-specific properties whose violation does not require
a git change: asset conservation, user entitlement, share/asset math, debt/LTV,
supply backing, reachable authorization, one-way state machines, replay,
oracle-manipulation assumptions, and free-form protocol invariants.

Each discovered property is an `invariants.model.CandidateInvariant` (so it
shares the INFERRED -> TESTED -> VALIDATED discipline and only a VALIDATED one
can ever gate `security_invariant`). Its `predicate` carries a **`test_recipe`**
- an objective dict in the same shape `invariants/regress.SearchTarget.objective`
uses - so Phase 4 (sequence planning) and Phase 9 (the blinded reproducer) can
drive an execution attempt straight from it without re-parsing prose.

Everything here is mechanical over a `ProtocolModel`. The optional LLM hook
(`llm_hypotheses`) only adds category-J proposals, each kept only if it names a
real function / variable in the model, at WEAK confidence, still INFERRED.
Nothing here decides a verdict.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

from src.nextgen.invariants import model as IM
from . import llm_hypotheses
from . import protocolmodel as PM

# --------------------------------------------------------------------------- #
# deep-hunt source tags (invariants/model.py validates `kind` + `status`, not
# `source`, so the vocabulary extends here without touching that module)
# --------------------------------------------------------------------------- #

SRC_CONSERVATION = "deep:asset-conservation"
SRC_ENTITLEMENT = "deep:user-entitlement"
SRC_SHARE_MATH = "deep:share-accounting"
SRC_DEBT_LTV = "deep:debt-collateral"
SRC_SUPPLY_SUM = "deep:supply-consistency"
SRC_AUTH_REACH = "deep:authorization-reachability"
SRC_STATE_MACHINE = "deep:state-machine"
SRC_REPLAY = "deep:replay-nonce"
SRC_ORACLE = "deep:oracle-assumption"
SRC_PROTOCOL = "deep:protocol-specific"

# --------------------------------------------------------------------------- #
# test-recipe objective types. The first four match
# invariants/regress.SearchTarget.objective exactly; the rest are deep-hunt's.
# --------------------------------------------------------------------------- #

OBJ_CALL_SUCCEEDS = "call_succeeds"
OBJ_REINIT = "reinit"
OBJ_STATE_RELATION = "state_relation_violated"
OBJ_UNAUTH_UPGRADE = "unauthorized_upgrade"

OBJ_CONSERVATION = "conservation_violated"
OBJ_ENTITLEMENT = "entitlement_exceeded"
OBJ_SHARE_MATH = "share_math_divergence"
OBJ_LTV = "ltv_exceeded"
OBJ_SUPPLY = "supply_mismatch"
OBJ_REPLAY = "replay_accepted"
OBJ_ORACLE = "oracle_manipulated_transition"
OBJ_PURITY = "transfer_side_effect"

RECIPE_TYPES = frozenset({
    OBJ_CALL_SUCCEEDS, OBJ_REINIT, OBJ_STATE_RELATION, OBJ_UNAUTH_UPGRADE,
    OBJ_CONSERVATION, OBJ_ENTITLEMENT, OBJ_SHARE_MATH, OBJ_LTV, OBJ_SUPPLY,
    OBJ_REPLAY, OBJ_ORACLE, OBJ_PURITY,
})

_SIG_PARAM_HINT = ("sig", "signature", "proof", "permit", "voucher", "ticket")
_FLAG_HINT = ("initialized", "initialised", "finalized", "started", "opened",
              "launched", "seeded", "bootstrapped", "setup", "sealed",
              "migrated", "activated")
_BACKING_HINT = ("reserve", "backing", "collateral", "asset", "treasury",
                 "underlying")


# --------------------------------------------------------------------------- #
# factory
# --------------------------------------------------------------------------- #

def _mk(kind: str, statement: str, source: str, *, contract: str,
        functions: Iterable[str] = (), variables: Iterable[str] = (),
        strength: str = IM.MEDIUM, recipe: dict | None = None,
        rationale: str = "") -> IM.CandidateInvariant:
    functions = tuple(functions)
    variables = tuple(variables)
    recipe = recipe or {}
    iid = "dinv-" + hashlib.sha256(
        "|".join([kind, source, contract, ",".join(functions),
                  ",".join(variables), statement]).encode()).hexdigest()[:12]
    return IM.CandidateInvariant(
        id=iid, kind=kind, statement=statement, source=source, strength=strength,
        contract=contract, functions=functions, variables=variables,
        predicate={"test_recipe": recipe, "rationale": rationale,
                   "confidence": strength},
        status=IM.INFERRED)


# --------------------------------------------------------------------------- #
# model accessors
# --------------------------------------------------------------------------- #

def _split(qual: str) -> tuple[str, str]:
    c, _, fn = qual.partition(".")
    return c, fn


def _moves_value(f) -> bool:
    if f.sends_eth:
        return True
    blob = " ".join(f.external_calls).lower()
    return any(t in blob for t in (".transfer", ".safetransfer", "senderc20"))


def _protocol_asset_vars(model: PM.ProtocolModel, c) -> tuple[str, ...]:
    out: set[str] = set()
    for a in model.assets:
        if a.kind == PM.ETH:
            out.add("<ETH balance>")
        elif a.contract == c.name:
            out.update(a.accounting_vars)
    return tuple(sorted(out))


def _caller_accounting_vars(model: PM.ProtocolModel) -> tuple[str, ...]:
    out: set[str] = set()
    for a in model.assets:
        if a.kind in (PM.SHARES, PM.ERC20, PM.ERC4626, PM.DEBT):
            out.update(a.accounting_vars)
    for c in model.contracts:
        for v, _t in c.state_vars:
            lv = v.lower()
            if any(k in lv for k in ("shares", "balance", "claimable", "owed",
                                     "deposited", "staked", "rewards")):
                out.add(v)
    return tuple(sorted(out))


def _share_vars(model: PM.ProtocolModel, c) -> tuple[str, ...]:
    out = {v for v, _t in c.state_vars
           if any(k in v.lower() for k in ("shares", "totalassets",
                                           "pricepershare", "exchangerate"))}
    return tuple(sorted(out))


# --------------------------------------------------------------------------- #
# A - asset conservation
# --------------------------------------------------------------------------- #

def cat_asset_conservation(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    tgt = model.target()
    if tgt is None:
        return out
    avars = _protocol_asset_vars(model, tgt)
    if not avars:
        return out
    for f in model.external_functions():
        if f.contract != tgt.name or not _moves_value(f):
            continue
        if f.mutability in ("view", "pure"):
            continue
        out.append(_mk(
            IM.ACCOUNTING,
            f"{tgt.name}.{f.name}() must not reduce the protocol's asset "
            f"reserves by more than the value legitimately owed to the caller",
            SRC_CONSERVATION, contract=tgt.name, functions=(f.name,),
            variables=avars, strength=IM.MEDIUM,
            recipe={"type": OBJ_CONSERVATION, "contract": tgt.name,
                    "function": f.name, "assets": list(avars),
                    "measure": "protocol_balance_delta <= caller_entitlement"},
            rationale="value-moving external entry point on the asset-holding "
                      "target contract"))
    return out


# --------------------------------------------------------------------------- #
# B - user entitlement
# --------------------------------------------------------------------------- #

def cat_user_entitlement(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    evars = _caller_accounting_vars(model)
    for rel in model.relations:
        if rel.kind not in (PM.REL_WITHDRAW_ASSET, PM.REL_CLAIM_REWARD):
            continue
        c, fn = _split(rel.function)
        out.append(_mk(
            IM.ACCOUNTING,
            f"the value {rel.function}() pays msg.sender is at most msg.sender's "
            f"recorded entitlement (shares x price-per-share / claimable / balance)",
            SRC_ENTITLEMENT, contract=c, functions=(fn,), variables=evars,
            strength=IM.STRONG,
            recipe={"type": OBJ_ENTITLEMENT, "contract": c, "function": fn,
                    "entitlement_vars": list(evars)},
            rationale=f"{rel.kind} relation - a payout keyed on caller state"))
    return out


# --------------------------------------------------------------------------- #
# C - share / asset math consistency
# --------------------------------------------------------------------------- #

def cat_share_accounting(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    for c in model.contracts:
        if not any(a.contract == c.name and a.kind in (PM.SHARES, PM.ERC4626)
                   for a in model.assets):
            continue
        deps = [r for r in model.relations
                if r.function.startswith(c.name + ".")
                and r.kind in (PM.REL_DEPOSIT_SHARES, PM.REL_STAKE_REWARDS)]
        wds = [r for r in model.relations
               if r.function.startswith(c.name + ".")
               and r.kind == PM.REL_WITHDRAW_ASSET]
        if not (deps and wds):
            continue
        svars = _share_vars(model, c)
        fns = tuple(_split(r.function)[1] for r in (deps + wds))
        out.append(_mk(
            IM.ACCOUNTING,
            f"in {c.name}, shares and assets convert through ONE consistent "
            f"price per share: no deposit/withdraw sequence lets a caller take "
            f"out more assets than they put in (minus fees)",
            SRC_SHARE_MATH, contract=c.name, functions=fns, variables=svars,
            strength=IM.STRONG,
            recipe={"type": OBJ_SHARE_MATH, "contract": c.name,
                    "deposit_fns": [_split(r.function)[1] for r in deps],
                    "withdraw_fns": [_split(r.function)[1] for r in wds],
                    "share_vars": list(svars),
                    "check": "assets_out/shares_in <= assets_in/shares_in"},
            rationale="matched deposit/withdraw on a share-accounted contract"))
        for r in wds:
            fn = _split(r.function)[1]
            out.append(_mk(
                IM.ACCOUNTING,
                f"{r.function}() burns exactly the shares implied by the assets "
                f"it pays out (burn N shares <-> transfer N x pps assets)",
                SRC_SHARE_MATH, contract=c.name, functions=(fn,),
                variables=svars, strength=IM.MEDIUM,
                recipe={"type": OBJ_SHARE_MATH, "contract": c.name,
                        "function": fn,
                        "check": "shares_burned == assets_out / pricePerShare"},
                rationale="withdraw-side share/asset correspondence "
                          "(spec section 8)"))
    return out


# --------------------------------------------------------------------------- #
# D - debt / collateral
# --------------------------------------------------------------------------- #

def cat_debt_collateral(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    borrows = [r for r in model.relations if r.kind == PM.REL_BORROW_DEBT]
    liqs = [r for r in model.relations if r.kind == PM.REL_LIQUIDATE_COLLATERAL]
    debt_assets = [a for a in model.assets if a.kind == PM.DEBT]
    if not (borrows or liqs or debt_assets):
        return out
    if debt_assets:
        c = debt_assets[0].contract
    elif borrows:
        c = _split(borrows[0].function)[0]
    else:
        c = _split(liqs[0].function)[0]
    dvars = tuple(sorted({v for a in debt_assets for v in a.accounting_vars}))
    bfns = tuple(_split(r.function)[1] for r in borrows)
    out.append(_mk(
        IM.ECONOMIC,
        f"in {c}, a position's debt never exceeds its collateral value times "
        f"the max LTV after any borrow / withdraw / oracle update",
        SRC_DEBT_LTV, contract=c, functions=bfns, variables=dvars,
        strength=IM.STRONG,
        recipe={"type": OBJ_LTV, "contract": c, "borrow_fns": list(bfns),
                "check": "debt <= collateralValue * maxLTV"},
        rationale="lending shape - borrow/debt relation present"))
    if liqs:
        lf = tuple(_split(r.function)[1] for r in liqs)
        out.append(_mk(
            IM.ECONOMIC,
            f"{c} liquidation may only seize collateral from a position that is "
            f"actually below the liquidation threshold",
            SRC_DEBT_LTV, contract=c, functions=lf, variables=dvars,
            strength=IM.MEDIUM,
            recipe={"type": OBJ_LTV, "contract": c, "liquidate_fns": list(lf),
                    "check": "position_health < 1 required"},
            rationale="liquidation relation present"))
    return out


# --------------------------------------------------------------------------- #
# E - supply consistency / backing
# --------------------------------------------------------------------------- #

def cat_supply_consistency(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    for a in model.assets:
        if a.kind not in (PM.ERC20, PM.ERC4626, PM.WRAPPED):
            continue
        cm = model.contract(a.contract)
        if cm is None:
            continue
        svars = tuple(sorted(set(a.accounting_vars) | {"totalSupply"}))
        out.append(_mk(
            IM.ACCOUNTING,
            f"in {a.contract}, the sum of all balances equals totalSupply at "
            f"all times",
            SRC_SUPPLY_SUM, contract=a.contract, functions=(), variables=svars,
            strength=IM.MEDIUM,
            recipe={"type": OBJ_SUPPLY, "contract": a.contract,
                    "check": "sum(balanceOf) == totalSupply"},
            rationale="ERC20 supply/balance shape"))
        backing = sorted({v for v, _t in cm.state_vars
                          if any(k in v.lower() for k in _BACKING_HINT)})
        mint_fns = tuple(f.name for f in cm.functions
                         if f.name.lower() in ("mint", "_mint") and f.external)
        if backing and mint_fns:
            out.append(_mk(
                IM.ACCOUNTING,
                f"{a.contract}'s minted supply stays fully backed: totalSupply "
                f"never outgrows the backing reserves {backing}",
                SRC_SUPPLY_SUM, contract=a.contract, functions=mint_fns,
                variables=tuple(backing), strength=IM.STRONG,
                recipe={"type": OBJ_SUPPLY, "contract": a.contract,
                        "mint_fns": list(mint_fns),
                        "check": "totalSupply <= backing"},
                rationale="mintable token with an on-contract backing reserve"))
    return out


# --------------------------------------------------------------------------- #
# F - authorization reachability
# --------------------------------------------------------------------------- #

def cat_authorization(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    priv: dict[str, set[str]] = {}
    for f in model.external_functions():
        if f.access_controlled:
            for w in f.writes:
                priv.setdefault(w, set()).add(f"{f.contract}.{f.name}")

    for f in model.external_functions():
        if f.access_controlled or not f.state_changing:
            continue
        hit = sorted(set(f.writes) & set(priv))
        if not hit:
            continue
        guards = sorted({g for v in hit for g in priv[v]})
        cross = any(not g.startswith(f.contract + ".") for g in guards)
        inv = _mk(
            IM.CROSS_CONTRACT if cross else IM.ACCESS_CONTROL,
            f"the privileged state {hit} may only be changed by an authorized "
            f"caller - yet {f.contract}.{f.name}() reaches it with no "
            f"caller-identity guard",
            SRC_AUTH_REACH, contract=f.contract, functions=(f.name,),
            variables=tuple(hit), strength=IM.STRONG,
            recipe={"type": OBJ_CALL_SUCCEEDS, "contract": f.contract,
                    "function": f.name, "caller": "unprivileged",
                    "privileged_vars": hit},
            rationale=f"the same state is guarded elsewhere by {guards}")
        inv.contradiction = (f"{f.contract}.{f.name}() is an unguarded external "
                             f"writer of {hit}")
        out.append(inv)

    for role in model.roles:
        for gf in role.gated_functions:
            c, fn = _split(gf)
            fm = model.function(c, fn)
            if fm is None or not fm.state_changing:
                continue
            out.append(_mk(
                IM.ACCESS_CONTROL,
                f"only the '{role.name}' authority may successfully call "
                f"{c}.{fn}()",
                SRC_AUTH_REACH, contract=c, functions=(fn,),
                variables=tuple(role.guard_vars), strength=IM.MEDIUM,
                recipe={"type": OBJ_CALL_SUCCEEDS, "contract": c, "function": fn,
                        "caller": "unprivileged"},
                rationale=f"gated today by {role.name} ({role.kind})"))
    return out


# --------------------------------------------------------------------------- #
# G - one-way state machine
# --------------------------------------------------------------------------- #

def cat_state_machine(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    for f in model.external_functions():
        n = f.name.lower()
        one_shot = n.startswith(("initialize", "initialise", "init", "setup",
                                 "seed", "bootstrap"))
        flag_write = [w for w in f.writes
                      if any(h in w.lower() for h in _FLAG_HINT)]
        if not (one_shot or flag_write):
            continue
        out.append(_mk(
            IM.STATE_MACHINE,
            f"{f.contract}.{f.name}() performs a one-way transition; a second "
            f"successful call must be impossible",
            SRC_STATE_MACHINE, contract=f.contract, functions=(f.name,),
            variables=tuple(flag_write), strength=IM.STRONG if one_shot else IM.MEDIUM,
            recipe={"type": OBJ_REINIT, "contract": f.contract,
                    "function": f.name, "flag_vars": flag_write},
            rationale="initializer / one-way flag write"))
    return out


# --------------------------------------------------------------------------- #
# H - replay / nonce
# --------------------------------------------------------------------------- #

def cat_replay(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    for f in model.external_functions():
        touched = list(f.writes) + list(f.reads)
        nonce_vars = sorted({x for x in touched
                             if any(k in x.lower() for k in PM._NONCE_VARS)})
        sig_param = any(
            any(h in (p.name or "").lower() for h in _SIG_PARAM_HINT)
            or "bytes" in (p.type or "") for p in f.params)
        recovers = any("ecrecover" in x.lower() or ".recover" in x.lower()
                       or "isvalidsignature" in x.lower()
                       for x in (list(f.external_calls) + list(f.internal_calls)))
        if not (nonce_vars or (sig_param and recovers)):
            continue
        out.append(_mk(
            IM.STATE_MACHINE,
            f"each authorization consumed by {f.contract}.{f.name}() (nonce / "
            f"signature / message id) can be used at most once",
            SRC_REPLAY, contract=f.contract, functions=(f.name,),
            variables=tuple(nonce_vars),
            strength=IM.STRONG if nonce_vars else IM.MEDIUM,
            recipe={"type": OBJ_REPLAY, "contract": f.contract,
                    "function": f.name, "nonce_vars": nonce_vars,
                    "sig_verified": bool(recovers)},
            rationale="nonce slot / signature-verifying entry point"))
    return out


# --------------------------------------------------------------------------- #
# I - oracle assumption
# --------------------------------------------------------------------------- #

_SPOT_HINTS = ("latestanswer", "getreserves", "getamountsout", "getamountout",
               "quote", "quoterouted", "consult", "current",
               "price0cumulativelast", "price1cumulativelast")


def cat_oracle_assumption(model: PM.ProtocolModel) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    for dep in model.dependencies:
        if dep.kind not in (PM.DEP_ORACLE, PM.DEP_AMM):
            continue
        spot = dep.kind == PM.DEP_AMM or dep.hint.lower() in _SPOT_HINTS
        if not spot and dep.return_checked is True:
            continue
        for who in dep.consumed_by:
            c, fn = _split(who)
            fm = model.function(c, fn)
            if fm is None or fm.mutability in ("view", "pure") or not fm.state_changing:
                continue
            out.append(_mk(
                IM.PROTOCOL,
                f"the price {who}() relies on must be manipulation-resistant "
                f"(a TWAP, or a staleness-checked feed) - not an instantaneous "
                f"AMM spot read via {dep.hint}()",
                SRC_ORACLE, contract=c, functions=(fn,), variables=(),
                strength=IM.STRONG if spot else IM.MEDIUM,
                recipe={"type": OBJ_ORACLE, "contract": c, "function": fn,
                        "oracle_hint": dep.hint, "spot_priced": spot,
                        "manipulation": "same-block flash swap on the priced pair"},
                rationale=f"{dep.kind} dependency ({dep.hint}) feeds a state "
                          f"transition; return_checked={dep.return_checked}"))
    return out


# --------------------------------------------------------------------------- #
# J - protocol specific (+ optional LLM proposals)
# --------------------------------------------------------------------------- #

_XFER_NAMES = ("transfer", "_transfer", "transferfrom", "_transferfrom")
_SIDE_EFFECTS = (".sync", ".skim", ".swap", "getreserves", "getamountsout",
                 ".mint", ".burn", "addliquidity", "removeliquidity")


def cat_protocol_specific(model: PM.ProtocolModel, *,
                          use_llm: bool = False) -> list[IM.CandidateInvariant]:
    out: list[IM.CandidateInvariant] = []
    for c in model.contracts:
        for f in c.functions:
            blob = " ".join(f.external_calls).lower()
            if f.name.lower() in _XFER_NAMES:
                seen = [x for x in _SIDE_EFFECTS if x in blob or x.lstrip(".") in blob]
                pair_touch = "sync" in blob or "getreserves" in blob or "pair" in blob
                if seen or (f.external_calls and pair_touch):
                    out.append(_mk(
                        IM.PROTOCOL,
                        f"{c.name}.{f.name}() moves balances only - an ERC20 "
                        f"transfer must not run swap logic, resync an AMM pair, "
                        f"or mint/burn a third party's balance",
                        SRC_PROTOCOL, contract=c.name, functions=(f.name,),
                        variables=(), strength=IM.STRONG,
                        recipe={"type": OBJ_PURITY, "contract": c.name,
                                "function": f.name, "side_effects_seen": seen},
                        rationale="swap / pair.sync side effects inside a "
                                  "transfer path (FireToken / AIZPT class)"))
            if any(x in blob for x in (".sync", ".skim")):
                out.append(_mk(
                    IM.PROTOCOL,
                    f"{c.name}.{f.name}() must not forcibly resync an external "
                    f"AMM pair's reserves from inside protocol logic",
                    SRC_PROTOCOL, contract=c.name, functions=(f.name,),
                    variables=(), strength=IM.MEDIUM,
                    recipe={"type": OBJ_PURITY, "contract": c.name,
                            "function": f.name, "side_effects_seen": ["pair.sync"]},
                    rationale="direct pair.sync()/skim() call"))
    if use_llm:
        for item in llm_hypotheses.propose_invariants(model):
            inv = _from_llm(model, item)
            if inv is not None:
                out.append(inv)
    return out


def _from_llm(model: PM.ProtocolModel, item: dict) -> IM.CandidateInvariant | None:
    stmt = str(item.get("statement", "")).strip()
    if not stmt:
        return None
    fns = [str(x) for x in item.get("functions", []) if x]
    varz = [str(x) for x in item.get("variables", []) if x]
    real_fns = {f"{f.contract}.{f.name}" for f in model.all_functions()} \
        | {f.name for f in model.all_functions()}
    real_vars = {v for c in model.contracts for v, _t in c.state_vars}
    if not (any(f in real_fns for f in fns) or any(v in real_vars for v in varz)):
        return None
    c = model.target().name if model.target() else (model.contracts[0].name
                                                    if model.contracts else "")
    inv = _mk(IM.PROTOCOL, stmt, SRC_PROTOCOL + ":llm", contract=c,
              functions=[f.split(".")[-1] for f in fns][:4], variables=varz[:6],
              strength=IM.WEAK,
              recipe={"type": OBJ_STATE_RELATION, "contract": c,
                      "statement": stmt},
              rationale="LLM proposal, structurally re-anchored to the model; "
                        "hypothesis only")
    inv.notes.append("source: LLM hypothesis - not evidence (spec section 22)")
    return inv


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #

CATEGORIES = (
    cat_asset_conservation, cat_user_entitlement, cat_share_accounting,
    cat_debt_collateral, cat_supply_consistency, cat_authorization,
    cat_state_machine, cat_replay, cat_oracle_assumption,
)


def discover(model: PM.ProtocolModel, *,
             use_llm: bool = False) -> list[IM.CandidateInvariant]:
    """Every deep invariant for `model`, all status INFERRED."""
    if not getattr(model, "compiled", False):
        return []
    out: list[IM.CandidateInvariant] = []
    for cat in CATEGORIES:
        try:
            out.extend(cat(model) or [])
        except Exception:  # noqa: BLE001 - one category failing != no result
            continue
    try:
        out.extend(cat_protocol_specific(model, use_llm=use_llm) or [])
    except Exception:  # noqa: BLE001
        pass
    return _dedupe(out)


def validate(model: PM.ProtocolModel,
             invs: list[IM.CandidateInvariant]) -> list[IM.CandidateInvariant]:
    """Model-level re-check.

    INFERRED -> TESTED when the structural trigger is still present in the model.
    Only category-F contradiction invariants reach VALIDATED here (a concrete
    unguarded external writer is a structural proof). The relationship
    invariants (A/B/C/D/E/I) stay at TESTED - VALIDATED needs an execution
    observation (Phase 9), matching the spec: only VALIDATED gates
    `security_invariant`.
    """
    for inv in invs:
        try:
            _validate_one(model, inv)
        except Exception:  # noqa: BLE001
            inv.notes.append("validate: skipped on error")
    return invs


def _validate_one(model: PM.ProtocolModel, inv: IM.CandidateInvariant) -> None:
    if inv.status not in (IM.INFERRED, IM.TESTED):
        return
    present = all(model.function(inv.contract, fn) is not None
                  for fn in inv.functions) if inv.functions else \
        model.contract(inv.contract) is not None
    if not present:
        inv.reject("named function / contract not present in the model")
        return
    _advance_to(inv, IM.TESTED, "structural trigger still present in the model")

    if inv.source == SRC_AUTH_REACH and inv.contradiction:
        fn = inv.functions[0] if inv.functions else ""
        fm = model.function(inv.contract, fn)
        if fm is not None and not fm.access_controlled and fm.state_changing:
            _advance_to(inv, IM.VALIDATED,
                        "unguarded external writer of the privileged state is "
                        "still present - contradiction stands")


def _advance_to(inv: IM.CandidateInvariant, target: str, note: str) -> None:
    order = (IM.INFERRED, IM.TESTED, IM.VALIDATED, IM.USED)
    while inv.status != IM.REJECTED and \
            order.index(inv.status) < order.index(target):
        inv.advance(order[order.index(inv.status) + 1], note=note)


def _dedupe(invs: list[IM.CandidateInvariant]) -> list[IM.CandidateInvariant]:
    seen: set[tuple] = set()
    out: list[IM.CandidateInvariant] = []
    for inv in invs:
        key = (inv.kind, inv.contract, tuple(inv.functions), inv.source,
               inv.statement)
        if key in seen:
            continue
        seen.add(key)
        out.append(inv)
    return out


def by_recipe_type(invs: Iterable[IM.CandidateInvariant]) -> dict[str, list]:
    out: dict[str, list] = {}
    for inv in invs:
        t = ((inv.predicate or {}).get("test_recipe") or {}).get("type", "?")
        out.setdefault(t, []).append(inv)
    return out


def summarize(invs: list[IM.CandidateInvariant]) -> str:
    if not invs:
        return "DEEP INVARIANTS\n==============\n\n  (none discovered)"
    lines = ["DEEP INVARIANTS", "=" * 14, "",
             f"  {len(invs)} candidate invariant(s)"]
    by_status: dict[str, int] = {}
    for inv in invs:
        by_status[inv.status] = by_status.get(inv.status, 0) + 1
    lines.append("  by status: " + ", ".join(f"{k}={v}"
                                              for k, v in sorted(by_status.items())))
    by_src: dict[str, list] = {}
    for inv in invs:
        by_src.setdefault(inv.source, []).append(inv)
    for src, group in sorted(by_src.items()):
        lines.append(f"\n  {src}  ({len(group)})")
        for inv in group[:6]:
            lines.append(f"    [{inv.status:<9}] {inv.statement[:96]}")
    return "\n".join(lines)
