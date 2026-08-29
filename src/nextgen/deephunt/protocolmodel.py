"""ProtocolModel - understand the deployed protocol before hunting it (spec section 3).

The Deep Hunt engine must not reason about a bag of functions. It reasons about
a *behavioural system*: which contracts exist and how they relate, what every
externally reachable function reads / writes / calls / emits, which roles gate
which state transitions (derived from actual access-control behaviour, never
from a name), what assets move, which external dependencies are trusted, and the
state-machine relationships between actions (deposit -> shares, borrow -> debt,
...). Every later phase - invariant discovery, sequence planning, counterfactual
mutation, the reproducer - reads this model.

It is built from a Slither compilation. A compile failure produces
`ProtocolModel(compiled=False, reason=...)`; the model is never guessed. This is
the same discipline as `src/nextgen/_solc.py` and the classic scanner's
coverage block: UNMEASURED is reported as UNMEASURED, not as SAFE.

Reuses:
  * `src.nextgen.attackgraph._classify_contract` for the structural contract
    kind (PROXY / ORACLE / VAULT / POOL / TOKEN / ...).
  * `src.rules._shared` for the guard primitives (`constrains_msg_sender`,
    `guard_nodes`, `node_depends_on_msg_sender`, `reachable`) so a role here
    means exactly what a "guard" means to the classic rules and to the
    `src/nextgen` invariant engine.

Nothing here decides anything. It is a structured description.
"""

from __future__ import annotations

import re
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

# --------------------------------------------------------------------------- #
# vocabulary
# --------------------------------------------------------------------------- #

# contract kinds - superset of attackgraph's, plus the pure structural ones
CONTRACT = "CONTRACT"
PROXY = "PROXY"
IMPLEMENTATION = "IMPLEMENTATION"
LIBRARY = "LIBRARY"
INTERFACE = "INTERFACE"
TOKEN = "TOKEN"
VAULT = "VAULT"
POOL = "POOL"
ORACLE = "ORACLE"
BRIDGE = "BRIDGE"
GOVERNANCE = "GOVERNANCE"

# asset kinds
ETH = "ETH"
ERC20 = "ERC20"
ERC721 = "ERC721"
ERC1155 = "ERC1155"
ERC4626 = "ERC4626"
LP = "LP"
SHARES = "SHARES"
DEBT = "DEBT"
WRAPPED = "WRAPPED"
PROTOCOL_BALANCE = "PROTOCOL_BALANCE"

# dependency kinds
DEP_ORACLE = "ORACLE"
DEP_ROUTER = "ROUTER"
DEP_AMM = "AMM"
DEP_LENDING = "LENDING"
DEP_BRIDGE = "BRIDGE"
DEP_CALLBACK = "CALLBACK"
DEP_STAKING = "STAKING"
DEP_EXTERNAL = "EXTERNAL"

# state-machine relation kinds
REL_DEPOSIT_SHARES = "DEPOSIT_SHARES"
REL_WITHDRAW_ASSET = "WITHDRAW_ASSET"
REL_BORROW_DEBT = "BORROW_DEBT"
REL_REPAY_DEBT = "REPAY_DEBT"
REL_LIQUIDATE_COLLATERAL = "LIQUIDATE_COLLATERAL"
REL_STAKE_REWARDS = "STAKE_REWARDS"
REL_CLAIM_REWARD = "CLAIM_REWARD"
REL_MINT_BURN = "MINT_BURN"

# --------------------------------------------------------------------------- #
# name / hint tables (lowercase, matched as substrings unless noted)
# --------------------------------------------------------------------------- #

_ORACLE_METHODS = ("latestanswer", "latestrounddata", "getprice", "consult",
                   "getamountout", "getamountsout", "price0cumulativelast",
                   "price1cumulativelast", "peek", "read", "getreserves",
                   "quote", "quoterouted", "current", "getrate",
                   "getunderlyingprice", "exchangerate", "getpriceusd")
_AMM_METHODS = ("swapexacttokens", "swaptokensfor", "swapexacteth", "swap",
                "getamountsout", "getamountout", "getreserves", "addliquidity",
                "removeliquidity", "quote", "consult", "sync", "skim")
_LENDING_METHODS = ("borrow", "repayborrow", "repay", "redeemunderlying",
                    "liquidateborrow", "flashloan", "flash", "mint", "redeem")
_BRIDGE_METHODS = ("relaymessage", "finalizedeposit", "finalizewithdrawal",
                   "processmessage", "receivemessage", "sendmessage",
                   "_executemessage", "outboundtransfer", "depositfor")
_CALLBACK_NAMES = ("onerc721received", "onerc1155received", "onerc1155batchreceived",
                   "tokensreceived", "uniswapv2call", "pancakecall", "hook",
                   "callback", "receiveflashloan", "executeoperation",
                   "onflashloan", "uniswapv3swapcallback", "beforetokentransfer",
                   "aftertokentransfer", "flashloancallback")
_TRANSFER_METHODS = ("transfer", "transferfrom", "safetransfer",
                     "safetransferfrom", "_transfer", "senderc20", "withdrawto")
_UPGRADE_NAMES = ("upgradeto", "upgradetoandcall", "_authorizeupgrade",
                  "changeadmin", "changeproxyadmin", "setimplementation")

_ROLE_HINT = re.compile(
    r"(ROLE|_ADMIN|ADMIN_|OWNER|GOVERNAN|MINTER|PAUSER|BURNER|KEEPER|OPERATOR|"
    r"GUARDIAN|LIQUIDATOR|UPGRADER|authoriz|whitelist|allowlist|_MANAGER)", re.I)

# an auth-looking modifier name (onlyOwner, onlyRole, requiresAuth, isAdmin, ...)
_AUTH_MOD_RE = re.compile(r"^(only|is|has|require[sd]?|auth|restricted|"
                          r"permissioned|gated|when)", re.I)
# a call inside a guard that IS an authorization check
_AUTH_CALL_NAMES = ("hasrole", "_checkrole", "checkrole", "isowner", "isadmin",
                    "isauthorized", "cancall", "requiresauth", "_onlyrole",
                    "onlyrole", "authorized", "checkowner", "_checkowner")
# a role/allowlist mapping whose [msg.sender] lookup gates a call
_AUTH_MAP_HINT = ("role", "auth", "whitelist", "allowlist", "admin", "operator",
                  "manager", "minter", "pauser", "keeper", "guardian",
                  "permitted", "approvedcaller", "cansend", "cancall")
_MSG_SENDER_CMP = re.compile(r"msg\.sender\s*[!=]=|[!=]=\s*msg\.sender")

_ACCOUNTING_VARS = ("shares", "totalassets", "totalshares", "reserve", "reserves",
                    "debt", "borrow", "collateral", "principal", "liquidity",
                    "pricepershare", "exchangerate", "totalsupply", "_balances",
                    "totaldebt", "totalborrow", "index", "accrued")
_ACCESS_VARS = ("owner", "admin", "role", "implementation", "authorized",
                "pendingowner", "paused", "governance", "guardian", "operator",
                "minter", "pauser")
_NONCE_VARS = ("nonce", "nonces", "used", "processed", "executed", "consumed",
               "seen", "claimed", "filled", "spent")
_SUPPLY_VARS = ("totalsupply", "_totalsupply", "_balances", "balances")


# --------------------------------------------------------------------------- #
# data types
# --------------------------------------------------------------------------- #

@dataclass
class ParamSpec:
    name: str
    type: str

    def as_dict(self) -> dict:
        return {"name": self.name, "type": self.type}


@dataclass
class FunctionModel:
    contract: str
    name: str
    signature: str                     # canonical ABI, e.g. "withdraw(uint256)"
    selector: str                      # "0x2e1a7d4d" or "" if unresolvable
    visibility: str
    mutability: str                    # pure / view / nonpayable / payable
    payable: bool = False
    modifiers: tuple[str, ...] = ()
    params: tuple[ParamSpec, ...] = ()
    returns: tuple[str, ...] = ()
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    external_calls: tuple[str, ...] = ()
    internal_calls: tuple[str, ...] = ()
    events: tuple[str, ...] = ()
    guarded: bool = False              # BROAD: control flow touches msg.sender
                                       # (== attackgraph's `guarded`, _shared)
    access_controlled: bool = False    # SHARP: restricts the CALLER's identity
                                       # (role modifier / msg.sender == owner /
                                       # role-mapping lookup) - what spec 5.F
                                       # cares about
    sends_eth: bool = False
    risk: int = 0
    risk_factors: tuple[str, ...] = ()
    # The function's own Solidity source. Needed by oracles that must inspect
    # an EXPRESSION rather than a fact Slither already summarises - notably the
    # signature-scope check (spec 5.H), which has to know what went INTO a
    # `keccak256(abi.encode(...))` preimage. Never used for detection of
    # anything Slither can answer structurally. "" when unavailable.
    source: str = ""

    @property
    def external(self) -> bool:
        return self.visibility in ("external", "public")

    @property
    def state_changing(self) -> bool:
        return bool(self.writes) or self.sends_eth or self.mutability == "payable"

    def as_dict(self) -> dict:
        return {"contract": self.contract, "name": self.name,
                "signature": self.signature, "selector": self.selector,
                "visibility": self.visibility, "mutability": self.mutability,
                "payable": self.payable, "modifiers": list(self.modifiers),
                "params": [p.as_dict() for p in self.params],
                "returns": list(self.returns), "reads": list(self.reads),
                "writes": list(self.writes),
                "external_calls": list(self.external_calls),
                "internal_calls": list(self.internal_calls),
                "events": list(self.events), "guarded": self.guarded,
                "access_controlled": self.access_controlled,
                "sends_eth": self.sends_eth, "risk": self.risk,
                "risk_factors": list(self.risk_factors)}


@dataclass
class ContractModel:
    name: str
    kind: str
    is_target: bool = False
    inherits: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    state_vars: tuple[tuple[str, str], ...] = ()      # (name, type)
    public_getters: tuple[str, ...] = ()             # public/external state vars
                                                     # -> implicit getter names
    functions: tuple[FunctionModel, ...] = ()

    def callable_names(self) -> set[str]:
        """Every name reachable as an external call: real functions + the
        implicit getters Slither does not synthesise into `functions`."""
        return ({f.name.lower() for f in self.functions}
                | {g.lower() for g in self.public_getters})

    def as_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "is_target": self.is_target,
                "inherits": list(self.inherits), "libraries": list(self.libraries),
                "state_vars": [list(v) for v in self.state_vars],
                "public_getters": list(self.public_getters),
                "functions": [f.as_dict() for f in self.functions]}


@dataclass
class RoleModel:
    name: str                          # descriptive, e.g. "gate on owner"
    kind: str                          # OWNER / ADMIN / ROLE / CUSTOM
    guard_vars: tuple[str, ...] = ()
    modifiers: tuple[str, ...] = ()
    gated_functions: tuple[str, ...] = ()     # "Contract.fn"

    def as_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind,
                "guard_vars": list(self.guard_vars),
                "modifiers": list(self.modifiers),
                "gated_functions": list(self.gated_functions)}


@dataclass
class AssetModel:
    kind: str
    label: str
    contract: str = ""                 # the in-unit contract that embodies it
    accounting_vars: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"kind": self.kind, "label": self.label, "contract": self.contract,
                "accounting_vars": list(self.accounting_vars)}


@dataclass
class DependencyModel:
    kind: str
    hint: str                          # the method / name that revealed it
    consumed_by: tuple[str, ...] = ()  # "Contract.fn"
    return_checked: Optional[bool] = None   # oracle only: freshness/round check present

    def as_dict(self) -> dict:
        return {"kind": self.kind, "hint": self.hint,
                "consumed_by": list(self.consumed_by),
                "return_checked": self.return_checked}


@dataclass
class RelationModel:
    kind: str
    function: str                      # "Contract.fn"
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"kind": self.kind, "function": self.function,
                "inputs": list(self.inputs), "outputs": list(self.outputs)}


@dataclass
class ProtocolModel:
    compiled: bool
    reason: str = ""
    target_contract: str = ""
    contracts: tuple[ContractModel, ...] = ()
    roles: tuple[RoleModel, ...] = ()
    assets: tuple[AssetModel, ...] = ()
    dependencies: tuple[DependencyModel, ...] = ()
    relations: tuple[RelationModel, ...] = ()

    # -- lookups -------------------------------------------------------------- #

    def contract(self, name: str) -> Optional[ContractModel]:
        for c in self.contracts:
            if c.name == name:
                return c
        return None

    def function(self, contract: str, name: str) -> Optional[FunctionModel]:
        c = self.contract(contract)
        if c is None:
            return None
        for f in c.functions:
            if f.name == name:
                return f
        return None

    def all_functions(self) -> list[FunctionModel]:
        return [f for c in self.contracts for f in c.functions]

    def external_functions(self) -> list[FunctionModel]:
        return [f for f in self.all_functions() if f.external]

    def ranked_functions(self) -> list[FunctionModel]:
        """External functions, most security-relevant first (spec section 21)."""
        return sorted(self.external_functions(),
                      key=lambda f: (-f.risk, f.contract, f.name))

    def target(self) -> Optional[ContractModel]:
        for c in self.contracts:
            if c.is_target:
                return c
        cands = [c for c in self.contracts
                 if c.kind not in (INTERFACE, LIBRARY)]
        return max(cands, key=lambda c: len(c.functions), default=None)

    def as_dict(self) -> dict:
        return {"compiled": self.compiled, "reason": self.reason,
                "target_contract": self.target_contract,
                "contracts": [c.as_dict() for c in self.contracts],
                "roles": [r.as_dict() for r in self.roles],
                "assets": [a.as_dict() for a in self.assets],
                "dependencies": [d.as_dict() for d in self.dependencies],
                "relations": [r.as_dict() for r in self.relations]}

    def coverage(self) -> dict:
        """Numbers for the spec section 28 dashboard."""
        fns = self.all_functions()
        return {"contracts_modeled": len(self.contracts),
                "functions_modeled": len(fns),
                "external_functions": len(self.external_functions()),
                "roles": len(self.roles), "assets": len(self.assets),
                "dependencies": len(self.dependencies),
                "state_relations": len(self.relations)}


# --------------------------------------------------------------------------- #
# building
# --------------------------------------------------------------------------- #

def build_from_sources(src: Union[str, dict, Path], *,
                       target: str = "",
                       compiler_version: str = "") -> ProtocolModel:
    """Compile `src` then model it.

    `src` may be a single self-contained source string, a `{path: content}`
    mapping (the Etherscan multi-file shape), or a directory Path. A compile
    failure returns `ProtocolModel(compiled=False, reason=...)`.

    `compiler_version` (bare semver, e.g. "0.8.19") pins the compiler for the
    whole attempt when it is installed - the verified deployment's own solc,
    from Sourcify/Etherscan. It suppresses the multi-solc fallback fan-out,
    which is the dominant cost on a large uncompilable bundle.
    """
    try:
        slither_obj = _compile_any(src, target, compiler_version=compiler_version)
    except Exception as exc:  # noqa: BLE001 - any compile failure is "unmeasured"
        return ProtocolModel(compiled=False,
                             reason=f"{type(exc).__name__}: {exc}"[:400],
                             target_contract=target)
    try:
        return build_model(slither_obj, target=target)
    except Exception as exc:  # noqa: BLE001
        return ProtocolModel(compiled=False,
                             reason=f"model build failed: {type(exc).__name__}: {exc}"[:400],
                             target_contract=target)


def compile_source(src: Union[str, dict, Path], *, target: str = "",
                   compiler_version: str = ""):
    """Compile `src` and return the raw Slither object (or raise). The orchestrator
    uses this once and shares it with the attack-graph / compensating-control
    analyzers so the source is parsed a single time."""
    return _compile_any(src, target, compiler_version=compiler_version)


def build_model(slither_obj, *, target: str = "") -> ProtocolModel:
    """Model an already-compiled Slither object."""
    from src.rules import _shared
    from src.nextgen.attackgraph import _classify_contract

    contracts_raw = [
        c for c in getattr(slither_obj, "contracts_derived", slither_obj.contracts)
        if not _is_test_contract(c)
    ]
    if not contracts_raw:
        return ProtocolModel(compiled=False, reason="no non-test contracts",
                             target_contract=target)

    # decide the target contract
    target_name = target
    if not target_name:
        non_iface = [c for c in contracts_raw
                     if not getattr(c, "is_interface", False)
                     and not getattr(c, "is_library", False)]
        pick = max(non_iface or contracts_raw,
                   key=lambda c: len(list(c.functions)), default=None)
        target_name = pick.name if pick else ""

    cmodels: list[ContractModel] = []
    for c in contracts_raw:
        kind = _contract_kind(c, _classify_contract)
        fns: list[FunctionModel] = []
        for fn in _model_functions(c):
            fm = _model_function(fn, c, kind, _shared)
            fns.append(fm)
        getters = tuple(getattr(v, "name", "") or ""
                        for v in getattr(c, "state_variables", []) or ()
                        if getattr(v, "visibility", "") in ("public", "external")
                        and (getattr(v, "name", "") or ""))
        cmodels.append(ContractModel(
            name=c.name, kind=kind, is_target=(c.name == target_name),
            inherits=tuple(b.name for b in getattr(c, "inheritance", []) or ()),
            libraries=tuple(sorted(_libraries(c))),
            state_vars=tuple((getattr(v, "name", "") or "",
                              str(getattr(v, "type", "")))
                             for v in getattr(c, "state_variables", []) or ()),
            public_getters=getters,
            functions=tuple(fns)))

    roles = _derive_roles(contracts_raw, _shared)
    assets = _derive_assets(cmodels)
    deps = _derive_dependencies(cmodels)
    relations = _derive_relations(cmodels)

    return ProtocolModel(compiled=True, target_contract=target_name,
                         contracts=tuple(cmodels), roles=tuple(roles),
                         assets=tuple(assets), dependencies=tuple(deps),
                         relations=tuple(relations))


# --------------------------------------------------------------------------- #
# compilation glue
# --------------------------------------------------------------------------- #

# A big multi-file Etherscan bundle can hold 100+ `.sol` files. Trying each one
# as a compile entry - and letting every failure fan out over ~20 installed solc
# versions - is where a run's wall time actually goes (measured: 300-600s on a
# single uncompilable case). Try only the few most promising entries.
_MAX_COMPILE_ENTRIES = 4

# path fragments that mark a vendored dependency: never a plausible target entry.
_VENDOR_SEGMENTS = ("node_modules/", "/lib/", "@openzeppelin/", "@uniswap/",
                    "@chainlink/", "solmate/", "forge-std/", "ds-test/",
                    "/interfaces/", "/mocks/")


def _bare_semver(v: str) -> str:
    m = re.match(r"\s*v?(\d+\.\d+\.\d+)", str(v or ""))
    return m.group(1) if m else ""


def _compile_any(src: Union[str, dict, Path], target: str,
                 *, compiler_version: str = ""):
    if isinstance(src, str) and "\n" in src and "pragma" in src:
        from .._solc import slither_for_source
        return slither_for_source(src)
    return _compile_tree(src, target, compiler_version=compiler_version)


def _compile_tree(src: Union[dict, str, Path], target: str,
                  *, compiler_version: str = ""):
    """Write a `{path: content}` bundle (or use a dir), then compile the most
    promising entry `.sol` with the classic engine's own `_shared.parse` (same
    solc fallback + remap handling as every rule). Returns the first Slither
    object that carries `target` (or the first that carries anything).

    Bounded: at most `_MAX_COMPILE_ENTRIES` entry files are tried, and when
    `compiler_version` names an installed solc it is pinned for the whole
    attempt so `_shared.parse` never fans out over every other version.
    """
    import os

    from src.rules import _shared

    if isinstance(src, dict):
        root = (Path(tempfile.gettempdir()) / "chainwatch-deephunt-src"
                / uuid.uuid4().hex)
        for rel, content in src.items():
            p = root / str(rel).lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        _materialize_imports(root)
        bundle = True
    else:
        root = Path(src)
        bundle = False
    if not root.exists():
        raise RuntimeError(f"source root does not exist: {root}")

    sols = [s for s in sorted(root.rglob("*.sol"))
            if not _shared.is_test_path_segments(str(s))]
    if not sols:
        raise RuntimeError("no .sol files under the source root")

    # rank entries: a file named like the target first, then non-vendored files
    # nobody imports (roots), then the biggest. Vendored files sink to last.
    imported = _imported_basenames(sols)

    def _is_vendor(p: Path) -> bool:
        rp = p.as_posix().lower()
        return any(seg in rp for seg in _VENDOR_SEGMENTS)

    def rank(p: Path):
        return (0 if (target and p.stem == target) else 1,
                1 if _is_vendor(p) else 0,
                1 if p.name in imported else 0,
                -p.stat().st_size)

    ordered = sorted(sols, key=rank)
    # if a file literally declares `contract <target>`, that is the only entry
    # worth trying - a large bundle's other 100 files are its dependencies.
    if target:
        decl = re.compile(rf"\b(contract|library|abstract\s+contract)\s+"
                          rf"{re.escape(target)}\b")
        named = [p for p in ordered
                 if _safe_read(p) and decl.search(_safe_read(p))]
        if named:
            ordered = named + [p for p in ordered if p not in named]
    entries = ordered[:_MAX_COMPILE_ENTRIES]

    pin = _bare_semver(compiler_version)
    saved = os.environ.get("SOLC_VERSION")
    if pin:
        try:
            from solc_select.solc_select import installed_versions
            if pin not in set(installed_versions()):
                pin = ""
        except Exception:  # noqa: BLE001 - solc-select absent: don't pin
            pin = ""
    if pin:
        os.environ["SOLC_VERSION"] = pin
    # `_shared.remaps_for` emits the npm convention as a RELATIVE remap
    # (`@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/`), which
    # solc resolves against its working directory. For a bundle WE wrote, run
    # from inside it so that resolves to the copies `_materialize_imports` just
    # made. Only for a bundle: a caller-supplied directory already sits in its
    # own project layout, and moving the cwd would break the relative paths
    # that layout depends on. Restored in `finally`, like RepoContext does for
    # the process-global build state.
    prev_cwd = None
    if bundle:
        try:
            prev_cwd = os.getcwd()
            os.chdir(root)
        except OSError:
            prev_cwd = None
    try:
        last_err: Optional[Exception] = None
        for entry in entries:
            try:
                _shared.reset_caches()
                sl = _shared.parse(entry)
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                continue
            names = {c.name
                     for c in getattr(sl, "contracts_derived", sl.contracts)}
            if not target or target in names:
                return sl
            last_err = RuntimeError(
                f"{entry.name} compiled but declares no contract {target!r}")
        raise last_err or RuntimeError("no entry file compiled")
    finally:
        if prev_cwd is not None:
            try:
                os.chdir(prev_cwd)
            except OSError:
                pass
        if pin:
            if saved is None:
                os.environ.pop("SOLC_VERSION", None)
            else:
                os.environ["SOLC_VERSION"] = saved


def _safe_read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


_IMPORT_RE = re.compile(
    r"""import\s+(?:[^"';]*?\s+from\s+)?["']([^"']+)["']""")


def _materialize_imports(root: Path, *, max_writes: int = 400) -> int:
    """Satisfy non-relative imports using the bundle's OWN files.

    A verified-source bundle (Sourcify / Etherscan) keeps each file under the
    key the verifier chose, but the Solidity inside still imports by the path
    the ORIGINAL build used. Those two disagree constantly, e.g. veth ships

        lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol

    while its source says

        import "node_modules/@openzeppelin/contracts/utils/ReentrancyGuard.sol";

    solc then cannot find the file and the whole bundle is unanalysable - which
    was the single largest cause of "did not compile" on DVBench, bigger than
    any solc-version issue.

    The fix copies a file the bundle ALREADY CONTAINS to the path its own code
    asks for, matching on the longest common path suffix. Nothing is downloaded
    and nothing is substituted from another project: every byte still comes
    from the verified source of the contract under analysis, so this can only
    turn "no analysis" into "analysis", never change what the analysis sees.
    An import with no suffix match in the bundle is left unresolved - the
    compile then fails honestly rather than against a guessed dependency.

    Returns the number of files written.
    """
    import posixpath

    # Index the ORIGINAL bundle by every path suffix, once. Copies made below
    # are never added, so a copy can never become the source of another copy.
    by_suffix: dict[str, Path] = {}
    for p in sorted(root.rglob("*.sol")):
        parts = p.relative_to(root).as_posix().split("/")
        for i in range(len(parts)):
            by_suffix.setdefault("/".join(parts[i:]), p)

    def _find(rel: str):
        parts = rel.split("/")
        return next((by_suffix["/".join(parts[i:])]
                     for i in range(len(parts))
                     if "/".join(parts[i:]) in by_suffix), None)

    written = 0
    # Fixed point: a file copied to a new location brings its own imports with
    # it, and those are usually RELATIVE - so they must resolve at the new
    # location too. Each round resolves one more level of that closure.
    for _ in range(8):
        wanted: set[str] = set()
        for p in list(root.rglob("*.sol")):
            base = p.parent.relative_to(root).as_posix()
            for m in _IMPORT_RE.finditer(_safe_read(p)):
                tgt = m.group(1)
                if tgt.startswith("."):
                    rel = posixpath.normpath(posixpath.join(base, tgt))
                else:
                    rel = tgt.lstrip("/")
                if rel.startswith(".."):
                    continue                  # escapes the bundle: unresolvable
                wanted.add(rel)
        # `_shared.remaps_for` applies the npm convention (`@scope/` ->
        # `node_modules/@scope/`), so a scoped import reaches solc as
        # `node_modules/@scope/...`. Provide both spellings.
        for w in list(wanted):
            if w.startswith("@"):
                wanted.add("node_modules/" + w)
            elif w.startswith("node_modules/"):
                wanted.add(w[len("node_modules/"):])

        new = 0
        for want in sorted(wanted):
            if written >= max_writes:
                break
            dest = root / want
            if dest.exists():
                continue
            srcp = _find(want)
            if srcp is None:
                continue                      # not in the bundle: leave it
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(_safe_read(srcp), encoding="utf-8")
                written += 1
                new += 1
            except OSError:
                continue
        if not new:
            break
    return written


def _imported_basenames(sols: list[Path]) -> set[str]:
    pat = re.compile(r"""import\s+(?:[^"';]*?\s+from\s+)?["']([^"']+)["']""")
    out: set[str] = set()
    for s in sols:
        try:
            text = s.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in pat.finditer(text):
            out.add(Path(m.group(1)).name)
    return out


# --------------------------------------------------------------------------- #
# function modelling
# --------------------------------------------------------------------------- #

def _model_functions(contract):
    for fn in contract.functions:
        if getattr(fn, "is_constructor", False):
            continue
        if not getattr(fn, "is_implemented", True):
            continue
        if getattr(fn, "is_shadowed", False):
            continue
        if (getattr(fn, "name", "") or "").startswith("slither"):
            continue
        yield fn


def _model_function(fn, contract, contract_kind: str, _shared) -> FunctionModel:
    sig, selector = _sig_and_selector(fn)
    ext_calls, int_calls, events = _calls_and_events(fn, _shared)
    reads = tuple(sorted({getattr(v, "name", "") or ""
                          for v in _safe(fn.all_state_variables_read) or []} - {""}))
    writes = tuple(sorted({getattr(v, "name", "") or ""
                           for v in _safe(fn.all_state_variables_written) or []} - {""}))
    payable = bool(getattr(fn, "payable", False))
    mutability = ("payable" if payable else
                  "view" if getattr(fn, "view", False) else
                  "pure" if getattr(fn, "pure", False) else "nonpayable")
    guarded = False
    try:
        guarded = _shared.constrains_msg_sender(fn, contract)
    except Exception:  # noqa: BLE001
        guarded = False
    access_controlled = _access_controlled(fn, contract, _shared)
    sends_eth = bool(_safe(fn.can_send_eth))

    fm = FunctionModel(
        contract=contract.name, name=fn.name or "", signature=sig,
        selector=selector, visibility=getattr(fn, "visibility", "") or "",
        mutability=mutability, payable=payable,
        modifiers=tuple(getattr(m, "name", "?") for m in getattr(fn, "modifiers", []) or ()),
        params=tuple(ParamSpec(getattr(p, "name", "") or "",
                               str(getattr(p, "type", "")))
                     for p in getattr(fn, "parameters", []) or ()),
        returns=tuple(str(t) for t in (getattr(fn, "return_type", None) or ())),
        reads=reads, writes=writes, external_calls=ext_calls,
        internal_calls=int_calls, events=events, guarded=guarded,
        access_controlled=access_controlled, sends_eth=sends_eth,
        source=_function_source(fn))
    fm.risk, fm.risk_factors = _risk_score(fm, contract_kind)
    return fm


def _function_source(fn) -> str:
    """The function's own Solidity text, or "". Best-effort and never raises:
    an oracle that needs it degrades to "not checkable" without it."""
    try:
        sm = getattr(fn, "source_mapping", None)
        txt = getattr(sm, "content", None)
        if isinstance(txt, str) and txt.strip():
            return txt
    except Exception:  # noqa: BLE001
        pass
    return ""


def _access_controlled(fn, contract, _shared) -> bool:
    """SHARP: does the function restrict WHO may call it?

    True when a role-shaped modifier constrains msg.sender, or a reachable guard
    compares msg.sender (or a msg.sender-dependent value) for identity, or a
    role/allowlist mapping keyed by msg.sender gates the call, or a known
    authorization call (`hasRole`, `_checkRole`, ...) sits in a guard.

    Deliberately NOT true for `require(balances[msg.sender] >= x)` - a balance
    check restricts the AMOUNT, not the CALLER, and misreading it as
    authorization would suppress a real access-control finding (spec 5.F).
    """
    try:
        reach = _shared.reachable(fn)
    except Exception:  # noqa: BLE001
        reach = [fn]

    for m in getattr(fn, "modifiers", []) or []:
        mn = getattr(m, "name", "") or ""
        if _AUTH_MOD_RE.match(mn):
            try:
                if _shared.constrains_msg_sender(m, contract):
                    return True
            except Exception:  # noqa: BLE001
                pass

    try:
        from slither.slithir.operations import (
            Binary, SolidityCall, HighLevelCall, InternalCall, LibraryCall,
        )
    except Exception:  # noqa: BLE001
        Binary = SolidityCall = HighLevelCall = InternalCall = LibraryCall = ()

    for f in reach:
        try:
            gnodes = list(_shared.guard_nodes(f))
        except Exception:  # noqa: BLE001
            continue
        for node in gnodes:
            expr = str(getattr(node, "expression", "") or "")
            if _MSG_SENDER_CMP.search(expr):
                return True
            low = expr.lower().replace(" ", "")
            if "[msg.sender]" in low and any(h in low for h in _AUTH_MAP_HINT):
                return True
            for ir in getattr(node, "irs", []) or []:
                if Binary and isinstance(ir, Binary):
                    tname = str(getattr(ir, "type", "")).upper()
                    if ("EQUAL" in tname) and any(
                            str(x) == "msg.sender" for x in getattr(ir, "read", [])):
                        return True
                if (SolidityCall or HighLevelCall) and isinstance(
                        ir, (SolidityCall, HighLevelCall, InternalCall, LibraryCall)):
                    nm = (getattr(ir, "function_name", None)
                          or getattr(getattr(ir, "function", None), "name", "")
                          or "")
                    if str(nm).lower() in _AUTH_CALL_NAMES:
                        try:
                            if _shared.node_depends_on_msg_sender(node, contract):
                                return True
                        except Exception:  # noqa: BLE001
                            return True
    return False


def _sig_and_selector(fn) -> tuple[str, str]:
    sig = ""
    for attr in ("solidity_signature", "full_name"):
        try:
            v = getattr(fn, attr, "") or ""
        except Exception:  # noqa: BLE001 - struct params can raise
            v = ""
        if v:
            sig = v
            break
    if not sig:
        sig = f"{getattr(fn, 'name', 'fn')}()"
    sig = sig.replace(" ", "")
    selector = ""
    if "(" in sig and sig.endswith(")"):
        try:
            from eth_utils import function_signature_to_4byte_selector
            selector = "0x" + function_signature_to_4byte_selector(sig).hex()
        except Exception:  # noqa: BLE001
            selector = ""
    return sig, selector


def _calls_and_events(fn, _shared) -> tuple[tuple[str, ...], tuple[str, ...],
                                            tuple[str, ...]]:
    """Calls and events made by `fn` OR by any function it transitively calls
    internally (via `_shared.reachable`, which follows internal / library calls
    and modifiers). A price read one helper-hop away from a state-changing entry
    point still counts as that entry point reading a price."""
    ext: list[str] = []
    internal: list[str] = []
    events: list[str] = []
    try:
        from slither.slithir.operations import (
            EventCall, HighLevelCall, LowLevelCall, LibraryCall, InternalCall,
        )
    except Exception:  # noqa: BLE001
        return (), (), ()
    try:
        funcs = _shared.reachable(fn)
    except Exception:  # noqa: BLE001
        funcs = [fn]
    for f in funcs:
        for node in getattr(f, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                if isinstance(ir, EventCall):
                    nm = str(getattr(ir, "name", "") or "").strip()
                    if nm:
                        events.append(nm)
                elif isinstance(ir, LibraryCall):
                    m = (getattr(ir, "function_name", None)
                         or getattr(getattr(ir, "function", None), "name", None))
                    d = _short_dest(getattr(ir, "destination", None))
                    ext.append(f"{d}.{m}" if (d and m) else (str(m) if m else d))
                elif isinstance(ir, HighLevelCall):
                    m = (getattr(ir, "function_name", None)
                         or getattr(getattr(ir, "function", None), "name", None))
                    d = _short_dest(getattr(ir, "destination", None))
                    ext.append(f"{d}.{m}" if (d and m)
                               else f"{d}.<call>" if d else str(m))
                elif isinstance(ir, LowLevelCall):
                    m = str(getattr(ir, "function_name", "") or "call")
                    ext.append(f"<low-level:{m}>")
                elif isinstance(ir, InternalCall):
                    nm = getattr(getattr(ir, "function", None), "name", None)
                    if nm and nm != getattr(fn, "name", None):
                        internal.append(str(nm))
    return _uniq(ext), _uniq(internal), _uniq(events)


def _short_dest(dest) -> str:
    if dest is None:
        return ""
    return str(dest).split("(", 1)[0].strip()


# --------------------------------------------------------------------------- #
# risk score (spec section 21)
# --------------------------------------------------------------------------- #

def _risk_score(fm: FunctionModel, contract_kind: str) -> tuple[int, tuple[str, ...]]:
    if not fm.external:
        return 0, ()
    name = fm.name.lower()
    calls = " ".join(fm.external_calls).lower()
    writes = {w.lower() for w in fm.writes}
    reads = {r.lower() for r in fm.reads}
    score = 0
    why: list[str] = []

    def add(pts: int, tag: str) -> None:
        nonlocal score
        score += pts
        why.append(f"+{pts} {tag}")

    if "liquidat" in name:
        add(3, "liquidation")
    if name.startswith(("withdraw", "redeem")):
        add(2, "withdrawal")
    if name.startswith("claim"):
        add(2, "claim / reward payout")
    if name.startswith("borrow"):
        add(2, "borrow")
    if any(u in name for u in _UPGRADE_NAMES):
        add(3, "upgradeability")
    if name in _CALLBACK_NAMES or "callback" in name or name.endswith("call"):
        add(2, "callback / hook entry point")
    if fm.sends_eth:
        add(3, "sends ETH")
    if any(t in calls for t in (".transfer", ".transferfrom", ".safetransfer")):
        add(3, "moves ERC20 value")
    if writes & set(_SUPPLY_VARS) and (name in ("mint", "burn", "_mint", "_burn")
                                       or {"totalsupply", "_totalsupply"} & writes):
        add(3, "mint / burn supply accounting")
    if any(a in w for w in writes for a in _ACCOUNTING_VARS):
        add(3, "writes core accounting state")
    if any(o in calls for o in _ORACLE_METHODS):
        add(3, "reads a price oracle")
    if any(a in calls for a in ("getreserves", "getamountsout", "getamountout",
                                "swap", "quote", "consult")):
        add(2, "AMM interaction")
    if "<low-level:delegatecall>" in calls:
        add(3, "delegatecall")
    if any(a in w for w in writes for a in _ACCESS_VARS):
        add(2, "changes authorization / privileged state")
    if any(n in x for x in (writes | reads) for n in _NONCE_VARS):
        add(1, "nonce / replay slot")
    if any(b in name or b in calls for b in _BRIDGE_METHODS):
        add(2, "bridge message")
    if fm.external_calls:
        add(1, "external protocol dependency")
    if fm.payable:
        add(1, "payable")
    if not fm.access_controlled and fm.state_changing:
        add(2, "no caller-identity guard on a state mutation")
    if contract_kind in (VAULT, POOL) and fm.state_changing:
        add(1, f"state-changing entry on a {contract_kind.lower()}")

    return score, tuple(why)


# --------------------------------------------------------------------------- #
# roles - from access-control BEHAVIOUR, not names (spec section 3)
# --------------------------------------------------------------------------- #

def _derive_roles(contracts, _shared) -> list[RoleModel]:
    buckets: dict[tuple, dict] = {}
    for c in contracts:
        for fn in _model_functions(c):
            if getattr(fn, "visibility", "") not in ("external", "public"):
                continue
            if not _access_controlled(fn, c, _shared):
                continue
            gvars = _guard_state_vars(fn, c, _shared)
            mods = tuple(sorted(getattr(m, "name", "?")
                                for m in getattr(fn, "modifiers", []) or ()))
            key = tuple(sorted(gvars)) or mods or ("<inline msg.sender check>",)
            b = buckets.setdefault(key, {"gvars": set(gvars), "mods": set(mods),
                                         "fns": []})
            b["gvars"] |= set(gvars)
            b["mods"] |= set(mods)
            b["fns"].append(f"{c.name}.{fn.name}")

    roles: list[RoleModel] = []
    for key, b in buckets.items():
        gvars = tuple(sorted(b["gvars"]))
        mods = tuple(sorted(b["mods"]))
        label_src = gvars or mods or key
        name = ("gate on " + ", ".join(gvars)) if gvars else \
               (", ".join(mods) if mods else "inline msg.sender gate")
        roles.append(RoleModel(name=name, kind=_role_kind(label_src),
                               guard_vars=gvars, modifiers=mods,
                               gated_functions=tuple(sorted(set(b["fns"])))))
    roles.sort(key=lambda r: (-len(r.gated_functions), r.name))
    return roles


def _guard_state_vars(fn, contract, _shared) -> set[str]:
    names: set[str] = set()
    try:
        reach = _shared.reachable(fn)
    except Exception:  # noqa: BLE001
        reach = [fn]
    for f in reach:
        try:
            gnodes = _shared.guard_nodes(f)
        except Exception:  # noqa: BLE001
            continue
        for node in gnodes:
            try:
                if not _shared.node_depends_on_msg_sender(node, contract):
                    continue
            except Exception:  # noqa: BLE001
                continue
            for v in getattr(node, "state_variables_read", []) or []:
                nm = getattr(v, "name", "") or ""
                if nm:
                    names.add(nm)
    return names


def _role_kind(tokens) -> str:
    joined = " ".join(str(t) for t in tokens).lower()
    if "owner" in joined:
        return "OWNER"
    if "admin" in joined or "proxyadmin" in joined:
        return "ADMIN"
    if any(t in joined for t in ("role", "minter", "pauser", "burner", "keeper",
                                 "operator", "guardian", "governance",
                                 "liquidator", "upgrader")):
        return "ROLE"
    return "CUSTOM"


# --------------------------------------------------------------------------- #
# assets
# --------------------------------------------------------------------------- #

def _derive_assets(cmodels: list[ContractModel]) -> list[AssetModel]:
    out: list[AssetModel] = []
    seen: set[tuple] = set()

    def push(a: AssetModel) -> None:
        k = (a.kind, a.contract)
        if k not in seen:
            seen.add(k)
            out.append(a)

    any_eth = False
    for c in cmodels:
        cn = c.callable_names()                 # functions + implicit getters
        vnames = {v[0].lower() for v in c.state_vars}
        for f in c.functions:
            if f.sends_eth or f.payable:
                any_eth = True

        has_supply = "totalsupply" in cn or "_totalsupply" in vnames
        has_balances = "_balances" in vnames or "balanceof" in cn \
            or "balances" in cn
        if "ownerof" in cn and "balanceof" in cn:
            push(AssetModel(ERC721, f"{c.name} (ERC721)", c.name))
        elif "balanceofbatch" in cn or "safebatchtransferfrom" in cn:
            push(AssetModel(ERC1155, f"{c.name} (ERC1155)", c.name))
        elif has_supply and has_balances:
            av = tuple(sorted({v[0] for v in c.state_vars
                               if v[0].lower() in _SUPPLY_VARS}))
            kind = WRAPPED if c.name.lower() in ("weth", "wbnb", "weth9",
                                                 "wmatic", "wavax") else ERC20
            push(AssetModel(kind, f"{c.name} token", c.name, av))

        if "asset" in cn and ("totalassets" in cn or "converttoshares" in cn
                              or "previewdeposit" in cn or "previewredeem" in cn):
            push(AssetModel(ERC4626, f"{c.name} (ERC4626 vault)", c.name,
                            ("totalAssets", "totalSupply")))

        share_vars = tuple(sorted({v[0] for v in c.state_vars
                                   if "shares" in v[0].lower()}))
        if share_vars:
            push(AssetModel(SHARES, f"{c.name} shares", c.name, share_vars))
        debt_vars = tuple(sorted({v[0] for v in c.state_vars
                                  if any(d in v[0].lower()
                                         for d in ("debt", "borrow", "principal"))}))
        if debt_vars:
            push(AssetModel(DEBT, f"{c.name} debt", c.name, debt_vars))
        if "getreserves" in cn or ("reserve0" in vnames and "reserve1" in vnames):
            push(AssetModel(LP, f"{c.name} LP", c.name))

        for f in c.functions:
            if any("balanceof(address(this))" in ec.lower().replace(" ", "")
                   for ec in f.external_calls):
                push(AssetModel(PROTOCOL_BALANCE,
                                f"{c.name} holds external token balances", c.name))
                break

    if any_eth:
        out.insert(0, AssetModel(ETH, "native ETH / gas token", ""))
    return out


# --------------------------------------------------------------------------- #
# external dependencies
# --------------------------------------------------------------------------- #

def _derive_dependencies(cmodels: list[ContractModel]) -> list[DependencyModel]:
    by_key: dict[tuple, DependencyModel] = {}

    def note(kind: str, hint: str, who: str, checked=None) -> None:
        key = (kind, hint)
        d = by_key.get(key)
        if d is None:
            d = DependencyModel(kind=kind, hint=hint, consumed_by=(),
                                return_checked=checked)
            by_key[key] = d
        d.consumed_by = tuple(sorted(set(d.consumed_by) | {who}))
        if checked is not None:
            d.return_checked = bool(d.return_checked) or checked

    for c in cmodels:
        for f in c.functions:
            who = f"{c.name}.{f.name}"
            body_reads_round = any(k in " ".join(f.reads).lower()
                                   for k in ("updatedat", "answeredinround",
                                             "roundid"))
            for ec in f.external_calls:
                low = ec.lower()
                method = low.split(".")[-1].strip("<>")
                if any(o in low for o in _ORACLE_METHODS):
                    checked = body_reads_round or ("latestrounddata" in low
                                                   and body_reads_round)
                    note(DEP_ORACLE, method, who, checked=checked)
                if any(a in low for a in _AMM_METHODS):
                    note(DEP_AMM, method, who)
                if any(l in low for l in ("swapexacttokens", "addliquidity",
                                          "removeliquidity")):
                    note(DEP_ROUTER, method, who)
                if any(l in low for l in _LENDING_METHODS) and "." in low:
                    note(DEP_LENDING, method, who)
                if any(b in low for b in _BRIDGE_METHODS):
                    note(DEP_BRIDGE, method, who)
                if "<low-level:" in low:
                    note(DEP_EXTERNAL, method or "call", who)
            if f.name.lower() in _CALLBACK_NAMES or "callback" in f.name.lower():
                note(DEP_CALLBACK, f.name, who)
    return sorted(by_key.values(), key=lambda d: (d.kind, d.hint))


# --------------------------------------------------------------------------- #
# state-machine relations
# --------------------------------------------------------------------------- #

def _derive_relations(cmodels: list[ContractModel]) -> list[RelationModel]:
    out: list[RelationModel] = []
    for c in cmodels:
        for f in c.functions:
            if not f.external:
                continue
            n = f.name.lower()
            who = f"{c.name}.{f.name}"
            w = {x.lower() for x in f.writes}
            moves_value = f.sends_eth or any(
                t in " ".join(f.external_calls).lower()
                for t in (".transfer", ".transferfrom", ".safetransfer"))
            hit_shares = any("shares" in x or "share" == x for x in w) \
                or any(x in ("balanceof", "_balances") for x in w)
            hit_debt = any(d in x for x in w for d in ("debt", "borrow", "principal"))

            if n.startswith(("deposit", "mint", "stake")) and (hit_shares or w):
                out.append(RelationModel(
                    REL_STAKE_REWARDS if n.startswith("stake") else REL_DEPOSIT_SHARES,
                    who, tuple(p.name for p in f.params),
                    tuple(sorted(w))[:6]))
            elif n.startswith(("withdraw", "redeem", "unstake")) and (moves_value or w):
                out.append(RelationModel(REL_WITHDRAW_ASSET, who,
                                         tuple(p.name for p in f.params),
                                         tuple(sorted(w))[:6]))
            elif n.startswith("borrow") and (hit_debt or w):
                out.append(RelationModel(REL_BORROW_DEBT, who,
                                         tuple(p.name for p in f.params),
                                         tuple(sorted(w))[:6]))
            elif n.startswith("repay") and (hit_debt or w):
                out.append(RelationModel(REL_REPAY_DEBT, who,
                                         tuple(p.name for p in f.params),
                                         tuple(sorted(w))[:6]))
            elif "liquidat" in n and (moves_value or w):
                out.append(RelationModel(REL_LIQUIDATE_COLLATERAL, who,
                                         tuple(p.name for p in f.params),
                                         tuple(sorted(w))[:6]))
            elif n.startswith("claim") and (moves_value or w):
                out.append(RelationModel(REL_CLAIM_REWARD, who,
                                         tuple(p.name for p in f.params),
                                         tuple(sorted(w))[:6]))
            elif n in ("mint", "burn", "_mint", "_burn") and \
                    (w & set(_SUPPLY_VARS)):
                out.append(RelationModel(REL_MINT_BURN, who,
                                         tuple(p.name for p in f.params),
                                         tuple(sorted(w))[:6]))
    return out


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def _contract_kind(c, classifier) -> str:
    if getattr(c, "is_interface", False):
        return INTERFACE
    if getattr(c, "is_library", False):
        return LIBRARY
    try:
        return classifier(c)
    except Exception:  # noqa: BLE001
        return CONTRACT


def _libraries(c) -> set[str]:
    """Library names this contract actually calls into. The robust signal is a
    LibraryCall IR op's destination, collected per function (`using X for Y`
    declarations are not consistently exposed across Slither versions)."""
    out: set[str] = set()
    for fn in getattr(c, "functions", []) or []:
        for node in getattr(fn, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                if ir.__class__.__name__ == "LibraryCall":
                    d = _short_dest(getattr(ir, "destination", None))
                    if d:
                        out.add(d)
    return out


def _is_test_contract(c) -> bool:
    from src.rules import _shared
    try:
        path = str(c.source_mapping.filename.absolute)
    except Exception:  # noqa: BLE001
        return False
    return _shared.is_test_path_segments(path)


def _safe(callable_):
    try:
        return callable_()
    except Exception:  # noqa: BLE001
        return None


def _uniq(seq) -> tuple[str, ...]:
    out: list[str] = []
    for x in seq:
        s = str(x)
        if s and s not in out:
            out.append(s)
    return tuple(out)
