"""Phase 11 - the blind DVBench harness (spec section 29).

Runs the Deep Hunt engine over a LOCAL checkout of
`github.com/Cecuro/defi-vuln-benchmark` (90 real DeFi exploits given as verified
Etherscan source + address + fork block), with each case's `reference_findings`
HIDDEN from the engine and used only for scoring.

Source-first: the harness runs Deep Hunt source-only (no fork) by default and
maps its `DeepFinding`s onto the benchmark's `AgentFinding` shape. Execution
grounding (a real fork replay) is opt-in via `fork=True` and only for the 31
Ethereum-mainnet cases (the one chain with an RPC in `.env`).

Scoring here is a DETERMINISTIC root-cause-overlap heuristic (shared function
names + significant keywords + focus-area alignment). The real DVBench uses an
LLM judge; this proxy is documented as approximate. It also reports the stricter
Chainwatch numbers: how many cases reached a reproduced violation, how many
reached CONFIRMED, and the section-27 CONFIRMED / false-positive ratio.

`ChainwatchAgent` (a `BaseAgent` subclass) is provided as a doc snippet
(`AGENT_SNIPPET`) for wiring the real LLM-judge score - it is NOT written into
the benchmark repo by this module.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import findings as F
from . import invariants as INV

# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #

def load_cases(checkout_dir: str, *, include_draft: bool = False) -> list[dict]:
    p = Path(checkout_dir) / "data" / "cases.jsonl"
    if not p.exists():
        raise FileNotFoundError(f"no cases.jsonl at {p}")
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        c = json.loads(line)
        if include_draft or c.get("status") == "ready":
            out.append(c)
    return out


SOURCIFY_BASE = "https://sourcify.dev/server"
SOURCIFY_TIMEOUT = 60


def _cache_path(case: dict, checkout_dir: str,
                cache_dir: Optional[str] = None) -> Path:
    cd = Path(cache_dir) if cache_dir else \
        Path(checkout_dir) / ".cache" / "etherscan"
    return cd / f"{case['chain_id']}_{str(case['target_contract']).lower()}.json"


def load_source(case: dict, checkout_dir: str, *,
                cache_dir: Optional[str] = None,
                allow_fetch: bool = False,
                timeout: int = SOURCIFY_TIMEOUT) -> Optional[dict]:
    """Return `{"source_files": {...}, "name": str, "evm_version": str|None}`
    from the checkout's Etherscan cache, or None when the case's source is not
    cached locally (the harness records it as source-unavailable, never guesses).

    The benchmark repo does NOT commit `.cache/etherscan/`, so a fresh checkout
    has no source at all. With `allow_fetch=True` a cache miss falls back to
    **Sourcify** - keyless, free, and the same service `src/verified.py` already
    trusts for build settings - and writes the result into the cache in the
    Etherscan shape, so every later run is offline. Default stays False: the
    test suite must never reach the network.
    """
    f = _cache_path(case, checkout_dir, cache_dir)
    if f.exists():
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            data = {}
        sf = data.get("source_files") or {}
        if sf:
            return {"source_files": sf, "name": data.get("name", ""),
                    "evm_version": data.get("evm_version"),
                    "compiler_version": data.get("compiler_version", "")}
    if not allow_fetch:
        return None
    return fetch_source_sourcify(case, cache_path=f, timeout=timeout)


def fetch_source_sourcify(case: dict, *, cache_path: Optional[Path] = None,
                          timeout: int = SOURCIFY_TIMEOUT) -> Optional[dict]:
    """Verified source for a case's target from Sourcify's v2 API.

    Returns the same record shape `load_source` yields, or None. NEVER raises:
    Sourcify being down, slow, or simply not knowing a contract are ordinary
    conditions - the caller records the case as source-unavailable, exactly as
    it would for a cache miss.
    """
    try:
        import requests
    except ImportError:  # pragma: no cover - requests ships with web3
        return None
    chain = case.get("chain_id")
    addr = str(case.get("target_contract", "")).lower()
    if not chain or not addr:
        return None
    url = f"{SOURCIFY_BASE}/v2/contract/{int(chain)}/{addr}?fields=sources,compilation"
    try:
        resp = requests.get(url, timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return None

    # Sourcify v2: sources = {path: {"content": str}}. Tolerate a bare string.
    files: dict[str, str] = {}
    for path, entry in (body.get("sources") or {}).items():
        text = entry.get("content") if isinstance(entry, dict) else entry
        if isinstance(text, str) and text.strip():
            files[str(path)] = text
    if not files:
        return None
    comp = body.get("compilation") or {}
    rec = {"source_files": files,
           "name": comp.get("name") or "",
           "evm_version": (comp.get("compilerSettings") or {}).get("evmVersion"),
           "compiler_version": comp.get("compilerVersion"),
           "_source": "sourcify", "_match": body.get("match")}
    if cache_path is not None:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(rec, indent=1), encoding="utf-8")
        except OSError:
            pass
    return {"source_files": files, "name": rec["name"],
            "evm_version": rec["evm_version"],
            "compiler_version": rec.get("compiler_version") or ""}


# --------------------------------------------------------------------------- #
# running one case
# --------------------------------------------------------------------------- #

@dataclass
class DVCaseResult:
    case_id: str
    chain_id: int = 0
    agent_findings: list = field(default_factory=list)     # AgentFinding-shaped dicts
    verdict: str = "UNKNOWN"
    model_compiled: bool = False
    n_reproduced: int = 0
    n_confirmed: int = 0
    coverage: dict = field(default_factory=dict)
    score: dict = field(default_factory=dict)
    seconds: float = 0.0
    error: str = ""

    def as_dict(self) -> dict:
        return {"case_id": self.case_id, "chain_id": self.chain_id,
                "verdict": self.verdict, "model_compiled": self.model_compiled,
                "n_reproduced": self.n_reproduced, "n_confirmed": self.n_confirmed,
                "findings": self.agent_findings, "score": self.score,
                "coverage": self.coverage, "execution_time_seconds": self.seconds,
                "error": self.error or None}


# Per-chain RPC env vars, named exactly as the benchmark's own .env.example
# does, so a user who configured DVBench already has these set.
RPC_ENV_BY_CHAIN: dict[int, tuple[str, ...]] = {
    1:     ("ETH_RPC_URL", "MAINNET_RPC_URL", "RPC_URL"),
    56:    ("BSC_RPC_URL",),
    8453:  ("BASE_RPC_URL",),
    42161: ("ARBITRUM_RPC_URL", "ARB_RPC_URL"),
    137:   ("POLYGON_RPC_URL",),
    10:    ("OPTIMISM_RPC_URL", "OP_RPC_URL"),
}


def rpc_for_chain(chain_id: int, *, rpc_urls: Optional[dict] = None,
                  rpc_url: str = "") -> str:
    """The RPC endpoint to fork `chain_id` with, or "".

    Resolution order: an explicit `rpc_urls[chain]` mapping, then the chain's
    own env var, then a bare `rpc_url` - but the bare one is only honoured for
    Ethereum mainnet, because pointing an `eth-mainnet` endpoint at a BSC case
    would fork the wrong chain and silently produce nonsense.
    """
    import os
    if rpc_urls:
        u = rpc_urls.get(chain_id) or rpc_urls.get(str(chain_id))
        if u:
            return str(u)
    for name in RPC_ENV_BY_CHAIN.get(int(chain_id or 0), ()):
        u = os.environ.get(name)
        if u:
            return u
    return rpc_url if int(chain_id or 0) == 1 else ""


def run_case(case: dict, source: dict, *, rpc_url: str = "", fork: bool = False,
             budget_findings: int = 8,
             rpc_urls: Optional[dict] = None) -> DVCaseResult:
    from .hunt import HuntInputs, run as run_hunt

    chain = int(case.get("chain_id", 0))
    chain_rpc = rpc_for_chain(chain, rpc_urls=rpc_urls, rpc_url=rpc_url)
    can_fork = bool(fork and chain_rpc)
    inp = HuntInputs(
        source=source["source_files"], target_contract=source.get("name", ""),
        chain_id=chain, block_number=case.get("block_number"),
        address=str(case.get("target_contract", "")),
        rpc_url=chain_rpc or None if can_fork else None,
        fork=can_fork, budget_findings=budget_findings,
        compiler_version=source.get("compiler_version", ""))
    t0 = time.time()
    try:
        res = run_hunt(inp)
    except Exception as exc:  # noqa: BLE001
        return DVCaseResult(case["id"], chain_id=chain,
                            error=f"{type(exc).__name__}: {exc}"[:300],
                            seconds=round(time.time() - t0, 1))

    agent_findings = [_to_agent_finding(fnd)
                      for fnd in res.findings if fnd.confidence != F.REJECTED]
    dv = DVCaseResult(
        case_id=case["id"], chain_id=chain, agent_findings=agent_findings,
        verdict=res.verdict, model_compiled=bool(res.model and res.model.compiled),
        n_reproduced=res.coverage.get("candidates_reproduced", 0),
        n_confirmed=res.coverage.get("confirmed_findings", 0),
        coverage=res.coverage, seconds=round(time.time() - t0, 1))
    dv.score = score_case(dv, case)
    return dv


def _to_agent_finding(fnd: F.DeepFinding) -> dict:
    sev = fnd.severity if fnd.severity != "unknown" else (
        "high" if fnd.confidence in (F.CONFIRMED, F.LIKELY) else "medium")
    desc = " | ".join(x for x in (
        fnd.security_property, fnd.why_it_should_hold, fnd.how_discovered) if x)
    return {"title": fnd.title, "severity": sev, "description": desc,
            "location": (f"{fnd.contract}.{fnd.function}"
                         if fnd.function else fnd.contract),
            "recommendation": fnd.why_it_should_hold,
            "_confidence": fnd.confidence, "_type": fnd.finding_type,
            "_reproduced": fnd.gates.get("reproducer") == "PASS"}


# --------------------------------------------------------------------------- #
# scoring (deterministic root-cause-overlap proxy)
# --------------------------------------------------------------------------- #

_STOP = frozenset("""
the a an and or of to in is are be by for with that this it its as on at from
into not no any can may will would should could does do done use used using
which when where who whom whose than then thus so such also more most less
function contract call caller external internal public private msg sender
address amount value token tokens uint reserve reserves via same block price
""".split())

_FOCUS_ALIGN = {
    "oracle_manipulation": {F.ORACLE},
    "economic_attacks": {F.ECONOMIC, F.ACCOUNTING},
    "business_logic": {F.LIVE_LOGIC, F.PROTOCOL_INVARIANT, F.ACCOUNTING,
                       F.STATE_MACHINE},
    "asset_management": {F.ACCOUNTING, F.ECONOMIC},
    "access_control": {F.ACCESS_CONTROL},
    "execution_flow": {F.STATE_MACHINE, F.PROTOCOL_INVARIANT, F.LIVE_LOGIC},
}


def _keywords(text: str) -> set[str]:
    toks = re.split(r"[^A-Za-z0-9_]+", (text or "").lower())
    return {t for t in toks if len(t) >= 4 and t not in _STOP and not t.isdigit()}


def _fn_names(text: str) -> set[str]:
    text = text or ""
    out: set[str] = set()
    out.update(m.group(1) for m in re.finditer(r"\b([a-zA-Z_]\w{2,})\s*\(", text))
    for known in ("getreserves", "latestanswer", "latestrounddata", "sync",
                  "skim", "_transfer", "transfer", "transferfrom", "withdraw",
                  "deposit", "borrow", "repay", "liquidate", "mint", "burn",
                  "buy", "sell", "swap", "claim", "redeem", "initialize",
                  "getamountsout", "quote"):
        if re.search(rf"\b{known}\b", text, re.I):
            out.add(known.lower())
    return {x.lower() for x in out}


def _matches(ref: dict, agent_findings: list) -> tuple[bool, str]:
    rtext = f"{ref.get('title', '')} {ref.get('content', '')}"
    rkw, rfns = _keywords(rtext), _fn_names(rtext)
    rfocus = set(ref.get("focus_areas", []))
    best = "no overlap"
    for af in agent_findings:
        atext = f"{af['title']} {af['description']} {af['location']}"
        akw, afns = _keywords(atext), _fn_names(atext)
        kw = len(rkw & akw)
        fn = len(rfns & afns)
        ftype = af.get("_type", "")
        focus_ok = any(ftype in _FOCUS_ALIGN.get(x, set()) for x in rfocus)
        if fn >= 1 and (kw >= 2 or focus_ok):
            return True, (f"fn overlap {sorted(rfns & afns)}, kw={kw}, "
                          f"focus_ok={focus_ok}")
        if kw >= 5 and focus_ok:
            return True, f"kw overlap {kw} + focus_ok"
        best = f"best so far: fn={fn}, kw={kw}, focus_ok={focus_ok}"
    return False, best


def score_case(dv: DVCaseResult, case: dict) -> dict:
    refs = [r for r in case.get("reference_findings", [])
            if r.get("auditable", True)]
    details = []
    matched = 0
    for r in refs:
        hit, why = _matches(r, dv.agent_findings)
        matched += int(hit)
        details.append({"reference": r.get("title", "")[:100],
                        "matched": hit, "why": why})
    total = len(refs)
    recall = round(matched / total, 4) if total else None
    novel = max(0, len(dv.agent_findings) - matched)
    return {"recall": recall, "reference_count": total,
            "matched_count": matched, "novel_findings_count": novel,
            "match_details": details}


# --------------------------------------------------------------------------- #
# the full run
# --------------------------------------------------------------------------- #

@dataclass
class DVReport:
    n_cases: int = 0
    n_run: int = 0
    n_source_unavailable: int = 0
    n_compiled: int = 0
    n_errors: int = 0
    mean_recall: Optional[float] = None
    total_matched: int = 0
    total_reference: int = 0
    total_novel: int = 0
    cases_reproduced: int = 0
    cases_confirmed: int = 0
    confirmed_false_positive_ratio: Optional[float] = None
    results: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"n_cases": self.n_cases, "n_run": self.n_run,
                "n_source_unavailable": self.n_source_unavailable,
                "n_compiled": self.n_compiled, "n_errors": self.n_errors,
                "mean_recall": self.mean_recall,
                "recall_micro": (round(self.total_matched / self.total_reference, 4)
                                 if self.total_reference else None),
                "total_matched": self.total_matched,
                "total_reference": self.total_reference,
                "total_novel": self.total_novel,
                "cases_reproduced": self.cases_reproduced,
                "cases_confirmed": self.cases_confirmed,
                "confirmed_false_positive_ratio": self.confirmed_false_positive_ratio,
                "results": [r.as_dict() for r in self.results]}

    def render(self) -> str:
        micro = (round(self.total_matched / self.total_reference, 4)
                 if self.total_reference else None)
        return "\n".join([
            "CHAINWATCH DEEP HUNT vs DVBench (blind)", "=" * 38, "",
            f"  cases (ready)          {self.n_cases}",
            f"  run                    {self.n_run}",
            f"  source unavailable     {self.n_source_unavailable}",
            f"  model compiled         {self.n_compiled}/{self.n_run}",
            f"  errors                 {self.n_errors}", "",
            f"  mean recall (macro)    {self.mean_recall}",
            f"  recall (micro)         {micro}   "
            f"({self.total_matched}/{self.total_reference} reference findings)",
            f"  novel findings         {self.total_novel}", "",
            f"  cases with a repro     {self.cases_reproduced}",
            f"  cases CONFIRMED        {self.cases_confirmed}",
            f"  CONFIRMED / false-pos  "
            + ("no false positives" if self.confirmed_false_positive_ratio is None
               else str(self.confirmed_false_positive_ratio))
            + "   (spec section 27)",
        ])


def run_dvbench(checkout_dir: str, *, case_ids: Optional[list[str]] = None,
                limit: Optional[int] = None, fork: bool = False,
                rpc_url: str = "", cache_dir: Optional[str] = None,
                budget_findings: int = 8, fetch_sources: bool = False,
                rpc_urls: Optional[dict] = None, on_case=None) -> DVReport:
    """Blind run over a local DVBench checkout.

    `fetch_sources=True` lets a cache miss fall back to Sourcify (keyless) and
    populates the cache for later offline runs. Off by default so the test
    suite never touches the network.
    """
    cases = load_cases(checkout_dir)
    if case_ids:
        want = set(case_ids)
        cases = [c for c in cases if c["id"] in want]
    if limit:
        cases = cases[:limit]

    rep = DVReport(n_cases=len(cases))
    recalls: list[float] = []
    fp = 0
    tp = 0
    for case in cases:
        src = load_source(case, checkout_dir, cache_dir=cache_dir,
                          allow_fetch=fetch_sources)
        if src is None:
            rep.n_source_unavailable += 1
            dv = DVCaseResult(case["id"], chain_id=case.get("chain_id", 0),
                              error="source unavailable in local cache")
            rep.results.append(dv)
            if on_case:
                on_case(dv)
            continue
        dv = run_case(case, src, rpc_url=rpc_url, fork=fork,
                      budget_findings=budget_findings, rpc_urls=rpc_urls)
        rep.n_run += 1
        rep.n_compiled += int(dv.model_compiled)
        rep.n_errors += int(bool(dv.error))
        sc = dv.score or {}
        if sc.get("recall") is not None:
            recalls.append(sc["recall"])
        rep.total_matched += sc.get("matched_count", 0)
        rep.total_reference += sc.get("reference_count", 0)
        rep.total_novel += sc.get("novel_findings_count", 0)
        if dv.n_reproduced > 0:
            rep.cases_reproduced += 1
        if dv.n_confirmed > 0:
            rep.cases_confirmed += 1
            if (sc.get("recall") or 0) > 0:
                tp += 1
            else:
                fp += 1
        rep.results.append(dv)
        if on_case:
            on_case(dv)

    rep.mean_recall = round(sum(recalls) / len(recalls), 4) if recalls else None
    rep.confirmed_false_positive_ratio = (round(tp / fp, 4) if fp else None)
    return rep


# --------------------------------------------------------------------------- #
# BaseAgent shim for the real LLM-judge score (doc snippet - not written to
# the benchmark repo by this module)
# --------------------------------------------------------------------------- #

AGENT_SNIPPET = '''\
# defi-vuln-benchmark/src/agents/chainwatch/agent.py
from pathlib import Path
from src.agents.base import AgentFinding, BaseAgent


class ChainwatchAgent(BaseAgent):
    name = "chainwatch"

    async def run(self, working_dir: Path, challenge: dict, config) -> list[AgentFinding]:
        import sys
        sys.path.insert(0, "<path-to-Chainwatch>")
        from src.nextgen.deephunt.hunt import HuntInputs, run as run_hunt

        contracts = working_dir / "contracts"
        source = {str(p.relative_to(contracts)): p.read_text()
                  for p in contracts.rglob("*.sol")}
        res = run_hunt(HuntInputs(
            source=source, chain_id=challenge["chain_id"],
            block_number=challenge.get("block_number"),
            address=challenge["target_contract"]))
        out = []
        for f in res.findings:
            if f.confidence == "REJECTED":
                continue
            out.append(AgentFinding(
                title=f.title,
                severity=(f.severity if f.severity != "unknown" else "medium"),
                description=f.security_property + " | " + f.how_discovered,
                location=f"{f.contract}.{f.function}",
                recommendation=f.why_it_should_hold))
        return out

# then register in defi-vuln-benchmark/src/agents/__init__.py:
#   AGENTS["chainwatch"] = ChainwatchAgent
'''
