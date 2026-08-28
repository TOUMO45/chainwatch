"""Git -> build -> bytecode -> deployment provenance (spec §9).

Assembles the chain that proves the vulnerable implementation produced by a
historical commit is what the chain is executing:

    regression commit
      -> compiler version + optimizer settings
      -> generated runtime bytecode hash
      -> on-chain runtime bytecode hash
      -> MATCH

The heavy lifting already exists - `src/liveness.py` (normalize + compare +
proxy resolution) and `src/verified.py` (Sourcify/Etherscan build settings).
This module COMPOSES them into one artifact + one gate result, and degrades to
UNKNOWN (never a false PASS) when an RPC or a compiled artifact is missing.

The pure assembler `build_chain` takes already-fetched inputs and is fully
testable without a network; `run` is the thin live wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import evidence_graph as EG
from . import state as S

COMMIT = "COMMIT"
BUILD_ENV = "BUILD_ENV"
LOCAL_BYTECODE = "LOCAL_BYTECODE"
CHAIN_BYTECODE = "CHAIN_BYTECODE"
MATCH = "MATCH"

MATCHED = "MATCH"
MISMATCH = "MISMATCH"
INCOMPLETE = "INCOMPLETE"


@dataclass
class ProvenanceLink:
    stage: str
    established: bool
    value: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {"stage": self.stage, "established": self.established,
                "value": self.value, "note": self.note}


@dataclass
class ProvenanceChain:
    links: list[ProvenanceLink] = field(default_factory=list)
    verdict: str = INCOMPLETE
    gate: str = S.GATE_UNKNOWN
    rationale: str = ""

    @property
    def complete(self) -> bool:
        return all(l.established for l in self.links)

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "gate": self.gate,
                "rationale": self.rationale,
                "links": [l.as_dict() for l in self.links]}

    def render_text(self) -> str:
        lines = ["GIT -> BUILD -> BYTECODE -> DEPLOYMENT PROVENANCE (spec §9)",
                 "=" * 46, ""]
        for l in self.links:
            mark = "ok " if l.established else "-- "
            lines.append(f"  [{mark}] {l.stage:<15} {l.value}")
            if l.note:
                lines.append(f"           {l.note}")
        lines += ["", f"  verdict: {self.verdict}",
                  f"  gate:    {self.gate}  -  {self.rationale}"]
        return "\n".join(lines)

    def to_evidence_graph(self, g: EG.EvidenceGraph) -> str:
        commit_l = _get(self.links, COMMIT)
        be_l = _get(self.links, BUILD_ENV)
        loc_l = _get(self.links, LOCAL_BYTECODE)
        chain_l = _get(self.links, CHAIN_BYTECODE)

        cid = g.add_node(EG.COMMIT, commit_l.value or "regression commit",
                         established_by="history.py",
                         data={"hash": commit_l.value})
        bid = g.add_node(EG.BUILD_ENV, be_l.value or "build settings",
                         established_by="verified.py", data={"note": be_l.note})
        lid = g.add_node(EG.BYTECODE, "local runtime bytecode",
                         established_by="solc", data={"hash": loc_l.value})
        did = g.add_node(EG.DEPLOYMENT, "on-chain runtime bytecode",
                         established_by="liveness.py", data={"hash": chain_l.value})
        g.add_edge(bid, EG.DERIVED_FROM, cid)
        g.add_edge(lid, EG.DERIVED_FROM, bid)
        rel = EG.MATCHES if self.verdict == MATCHED else EG.MISMATCHES
        g.add_edge(lid, rel, did)
        return did


def _get(links: list[ProvenanceLink], stage: str) -> ProvenanceLink:
    for l in links:
        if l.stage == stage:
            return l
    return ProvenanceLink(stage, False)


def build_chain(*, commit: Optional[str], build_settings: Optional[dict],
                local_runtime_hex: Optional[str],
                liveness: Optional[dict]) -> ProvenanceChain:
    """`liveness` is a dict shaped like `src.liveness.LivenessResult.as_dict()`
    (or None): it carries `verdict` in {LIVE, PATCHED, UNKNOWN} and evidence."""
    links: list[ProvenanceLink] = []

    links.append(ProvenanceLink(
        COMMIT, bool(commit), value=(commit or "")[:12],
        note="" if commit else "no regression commit supplied"))

    bs = build_settings or {}
    has_bs = bool(bs.get("compiler") or bs.get("solc") or bs.get("compiler_version"))
    opt = bs.get("optimizer")
    links.append(ProvenanceLink(
        BUILD_ENV, has_bs,
        value=_fmt_settings(bs),
        note="" if has_bs else "compiler/optimizer settings not established"))

    links.append(ProvenanceLink(
        LOCAL_BYTECODE, bool(local_runtime_hex),
        value=_short_hex(local_runtime_hex),
        note="" if local_runtime_hex else "no locally compiled runtime bytecode"))

    lv = liveness or {}
    lverdict = (lv.get("verdict") or "").upper()
    chain_hash = (((lv.get("evidence") or {}).get("deployed") or {})
                  .get("normalized_keccak", ""))
    links.append(ProvenanceLink(
        CHAIN_BYTECODE, bool(lverdict),
        value=_short_hex(chain_hash) or lv.get("resolved_target", ""),
        note="" if lverdict else "no on-chain bytecode read (no RPC / address)"))

    if lverdict == "LIVE":
        verdict, gate, why = MATCHED, S.PASS, (
            "the locally compiled vulnerable bytecode is byte-identical to what "
            "executes on-chain")
        links.append(ProvenanceLink(MATCH, True, value="LIVE"))
    elif lverdict == "PATCHED":
        verdict, gate, why = MISMATCH, S.FAIL, (
            "on-chain bytecode differs from the vulnerable build - the chain is "
            "not running this commit's implementation")
        links.append(ProvenanceLink(MATCH, True, value="PATCHED"))
    else:
        verdict, gate, why = INCOMPLETE, S.GATE_UNKNOWN, (
            "the provenance chain is incomplete - "
            + ", ".join(l.stage for l in links if not l.established))
        links.append(ProvenanceLink(MATCH, False))

    return ProvenanceChain(links, verdict, gate, why)


def run(address: str, local_runtime_hex: Optional[str], *,
        commit: Optional[str], rpc_url: Optional[str] = None,
        chain_id: int = 1, immutable_refs: Optional[dict] = None
        ) -> ProvenanceChain:
    """Live path: fetch build settings + on-chain bytecode, then `build_chain`.

    Any failure (no web3, no RPC, unverified address, compile artifact absent)
    yields an INCOMPLETE chain, never a wrong verdict.
    """
    build_settings = None
    liveness = None
    try:
        from src import verified as VER
        build_settings = VER.settings_for(address, chain_id=chain_id)
    except Exception:  # noqa: BLE001
        build_settings = None
    if local_runtime_hex and address:
        try:
            from src import liveness as L
            res = L.check_against_artifact(address, local_runtime_hex,
                                          rpc_url=rpc_url,
                                          immutable_refs=immutable_refs)
            liveness = res.as_dict() if hasattr(res, "as_dict") else dict(res)
        except Exception:  # noqa: BLE001
            liveness = None
    return build_chain(commit=commit, build_settings=build_settings,
                       local_runtime_hex=local_runtime_hex, liveness=liveness)


def _fmt_settings(bs: dict) -> str:
    if not bs:
        return ""
    comp = bs.get("compiler") or bs.get("solc") or bs.get("compiler_version") or "?"
    opt = bs.get("optimizer")
    runs = bs.get("runs") or bs.get("optimizer_runs")
    evm = bs.get("evm_version") or bs.get("evmVersion")
    return f"solc {comp}, optimizer={opt}, runs={runs}, evm={evm}"


def _short_hex(h: Optional[str]) -> str:
    if not h:
        return ""
    h = str(h)
    return (h[:14] + "…") if len(h) > 15 else h
